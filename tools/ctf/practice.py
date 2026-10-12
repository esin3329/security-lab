#!/usr/bin/env python3
"""Solo Juice Shop v17.1.1 CTF controller; Python 3.10+ standard library only.

python3 tools/ctf/practice.py [--runtime-dir ABS] init
python3 tools/ctf/practice.py start [--wait-seconds 60]
python3 tools/ctf/practice.py status
python3 tools/ctf/practice.py verify --challenge-id scoreBoardChallenge
python3 tools/ctf/practice.py reset --confirm-event ID --confirm-round N

Flag input is stdin only (terminal echo disabled); flags are never persisted.
Exit 0: completed/ready/accepted. 2: rejected input, boundary or corrupt state.
3: genuine prerequisite missing or target not ready. 4: I/O, Docker/API operation
failed or reset incomplete. All commands need a local Ubuntu VM; no SSH, remote
engine, arbitrary URL, installation, pull, tool execution or benchmark writer.

State is one atomic, authenticated JSON document containing safe receipts. The
runtime directory is outside Git, owned by the caller, 0700; its files are 0600.
Only this controller may operate its project while its private lock is held.
Docker access and the private event directory are trusted operator privileges.
"""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import hashlib
import hmac
import http.client
import io
import json
import math
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import time


ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "infra" / "compose.targets.yml"
PIN_FILE = Path(__file__).resolve().with_name("juice-shop.lock.json")
COMMIT = "39b46860612990ae18d499a20472172839fe8c77"
VERSION = "17.1.1"
IMAGE = "bkimminich/juice-shop:v17.1.1"
NETWORK = "targets-net"
CONTAINER = "juice-shop"
VOLUME = "juice-shop-data"
PREFIX = "io.security-lab.ctf."
MAX_JSON = 8 * 1024 * 1024
ID_RE = re.compile(r"[0-9a-f]{32}\Z")
CID_RE = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
KEY_RE = re.compile(rb"[0-9a-f]{64}\Z")
FLAG_RE = re.compile(rb"[0-9a-f]{40}\Z")
ATTEST = (
    "package.json", "data/static/challenges.yml", "config/ctf.yml",
    "lib/utils.ts", "lib/challengeUtils.ts", "server.ts",
    "routes/appVersion.ts", "routes/appConfiguration.ts", "routes/verify.ts",
    "models/index.ts", "data/staticData.ts",
)


class Fault(Exception):
    """A fixed, secret-free diagnostic with a public exit code."""

    def __init__(self, message, code=2):
        super().__init__(message)
        self.code = code


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "ctf: invalid arguments; use --help (flag input is stdin only)\n")


def require(condition, message, code=2):
    if not condition:
        raise Fault(message, code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def finite_float(value):
    number = float(value)
    require(math.isfinite(number), "non-finite JSON number")
    return number


def bad_constant(_value):
    raise Fault("non-standard JSON constant")


def decode_json(raw):
    require(len(raw) <= MAX_JSON, "JSON size limit exceeded")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_float=finite_float, parse_constant=bad_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise Fault("invalid or truncated UTF-8 JSON") from None


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      allow_nan=False, separators=(",", ":")).encode("utf-8")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def timestamp(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").utcoffset().total_seconds() == 0
    except (ValueError, OverflowError):
        return False


def fields(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected), "invalid state structure")


def hex_id(value):
    return isinstance(value, str) and ID_RE.fullmatch(value) is not None


def pin_metadata():
    data = decode_json(PIN_FILE.read_bytes())
    require(data.get("schema_version") == 1 and data.get("commit") == COMMIT and
            data.get("tag") == "v" + VERSION and data.get("image") == IMAGE,
            "pinned metadata does not match this controller")
    require(isinstance(data.get("source_git_blobs"), dict) and
            all(re.fullmatch(r"[0-9a-f]{40}", data["source_git_blobs"].get(p, ""))
                for p in ATTEST), "pinned source blob metadata is incomplete")
    catalog = {}
    for row in data.get("challenges", []):
        fields(row, ("key", "name", "difficulty"))
        require(isinstance(row["key"], str) and
                re.fullmatch(r"[A-Za-z][A-Za-z0-9]+Challenge", row["key"]) and
                isinstance(row["name"], str) and row["name"] and
                type(row["difficulty"]) is int and 1 <= row["difficulty"] <= 6 and
                row["key"] not in catalog, "invalid pinned challenge catalog")
        catalog[row["key"]] = row
    require(len(catalog) == 107 and catalog.get("scoreBoardChallenge") ==
            {"key": "scoreBoardChallenge", "name": "Score Board", "difficulty": 1},
            "incomplete pinned v17.1.1 catalog")
    return data, catalog


def ubuntu_vm():
    require(sys.version_info >= (3, 10), "Python 3.10 or newer is required in the VM", 3)
    require(sys.platform == "linux" and os.name == "posix", "run inside the local Ubuntu Linux VM", 3)
    kernel = platform.release().lower()
    require("microsoft" not in kernel and "wsl" not in kernel,
            "Windows/WSL execution is refused; run inside the Ubuntu VM", 3)
    try:
        release = Path("/etc/os-release").read_text(encoding="utf-8")
        product = Path("/sys/class/dmi/id/product_name").read_text(encoding="utf-8").lower()
    except OSError:
        raise Fault("Ubuntu VM identity metadata is unavailable", 3) from None
    require(re.search(r'^ID=["\']?ubuntu["\']?$', release, re.M) is not None,
            "Ubuntu is required", 3)
    require(any(word in product for word in
                ("virtualbox", "vmware", "kvm", "qemu", "virtual machine", "bochs", "hvm domu")),
            "VM identity could not be established from DMI metadata", 3)


def default_runtime():
    import pwd
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    checkout_id = hashlib.sha256(os.fsencode(ROOT)).hexdigest()[:16]
    return home / ".local" / "state" / "security-lab" / "ctf" / checkout_id


def runtime_path(argument):
    path = Path(argument) if argument is not None else default_runtime()
    require(path.is_absolute() and ".." not in path.parts, "runtime directory must be an absolute path")
    for parent in reversed((path, *path.parents)):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            continue
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                "runtime path must use real directories without symlinks")
        require(not (parent / ".git").exists(), "runtime directory must be outside every Git checkout")
        require(not (info.st_mode & 0o022) or
                (info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
                "runtime ancestors must not be writable by other users")
    require(path != ROOT and ROOT not in path.parents, "runtime directory cannot be inside the checkout")
    return path


def private_stat(info, directory=False):
    mode = 0o700 if directory else 0o600
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) and
            info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == mode and
            (directory or info.st_nlink == 1), "private runtime ownership, type or permissions are invalid")


class Store:
    """Directory-FD based private files; flock protects atomic state transactions."""

    def __init__(self, path):
        self.path = path
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            private_stat(os.fstat(self.fd), directory=True)
        except BaseException:
            os.close(self.fd)
            raise

    def close(self):
        os.close(self.fd)

    def open(self, name, flags):
        require(Path(name).name == name, "invalid private file name")
        try:
            fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self.fd)
        except OSError as exc:
            if exc.errno == errno.ELOOP or (not flags & os.O_CREAT and
                    exc.errno in (errno.ENOENT, errno.EACCES, errno.EPERM)):
                raise Fault("private runtime file is missing, unreadable or a symlink") from None
            raise
        try:
            if flags & os.O_CREAT and flags & os.O_EXCL:
                os.fchmod(fd, 0o600)
            private_stat(os.fstat(fd))
        except BaseException:
            os.close(fd)
            raise
        return fd

    def read(self, name, limit=MAX_JSON):
        fd = self.open(name, os.O_RDONLY)
        with os.fdopen(fd, "rb") as source:
            raw = source.read(limit + 1)
        require(len(raw) <= limit, "private file exceeds its size limit")
        return raw

    def create(self, name, raw):
        fd = self.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        with os.fdopen(fd, "wb") as destination:
            destination.write(raw)
            destination.flush()
            os.fsync(destination.fileno())
        os.fsync(self.fd)

    def atomic(self, name, raw):
        require(len(raw) <= MAX_JSON, "private state exceeds its size limit", 4)
        temporary = ".write-" + secrets.token_hex(16)
        created = False
        try:
            fd = self.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            created = True
            with os.fdopen(fd, "wb") as destination:
                destination.write(raw)
                destination.flush()
                os.fsync(destination.fileno())
            # Refuse replacing an unexpected object; the lock serializes all writers.
            try:
                private_stat(os.stat(name, dir_fd=self.fd, follow_symlinks=False))
            except FileNotFoundError:
                pass
            os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            created = False
            os.fsync(self.fd)
        finally:
            if created:
                os.unlink(temporary, dir_fd=self.fd)

    def remove(self, name):
        private_stat(os.stat(name, dir_fd=self.fd, follow_symlinks=False))
        os.unlink(name, dir_fd=self.fd)
        os.fsync(self.fd)

    @contextmanager
    def locked(self):
        import fcntl
        fd = self.open("lock", os.O_RDWR)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Fault("another CTF operation holds the private runtime lock") from None
            yield
        finally:
            os.close(fd)

    def key(self, name):
        raw = self.read(name, 64)
        require(KEY_RE.fullmatch(raw) is not None, "private key is missing or corrupt")
        return raw

    def save(self, state):
        auth = self.key("state-auth.key")
        payload = dict(state)
        payload["integrity"] = hmac.new(auth, canonical(state), hashlib.sha256).hexdigest()
        self.atomic("state.json", canonical(payload) + b"\n")

    def load(self, catalog):
        raw = self.read("state.json")
        require(raw.endswith(b"\n"), "private state is truncated")
        state = decode_json(raw)
        require(isinstance(state, dict), "invalid private state")
        integrity = state.pop("integrity", None)
        require(isinstance(integrity, str) and re.fullmatch(r"[0-9a-f]{64}", integrity),
                "private state integrity field is invalid")
        expected = hmac.new(self.key("state-auth.key"), canonical(state), hashlib.sha256).hexdigest()
        require(hmac.compare_digest(integrity, expected), "private state integrity check failed")
        validate_state(state, catalog)
        require(hmac.compare_digest(hashlib.sha256(self.key(state["key_file"])).hexdigest(),
                                    state["key_sha256"]), "event key does not match private state")
        if state["pending"] is not None:
            pending = state["pending"]
            require(hmac.compare_digest(hashlib.sha256(self.key(pending["key_file"])).hexdigest(),
                                        pending["key_sha256"]), "pending event key does not match private state")
        return state


def validate_binding(binding):
    fields(binding, ("engine_id", "container_id", "image_id", "started_at",
                     "volume_name", "volume_created_at", "network_id"))
    require(isinstance(binding["engine_id"], str) and 1 <= len(binding["engine_id"]) <= 256 and
            isinstance(binding["container_id"], str) and CID_RE.fullmatch(binding["container_id"]) and
            isinstance(binding["image_id"], str) and IMAGE_RE.fullmatch(binding["image_id"]) and
            timestamp(binding["started_at"]) and isinstance(binding["volume_created_at"], str) and
            binding["volume_created_at"] and isinstance(binding["network_id"], str) and
            CID_RE.fullmatch(binding["network_id"]), "invalid target binding")


def validate_state(state, catalog):
    fields(state, ("schema_version", "checkout", "source_commit", "project_id", "event_id", "round",
                   "created_at", "key_file", "key_sha256", "phase", "target", "pending", "history", "receipts"))
    require(type(state["schema_version"]) is int and state["schema_version"] == 1 and
            state["checkout"] == str(ROOT) and state["source_commit"] == COMMIT and
            hex_id(state["project_id"]) and hex_id(state["event_id"]) and
            type(state["round"]) is int and state["round"] > 0 and timestamp(state["created_at"]),
            "state belongs to another checkout or contains invalid event metadata")
    require(state["key_file"] == "event-" + state["event_id"] + ".key" and
            isinstance(state["key_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", state["key_sha256"]) and
            state["phase"] in ("initialized", "starting", "active", "resetting"), "invalid event lifecycle")
    project_volume = project_name(state) + "_" + VOLUME
    if state["target"] is not None:
        validate_binding(state["target"])
        require(state["target"]["volume_name"] == project_volume, "invalid project volume binding")
    require((state["phase"] != "active" or state["target"] is not None) and
            (state["phase"] != "initialized" or state["target"] is None), "invalid lifecycle target binding")
    if state["pending"] is not None:
        pending = state["pending"]
        fields(pending, ("event_id", "round", "created_at", "key_file", "key_sha256", "stage"))
        require(state["phase"] == "resetting" and state["target"] is not None and
                hex_id(pending["event_id"]) and pending["event_id"] != state["event_id"] and
                type(pending["round"]) is int and pending["round"] == state["round"] + 1 and
                timestamp(pending["created_at"]) and
                pending["key_file"] == "event-" + pending["event_id"] + ".key" and
                isinstance(pending["key_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", pending["key_sha256"]) and
                pending["stage"] in ("planned", "container_removed", "volume_removed"), "invalid reset transaction")
    else:
        require(state["phase"] != "resetting", "reset transaction is missing")
    require(isinstance(state["history"], list) and isinstance(state["receipts"], list), "invalid receipt/history storage")
    rounds = {}
    for item in state["history"]:
        fields(item, ("event_id", "round", "created_at", "ended_at", "target"))
        require(hex_id(item["event_id"]) and type(item["round"]) is int and
                item["round"] == len(rounds) + 1 and timestamp(item["created_at"]) and
                timestamp(item["ended_at"]) and item["event_id"] not in rounds, "invalid round history")
        validate_binding(item["target"])
        require(item["target"]["volume_name"] == project_volume, "invalid historic project volume")
        rounds[item["event_id"]] = item
    require(state["round"] == len(rounds) + 1 and state["event_id"] not in rounds, "invalid current round")
    rounds[state["event_id"]] = state
    seen = set()
    receipt_ids = set()
    for receipt in state["receipts"]:
        fields(receipt, ("receipt_id", "event_id", "round", "challenge_id", "challenge_key", "challenge_name",
                         "accepted_at", "application_version", "source_commit", "container_id", "image_id",
                         "container_started_at", "verification"))
        require(hex_id(receipt["receipt_id"]) and receipt["receipt_id"] not in receipt_ids and
                isinstance(receipt["event_id"], str) and receipt["event_id"] in rounds and
                isinstance(receipt["challenge_key"], str) and receipt["challenge_key"] in catalog,
                "invalid acceptance receipt identity")
        identity = (receipt["event_id"], receipt["challenge_key"])
        item = rounds[receipt["event_id"]]
        binding = item["target"]
        require(identity not in seen and binding is not None and type(receipt["round"]) is int and
                receipt["round"] == item["round"] and
                type(receipt["challenge_id"]) is int and receipt["challenge_id"] > 0 and
                receipt["challenge_name"] == catalog[receipt["challenge_key"]]["name"] and
                timestamp(receipt["accepted_at"]) and receipt["application_version"] == VERSION and
                receipt["source_commit"] == COMMIT and receipt["container_id"] == binding["container_id"] and
                receipt["image_id"] == binding["image_id"] and
                receipt["container_started_at"] == binding["started_at"] and
                receipt["verification"] == "HMAC-SHA1+solved-catalog", "invalid or duplicate acceptance receipt")
        seen.add(identity)
        receipt_ids.add(receipt["receipt_id"])


def new_event(round_number):
    event = secrets.token_hex(16)
    key = secrets.token_hex(32).encode("ascii")
    return {"event_id": event, "round": round_number, "created_at": utc_now(),
            "key_file": "event-" + event + ".key", "key_sha256": hashlib.sha256(key).hexdigest()}, key


def initialize(path):
    # mkdir is the no-overwrite boundary, even after an interrupted prior init.
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    runtime_path(str(path))
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        raise Fault("runtime directory already exists; existing events are never overwritten") from None
    store = Store(path)
    try:
        event, key = new_event(1)
        store.create("lock", b"")
        store.create("state-auth.key", secrets.token_hex(32).encode("ascii"))
        store.create(event["key_file"], key)
        state = {"schema_version": 1, "checkout": str(ROOT), "source_commit": COMMIT,
                 "project_id": secrets.token_hex(16), **event, "phase": "initialized",
                 "target": None, "pending": None, "history": [], "receipts": []}
        store.save(state)
        output(state, "initialized", runtime_dir=str(path))
    finally:
        store.close()


def project_name(state):
    return "security-lab-ctf-" + state["project_id"]


def labels(state):
    return {PREFIX + "project": state["project_id"], PREFIX + "event": state["event_id"],
            PREFIX + "round": str(state["round"])}


def output(state, status, **extra):
    # Callers only pass verified/safe metadata, never raw API/Docker responses.
    value = {"status": status, "event_id": state["event_id"], "round": state["round"],
             "project": project_name(state), "accepted_count": sum(
                 row["event_id"] == state["event_id"] for row in state["receipts"]), **extra}
    print(json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False))


class Docker:
    def __init__(self):
        self.executable = shutil.which("docker")
        require(self.executable is not None and not self.executable.lower().endswith(".exe"),
                "native Linux Docker CLI and Compose v2 are required", 3)
        require(not any(os.environ.get(name) for name in
                        ("DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION")),
                "Docker TLS/API overrides are refused")
        self.env = dict(os.environ)
        context = self.run([self.executable, "context", "show"], "Docker context query").decode("utf-8").strip()
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", context) is not None,
                "Docker context name is invalid")
        info = decode_json(self.run([self.executable, "context", "inspect", context], "Docker context metadata"))
        require(isinstance(info, list) and len(info) == 1, "Docker context metadata is invalid")
        endpoint = info[0].get("Endpoints", {}).get("docker", {}).get("Host")
        allowed = ("unix:///var/run/docker.sock", "unix:///run/docker.sock",
                   "unix:///run/user/" + str(os.getuid()) + "/docker.sock")
        require(endpoint in allowed, "remote or Desktop Docker engine is refused")
        requested = os.environ.get("DOCKER_HOST")
        require(not requested or requested == endpoint, "Docker host override does not match the local context")
        try:
            socket = os.stat(endpoint[len("unix://"):])
        except OSError:
            raise Fault("local Docker socket/access is missing; grant the operator Docker access in the VM", 3) from None
        require(stat.S_ISSOCK(socket.st_mode) and socket.st_uid in (0, os.getuid()),
                "local Docker Unix socket is unavailable or has unexpected ownership", 3)
        # Freeze the already-validated endpoint for every subsequent operation.
        for name in list(self.env):
            if name.startswith(("DOCKER_", "COMPOSE_", "CTF_")):
                del self.env[name]
        self.base = [self.executable, "--host", endpoint]
        daemon = self.json(["info", "--format", "{{json .}}"], "Docker daemon metadata")
        require(daemon.get("OSType") == "linux" and
                "ubuntu" in daemon.get("OperatingSystem", "").lower() and
                "desktop" not in daemon.get("OperatingSystem", "").lower() and
                daemon.get("Name") == platform.node(), "Docker daemon is not the local Ubuntu VM engine")
        self.engine_id = daemon.get("ID")
        require(isinstance(self.engine_id, str) and 1 <= len(self.engine_id) <= 256,
                "Docker engine identity is missing")
        compose_version = self.call(["compose", "version", "--short"], "Docker Compose version").decode("ascii").strip()
        require(re.fullmatch(r"v?2\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", compose_version) is not None,
                "Docker Compose v2 with JSON config support is required", 3)

    def run(self, argv, description, env=None, timeout=30):
        try:
            result = subprocess.run(argv, cwd=str(ROOT), env=self.env if env is None else env,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    shell=False, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise Fault(description + " timed out; operation may be incomplete", 4) from None
        except OSError:
            raise Fault(description + " could not execute", 4) from None
        require(result.returncode == 0, description + " failed (exit " + str(result.returncode) + ")", 4)
        require(len(result.stdout) <= MAX_JSON, description + " response is too large", 4)
        return result.stdout

    def call(self, args, description, **options):
        return self.run(self.base + args, description, **options)

    def json(self, args, description, **options):
        return decode_json(self.call(args, description, **options))

    def identifiers(self, args, description):
        raw = self.call(args, description).decode("ascii").strip()
        ids = raw.splitlines() if raw else []
        require(len(set(ids)) == len(ids) and all(CID_RE.fullmatch(x) for x in ids),
                description + " returned invalid identifiers", 4)
        return ids

    def container(self):
        ids = self.identifiers(["container", "ls", "--all", "--quiet", "--no-trunc",
                                "--filter", "name=^/juice-shop$"], "target container inventory")
        require(len(ids) <= 1, "target container name is ambiguous")
        return self.inspect_container(ids[0]) if ids else None

    def inspect_container(self, cid):
        data = self.json(["container", "inspect", cid], "target container metadata")
        require(isinstance(data, list) and len(data) == 1 and data[0].get("Id") == cid,
                "target container identity changed")
        return data[0]

    def volume(self, name):
        names = self.call(["volume", "ls", "--quiet", "--filter", "name=^" + name + "$"],
                          "target volume inventory").decode("ascii").splitlines()
        require(all(item == name for item in names) and len(names) <= 1, "target volume name is ambiguous")
        if not names:
            return None
        data = self.json(["volume", "inspect", name], "target volume metadata")
        require(isinstance(data, list) and len(data) == 1 and data[0].get("Name") == name,
                "target volume identity changed")
        return data[0]

    def network(self):
        ids = self.identifiers(["network", "ls", "--quiet", "--no-trunc", "--filter",
                                "name=^targets-net$"], "target network inventory")
        require(len(ids) <= 1, "target network name is ambiguous")
        if not ids:
            return None
        data = self.json(["network", "inspect", ids[0]], "target network metadata")
        require(isinstance(data, list) and len(data) == 1 and data[0].get("Id") == ids[0],
                "target network identity changed")
        network = data[0]
        require(network.get("Name") == NETWORK and network.get("Internal") is True and
                network.get("Driver") == "bridge" and network.get("Scope") == "local" and
                network.get("Ingress") is False, "targets-net must be a local internal bridge")
        return network

    def image(self):
        ids = set(self.call(["image", "ls", "--quiet", "--no-trunc", IMAGE],
                            "pinned image inventory").decode("ascii").splitlines())
        require(len(ids) == 1, "preload the official bkimminich/juice-shop:v17.1.1 image in this VM", 3)
        image_id = next(iter(ids))
        require(IMAGE_RE.fullmatch(image_id) is not None, "pinned image identifier is invalid")
        data = self.json(["image", "inspect", image_id], "pinned image metadata")
        require(isinstance(data, list) and len(data) == 1 and data[0].get("Id") == image_id,
                "pinned image identity changed")
        image = data[0]
        cfg = image.get("Config", {})
        meta = cfg.get("Labels") or {}
        revision = meta.get("org.opencontainers.image.revision", "")
        # Official release workflow passes git rev-parse --short HEAD.
        require(image.get("Os") == "linux" and IMAGE in (image.get("RepoTags") or []) and
                meta.get("org.opencontainers.image.version") == VERSION and
                meta.get("org.opencontainers.image.source") == "https://github.com/juice-shop/juice-shop" and
                isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{7,40}", revision) and
                COMMIT.startswith(revision) and cfg.get("WorkingDir") == "/juice-shop" and
                cfg.get("User") == "65532" and
                cfg.get("Cmd") == ["/juice-shop/build/app.js"], "image does not match the pinned official v17.1.1 release")
        self.image_config = cfg
        return image_id

    def copy_bytes(self, cid, path):
        # docker cp - returns a tar stream; read one regular file in memory.
        # Never extract paths or persist a raw Docker/application response.
        raw = self.call(["container", "cp", cid + ":/juice-shop/" + path, "-"], "pinned application source read")
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                members = archive.getmembers()
                require(len(members) == 1 and members[0].isfile() and
                        Path(members[0].name).name == Path(path).name and members[0].size <= MAX_JSON,
                        "application source archive is invalid")
                stream = archive.extractfile(members[0])
                require(stream is not None, "application source archive is unreadable")
                with stream:
                    result = stream.read(MAX_JSON + 1)
                require(len(result) == members[0].size, "application source file is truncated")
                return result
        except (tarfile.TarError, EOFError):
            raise Fault("application source archive is corrupt") from None


def event_env(docker, store, state):
    env = dict(docker.env)
    env.update(CTF_KEY=store.key(state["key_file"]).decode("ascii"),
               CTF_PROJECT_ID=state["project_id"], CTF_EVENT_ID=state["event_id"], CTF_ROUND=str(state["round"]))
    return env


def compose_args(state, file):
    return ["compose", "--env-file", "/dev/null", "--project-name", project_name(state),
            "--project-directory", str(ROOT), "--file", str(file)]


def compose_config(docker, store, state):
    cfg = docker.json(compose_args(state, COMPOSE) + ["config", "--format", "json"],
                      "project Compose configuration", env=event_env(docker, store, state))
    require(isinstance(cfg, dict) and set(cfg) <= {"name", "services", "volumes", "networks"} and
            set(cfg.get("services", {})) == {CONTAINER} and
            set(cfg.get("volumes", {})) == {VOLUME} and set(cfg.get("networks", {})) == {NETWORK},
            "Compose must contain only this project's single target service/volume/network")
    service = cfg["services"][CONTAINER]
    require(set(service) <= {"image", "container_name", "restart", "ports", "networks", "volumes",
                             "environment", "labels"} and service.get("image") == IMAGE and
            service.get("container_name") == CONTAINER and service.get("restart") == "unless-stopped",
            "Compose target execution boundary changed")
    environment = service.get("environment", {})
    require(set(environment) == {"NODE_ENV", "CTF_KEY"} and environment["NODE_ENV"] == "ctf" and
            hmac.compare_digest(environment["CTF_KEY"], store.key(state["key_file"]).decode("ascii")),
            "Compose must inject the private event key in NODE_ENV=ctf")
    ports = service.get("ports", [])
    require(len(ports) == 1 and ports[0].get("host_ip") == "127.0.0.1" and
            ports[0].get("target") == 3000 and str(ports[0].get("published")) == "3000" and
            ports[0].get("protocol") == "tcp" and
            ports[0].get("mode", "ingress") == "ingress" and
            set(ports[0]) <= {"host_ip", "target", "published", "protocol", "mode"},
            "Compose must publish only 127.0.0.1:3000:3000/tcp")
    require(set(service.get("networks", {})) == {NETWORK} and
            service["networks"][NETWORK] in (None, {}), "Compose target network options changed")
    mounts = service.get("volumes", [])
    require(len(mounts) == 1 and mounts[0].get("type") == "volume" and
            mounts[0].get("source") == VOLUME and mounts[0].get("target") == "/juice-shop/data" and
            mounts[0].get("read_only", False) is False and
            set(mounts[0]) <= {"type", "source", "target", "read_only", "volume"} and
            mounts[0].get("volume", {}) in ({}, {"nocopy": False}), "Compose data mount boundary changed")
    required_labels = {**labels(state), PREFIX + "source-commit": COMMIT}
    require(service.get("labels") == required_labels, "Compose event ownership labels changed")
    volume = cfg["volumes"][VOLUME]
    require(set(volume) <= {"name", "driver", "labels"} and volume.get("driver") == "local" and
            volume.get("name") == project_name(state) + "_" + VOLUME and volume.get("labels") == labels(state),
            "Compose volume ownership boundary changed")
    network = cfg["networks"][NETWORK]
    require(set(network) <= {"name", "driver", "internal"} and network.get("name") == NETWORK and
            network.get("driver") == "bridge" and network.get("internal") is True,
            "Compose must retain targets-net internal:true")
    return cfg


def write_plan(store, cfg):
    # Treat the shared, metadata-verified internal network as external to Compose
    # management. This avoids ownership conflicts with attached tools and ensures
    # it is never removed. The source Compose keeps internal:true unchanged.
    cfg["networks"][NETWORK] = {"name": NETWORK, "external": True}
    cfg["services"][CONTAINER]["environment"]["CTF_KEY"] = "${CTF_KEY:?private event key required}"
    store.atomic("compose.runtime.json", canonical(cfg) + b"\n")
    return store.path / "compose.runtime.json"


def check_volume(docker, state, volume, binding=None):
    require(volume is not None, "target data volume is missing", 3)
    meta = volume.get("Labels") or {}
    require(volume.get("Name") == project_name(state) + "_" + VOLUME and
            volume.get("Driver") == "local" and volume.get("Scope") == "local" and
            not volume.get("Options") and all(meta.get(k) == v for k, v in labels(state).items()) and
            meta.get("com.docker.compose.project") == project_name(state) and
            meta.get("com.docker.compose.volume") == VOLUME,
            "data volume is not owned exclusively by the current project/event/round")
    require(isinstance(volume.get("CreatedAt"), str) and volume["CreatedAt"], "volume creation identity is missing")
    if binding is not None:
        require(volume["CreatedAt"] == binding["volume_created_at"], "data volume was replaced outside reset")
    attached = docker.identifiers(["container", "ls", "--all", "--quiet", "--no-trunc", "--filter",
                                   "volume=" + volume["Name"]], "target volume attachment inventory")
    allowed = {binding["container_id"]} if binding is not None else set()
    require(set(attached) <= allowed, "another container uses the target volume; reset/start is refused")


def inspect_target(docker, store, state, image_id, require_running=True, continuity=True):
    target = docker.container()
    require(target is not None, "target container is absent; run start", 3)
    cfg = target.get("Config", {})
    host = target.get("HostConfig", {})
    meta = cfg.get("Labels") or {}
    cid = target.get("Id")
    require(isinstance(cid, str) and CID_RE.fullmatch(cid) and target.get("Name") == "/" + CONTAINER and
            target.get("Image") == image_id and cfg.get("Image") == IMAGE and
            all(meta.get(k) == v for k, v in labels(state).items()) and
            meta.get(PREFIX + "source-commit") == COMMIT and
            meta.get("com.docker.compose.project") == project_name(state) and
            meta.get("com.docker.compose.service") == CONTAINER and
            meta.get("com.docker.compose.project.working_dir") == str(ROOT) and
            meta.get("com.docker.compose.project.config_files") == str(store.path / "compose.runtime.json") and
            meta.get("com.docker.compose.oneoff", "").lower() == "false",
            "target container identity, image or project/event ownership does not match")
    require(cfg.get("Cmd") == docker.image_config.get("Cmd") and
            cfg.get("Entrypoint") == docker.image_config.get("Entrypoint") and
            cfg.get("WorkingDir") == "/juice-shop" and cfg.get("User") == "65532",
            "target container command, entrypoint or execution identity was overridden")
    project_ids = docker.identifiers(["container", "ls", "--all", "--quiet", "--no-trunc", "--filter",
                                      "label=com.docker.compose.project=" + project_name(state)],
                                     "project container inventory")
    require(set(project_ids) == {cid}, "unexpected containers share this private Compose project")
    environment = {}
    for pair in cfg.get("Env") or []:
        require(isinstance(pair, str) and "=" in pair, "invalid container environment metadata")
        key, value = pair.split("=", 1)
        require(key not in environment, "duplicate container environment setting")
        environment[key] = value
    image_environment = {}
    for pair in docker.image_config.get("Env") or []:
        require(isinstance(pair, str) and "=" in pair, "invalid pinned image environment metadata")
        key, value = pair.split("=", 1)
        require(key not in image_environment, "duplicate pinned image environment setting")
        image_environment[key] = value
    expected_names = set(image_environment) | {"NODE_ENV", "CTF_KEY"}
    require(environment.get("NODE_ENV") == "ctf" and
            hmac.compare_digest(environment.get("CTF_KEY", ""), store.key(state["key_file"]).decode("ascii")) and
            set(environment) == expected_names and
            all(environment[key] == value for key, value in image_environment.items()
                if key not in ("NODE_ENV", "CTF_KEY")) and
            not set(environment).intersection({"NODE_CONFIG", "NODE_CONFIG_DIR", "PORT", "BASE_PATH", "SOLUTIONS_WEBHOOK"}),
            "container CTF environment differs from the private event")
    require(host.get("PortBindings") == {"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3000"}]} and
            host.get("RestartPolicy", {}).get("Name") == "unless-stopped" and
            host.get("Privileged") is False and not host.get("Binds") and not host.get("Devices") and
            not host.get("CapAdd") and host.get("PidMode", "") == "" and host.get("NetworkMode") == NETWORK,
            "target container isolation or loopback publication changed")
    networks = target.get("NetworkSettings", {}).get("Networks", {})
    running = target.get("State", {}).get("Running") is True
    require(set(networks) == {NETWORK} or (not require_running and not running and not networks),
            "target container is attached to an unexpected network")
    network = docker.network()
    require(network is not None, "actual internal targets-net is missing", 3)
    if running:
        require(networks[NETWORK].get("NetworkID") == network["Id"] and
                cid in (network.get("Containers") or {}),
                "target is not attached to the actual internal targets-net", 3)
    elif networks:
        # Docker may clear a stopped container's active endpoint metadata.
        require(networks[NETWORK].get("NetworkID", "") in ("", network["Id"]),
                "stopped target references a different internal network")
    mounts = target.get("Mounts", [])
    volume_name = project_name(state) + "_" + VOLUME
    require(len(mounts) == 1 and mounts[0].get("Type") == "volume" and
            mounts[0].get("Name") == volume_name and mounts[0].get("Destination") == "/juice-shop/data" and
            mounts[0].get("RW") is True, "target container has an unexpected mount")
    volume = docker.volume(volume_name)
    observed = {"engine_id": docker.engine_id, "container_id": cid, "image_id": image_id,
                "started_at": target.get("State", {}).get("StartedAt"), "volume_name": volume_name,
                "volume_created_at": volume.get("CreatedAt") if volume is not None else "",
                "network_id": network["Id"]}
    validate_binding(observed)
    check_volume(docker, state, volume, observed)
    binding = state["target"]
    if binding is not None:
        require(all(observed[k] == binding[k] for k in binding if k != "started_at"),
                "target/container/engine/volume/network changed outside the current round")
        if continuity:
            require(observed["started_at"] == binding["started_at"],
                    "target restarted; current round is invalid and explicit reset is required", 3)
    if require_running:
        require(target.get("State", {}).get("Running") is True and
                target.get("State", {}).get("Restarting") is False and
                target.get("NetworkSettings", {}).get("Ports") ==
                {"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3000"}]},
                "target is stopped/restarting or its loopback port is not ready", 3)
    return observed


def attest_application(docker, binding, pins):
    for path in ATTEST:
        raw = docker.copy_bytes(binding["container_id"], path)
        git_blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        require(hmac.compare_digest(git_blob, pins["source_git_blobs"][path]),
                "actual application source differs from the immutable v17.1.1 pin")
        if path == "package.json":
            require(decode_json(raw).get("version") == VERSION, "actual application package version is wrong")


def api_json(path):
    require(path in ("/api/Challenges", "/rest/admin/application-configuration", "/rest/admin/application-version"),
            "API path is outside the fixed local target contract")
    connection = http.client.HTTPConnection("127.0.0.1", 3000, timeout=5)
    try:
        connection.request("GET", path, headers={"Accept": "application/json", "Connection": "close"})
        response = connection.getresponse()
        require(response.status == 200, "target API returned a non-success status", 3)
        require(response.getheader("Content-Type", "").split(";", 1)[0].lower() == "application/json",
                "target API did not return JSON")
        raw = response.read(MAX_JSON + 1)
        return decode_json(raw)
    except (OSError, http.client.HTTPException):
        raise Fault("target API is not reachable/ready on VM loopback port 3000", 3) from None
    finally:
        connection.close()


def actual_catalog(catalog):
    cfg = api_json("/rest/admin/application-configuration")
    require(isinstance(cfg, dict) and isinstance(cfg.get("config"), dict), "target configuration API shape is invalid")
    cfg = cfg["config"]
    require(cfg.get("ctf", {}).get("showFlagsInNotifications") is True and
            cfg.get("application", {}).get("localBackupEnabled") is False and
            cfg.get("application", {}).get("showVersionNumber") is False and
            cfg.get("challenges", {}).get("showHints") is False and
            cfg.get("challenges", {}).get("safetyMode") == "disabled",
            "actual application is not using the pinned CTF configuration")
    # ctf.yml deliberately hides version; package/source/image checks establish it.
    require(api_json("/rest/admin/application-version") == {"version": ""},
            "version API does not match the pinned CTF-mode response")
    response = api_json("/api/Challenges")
    require(isinstance(response, dict) and response.get("status") == "success" and
            isinstance(response.get("data"), list), "challenge catalog API shape is invalid")
    rows = {}
    ids = set()
    for item in response["data"]:
        require(isinstance(item, dict) and isinstance(item.get("key"), str) and
                item["key"] in catalog and item["key"] not in rows and
                type(item.get("id")) is int and item["id"] > 0 and item["id"] not in ids,
                "actual challenge catalog contains invalid/duplicate/unknown identities")
        expected = catalog[item["key"]]
        require(item.get("name") == expected["name"] and
                type(item.get("difficulty")) is int and item["difficulty"] == expected["difficulty"] and
                type(item.get("solved")) is bool, "actual challenge differs from the pinned catalog")
        # Retain only judge fields, never an entire raw target response.
        rows[item["key"]] = {"key": item["key"], "name": item["name"],
                             "id": item["id"], "solved": item["solved"]}
        ids.add(item["id"])
    require(set(rows) == set(catalog), "actual v17.1.1 catalog is incomplete")
    return rows


def ready(docker, store, state, pins, catalog):
    require(state["phase"] in ("starting", "active") and state["target"] is not None,
            "event has no bound running target; run start or finish the explicit reset", 3)
    compose_config(docker, store, state)
    image_id = docker.image()
    binding = inspect_target(docker, store, state, image_id)
    attest_application(docker, binding, pins)
    rows = actual_catalog(catalog)
    # Prevent a restart/replacement during HTTP/source checks from accepting a flag.
    require(inspect_target(docker, store, state, image_id) == binding,
            "target changed during readiness validation")
    return rows


def start(docker, store, state, pins, catalog, wait_seconds):
    require(state["pending"] is None, "reset is incomplete; repeat reset with the current confirmation", 3)
    cfg = compose_config(docker, store, state)
    image_id = docker.image()
    if state["phase"] == "active" or state["target"] is not None:
        # Never restart/recreate an already bound instance under the same event key.
        inspect_target(docker, store, state, image_id)
    else:
        existing = docker.container()
        if existing is not None:
            require(state["phase"] == "starting", "juice-shop container already exists; it is not adopted or overwritten")
            inspect_target(docker, store, state, image_id, require_running=False)
        else:
            project_ids = docker.identifiers(["container", "ls", "--all", "--quiet", "--no-trunc", "--filter",
                                              "label=com.docker.compose.project=" + project_name(state)],
                                             "private project inventory")
            require(not project_ids, "unexpected containers already use this private project")
            volume = docker.volume(project_name(state) + "_" + VOLUME)
            if volume is not None:
                require(state["phase"] == "starting", "existing data volume is not adopted by a new event")
                check_volume(docker, state, volume)
        state["phase"] = "starting"
        store.save(state)
        network = docker.network()
        if network is None:
            docker.call(["network", "create", "--driver", "bridge", "--internal", "--label",
                         PREFIX + "network=" + NETWORK, NETWORK], "internal target network creation")
            require(docker.network() is not None, "internal target network creation was not observed", 4)
        plan = write_plan(store, cfg)
        # Config is checked before every mutation. Pull/install/build are explicit prerequisites.
        docker.call(compose_args(state, plan) + ["up", "--detach", "--no-build", "--pull", "never",
                                                "--no-deps", CONTAINER],
                    "CTF target Compose start", env=event_env(docker, store, state), timeout=120)
        # Bind a created but failed/stopped instance too, so explicit reset can
        # safely recover a partial start without adopting an unrelated target.
        binding = inspect_target(docker, store, state, image_id, require_running=False)
        state["target"] = binding
        store.save(state)
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            rows = ready(docker, store, state, pins, catalog)
            break
        except Fault as exc:
            if exc.code != 3 or time.monotonic() >= deadline:
                raise
            time.sleep(min(1, max(0, deadline - time.monotonic())))
    if state["phase"] == "starting":
        require(not any(row["solved"] for row in rows.values()),
                "new round does not have a clean challenge baseline; explicit reset is required")
        state["phase"] = "active"
        store.save(state)
    return rows


def read_flag():
    import termios
    tty = sys.stdin.isatty()
    previous = None
    try:
        if tty:
            fd = sys.stdin.fileno()
            previous = termios.tcgetattr(fd)
            hidden = list(previous)
            hidden[3] &= ~(termios.ECHO | termios.ECHONL)
            termios.tcsetattr(fd, termios.TCSAFLUSH, hidden)
            print("Flag (stdin, hidden): ", end="", file=sys.stderr, flush=True)
            raw = sys.stdin.buffer.readline(43)
        else:
            # Require EOF after one token, rather than accepting the first of many flags.
            raw = sys.stdin.buffer.read(43)
        if raw.endswith(b"\r\n"):
            raw = raw[:-2]
        elif raw.endswith(b"\n"):
            raw = raw[:-1]
        require(FLAG_RE.fullmatch(raw) is not None, "invalid flag format")
        return raw
    finally:
        if previous is not None:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, previous)
            print(file=sys.stderr)


def verify(docker, store, state, pins, catalog, arguments):
    require(state["phase"] == "active", "current round is not active", 3)
    if arguments.event_id is not None:
        require(arguments.event_id == state["event_id"], "submission belongs to a different event")
    if arguments.round is not None:
        require(arguments.round == state["round"], "submission belongs to a different round")
    rows = ready(docker, store, state, pins, catalog)
    value = arguments.challenge_id
    if value in rows:
        challenge = rows[value]
    elif re.fullmatch(r"[1-9][0-9]{0,8}", value):
        candidates = [row for row in rows.values() if row["id"] == int(value)]
        require(len(candidates) == 1, "challenge ID is not in the actual pinned catalog")
        challenge = candidates[0]
    else:
        raise Fault("challenge ID is not in the actual pinned catalog")
    require(not any(receipt["event_id"] == state["event_id"] and
                    receipt["challenge_key"] == challenge["key"] for receipt in state["receipts"]),
            "challenge has already been accepted in this round")
    flag = read_flag()
    expected = hmac.new(store.key(state["key_file"]), challenge["name"].encode("utf-8"), hashlib.sha1).hexdigest().encode("ascii")
    require(hmac.compare_digest(flag, expected), "flag rejected for the current event/challenge")
    # A claimed solve alone is never accepted; the application must also mark it solved.
    fresh = ready(docker, store, state, pins, catalog)[challenge["key"]]
    require(fresh == challenge and fresh["solved"] is True, "actual application has not solved this challenge")
    binding = state["target"]
    receipt = {"receipt_id": secrets.token_hex(16), "event_id": state["event_id"], "round": state["round"],
               "challenge_id": challenge["id"], "challenge_key": challenge["key"], "challenge_name": challenge["name"],
               "accepted_at": utc_now(), "application_version": VERSION, "source_commit": COMMIT,
               "container_id": binding["container_id"], "image_id": binding["image_id"],
               "container_started_at": binding["started_at"], "verification": "HMAC-SHA1+solved-catalog"}
    state["receipts"].append(receipt)
    store.save(state)
    output(state, "accepted", receipt=receipt)


def reset(docker, store, state, pins, catalog, arguments):
    require(arguments.confirm_event == state["event_id"] and arguments.confirm_round == state["round"],
            "reset confirmation does not match the current event and round")
    compose_config(docker, store, state)
    image_id = docker.image()
    if state["target"] is None and state["phase"] == "starting":
        # A nonzero/interrupted Compose call may have created an owned target
        # before binding was saved. Inspect it before recording reset intent.
        state["target"] = inspect_target(docker, store, state, image_id, require_running=False)
        store.save(state)
    require(state["target"] is not None, "no bound project target exists to reset; reset cannot report a no-op success")
    binding = state["target"]
    require(docker.engine_id == binding["engine_id"] and image_id == binding["image_id"],
            "reset cannot operate on another engine or a replaced image")
    if state["pending"] is None:
        inspect_target(docker, store, state, image_id, require_running=False, continuity=False)
        volume = docker.volume(binding["volume_name"])
        check_volume(docker, state, volume, binding)
        event, key = new_event(state["round"] + 1)
        store.create(event["key_file"], key)
        state["pending"] = {**event, "stage": "planned"}
        state["phase"] = "resetting"
        store.save(state)  # Durable intent before the first destructive Docker operation.
    pending = state["pending"]
    try:
        target = docker.container()
        if target is not None:
            require(pending["stage"] == "planned" and target.get("Id") == binding["container_id"],
                    "unexpected container appeared during reset")
            inspect_target(docker, store, state, image_id, require_running=False, continuity=False)
            docker.call(["container", "rm", "--force", binding["container_id"]], "owned target container removal")
        remaining = docker.identifiers(["container", "ls", "--all", "--quiet", "--no-trunc", "--filter",
                                        "id=" + binding["container_id"]], "removed target confirmation")
        require(not remaining and docker.container() is None, "target container removal was not completed", 4)
        if pending["stage"] == "planned":
            pending["stage"] = "container_removed"
            store.save(state)
        volume = docker.volume(binding["volume_name"])
        if volume is not None:
            require(pending["stage"] == "container_removed", "unexpected volume appeared after reset deletion")
            check_volume(docker, state, volume, binding)
            require(not docker.identifiers(["container", "ls", "--all", "--quiet", "--no-trunc", "--filter",
                                            "volume=" + binding["volume_name"]], "reset volume attachment confirmation"),
                    "a container attached to the target volume during reset")
            docker.call(["volume", "rm", binding["volume_name"]], "owned target data volume removal")
        require(docker.volume(binding["volume_name"]) is None, "target volume removal was not completed", 4)
        pending["stage"] = "volume_removed"
        store.save(state)
        old_key = state["key_file"]
        state["history"].append({"event_id": state["event_id"], "round": state["round"],
                                 "created_at": state["created_at"], "ended_at": utc_now(), "target": binding})
        state.update({k: v for k, v in pending.items() if k != "stage"})
        state.update(phase="initialized", target=None, pending=None)
        store.save(state)
        store.remove(old_key)  # Only the old private event key, never tool/target databases.
        rows = start(docker, store, state, pins, catalog, arguments.wait_seconds)
        # Docker volume CreatedAt has coarse resolution. Removal was confirmed
        # above; the new event labels and new container prove recreation even
        # when both volumes were created within the same clock second.
        require(not any(row["solved"] for row in rows.values()) and
                state["target"]["container_id"] != binding["container_id"],
                "reset did not establish a genuinely new clean target round", 4)
    except Fault as exc:
        raise Fault("reset incomplete: " + str(exc) + "; inspect status and resume the recorded transaction", 4) from None
    output(state, "reset-ready", target_url="http://127.0.0.1:3000", application_version=VERSION)


def positive(value):
    if re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise argparse.ArgumentTypeError("positive integer required")
    return int(value)


def wait_value(value):
    number = positive(value)
    if number > 300:
        raise argparse.ArgumentTypeError("wait must be 1..300 seconds")
    return number


def arguments():
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--runtime-dir", default=None, help="absolute private state directory outside Git")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
    for name in ("init", "start", "status", "verify", "reset"):
        command = commands.add_parser(name, allow_abbrev=False)
        command.add_argument("--runtime-dir", default=argparse.SUPPRESS,
                             help="absolute private state directory outside Git")
        if name in ("start", "reset"):
            command.add_argument("--wait-seconds", default=60, type=wait_value, help="API readiness wait: 1..300 seconds")
        if name == "verify":
            command.add_argument("--challenge-id", required=True, help="pinned challenge key or actual API numeric ID")
            command.add_argument("--event-id", help="optional current-event assertion")
            command.add_argument("--round", type=positive, help="optional current-round assertion")
        if name == "reset":
            command.add_argument("--confirm-event", required=True, help="current event ID from init/status")
            command.add_argument("--confirm-round", required=True, type=positive, help="current round from init/status")
    return parser.parse_args()


def main():
    store = None
    state = None
    args = None
    previous_umask = None
    try:
        args = arguments()
        ubuntu_vm()
        previous_umask = os.umask(0o077)
        pins, catalog = pin_metadata()
        path = runtime_path(args.runtime_dir)
        if args.command == "init":
            initialize(path)
            return 0
        require(path.exists(), "private event is missing; run init in the VM first", 3)
        store = Store(path)
        with store.locked():
            state = store.load(catalog)
            if args.command == "status" and state["phase"] in ("initialized", "resetting"):
                # Still inspect real engine/config/resources, then report genuine lifecycle state.
                docker = Docker()
                compose_config(docker, store, state)
                image_id = docker.image()
                docker.network()
                target = docker.container()
                if target is not None:
                    require(target.get("Id") == (state["target"] or {}).get("container_id"),
                            "unexpected juice-shop container occupies this project target name")
                    require(state["pending"] is not None and state["pending"]["stage"] == "planned",
                            "unexpected target exists after the recorded reset deletion")
                    inspect_target(docker, store, state, image_id, require_running=False, continuity=False)
                volume = docker.volume(project_name(state) + "_" + VOLUME)
                if volume is not None:
                    require(state["phase"] == "resetting" and state["pending"]["stage"] != "volume_removed",
                            "unexpected data volume exists in this lifecycle state")
                    check_volume(docker, state, volume, state["target"])
                output(state, "not-ready", phase=state["phase"],
                       pending_stage=state["pending"]["stage"] if state["pending"] is not None else None,
                       next_action="start" if state["phase"] == "initialized" else "reset with current confirmation")
                return 3
            docker = Docker()
            if args.command == "start":
                rows = start(docker, store, state, pins, catalog, args.wait_seconds)
                output(state, "ready", target_url="http://127.0.0.1:3000", application_version=VERSION,
                       catalog_count=len(rows), target=state["target"])
            elif args.command == "status":
                rows = ready(docker, store, state, pins, catalog)
                require(state["phase"] == "active", "target exists but start has not committed a clean round", 3)
                output(state, "ready", phase=state["phase"], target_url="http://127.0.0.1:3000",
                       application_version=VERSION, catalog_count=len(rows), solved_count=sum(
                           row["solved"] for row in rows.values()), target=state["target"])
            elif args.command == "verify":
                verify(docker, store, state, pins, catalog, args)
            elif args.command == "reset":
                reset(docker, store, state, pins, catalog, args)
        return 0
    except Fault as exc:
        if state is not None and args is not None and args.command == "status":
            output(state, {2: "rejected", 3: "not-ready", 4: "error"}[exc.code], phase=state["phase"])
        print("ctf: " + str(exc), file=sys.stderr)
        return exc.code
    except OSError as exc:
        # No arbitrary exception text, paths, subprocess output, flag or key in diagnostics.
        print("ctf: filesystem/socket operation failed (errno " + str(exc.errno) + ")", file=sys.stderr)
        return 4
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError):
        print("ctf: invalid state, metadata or response; no acceptance recorded", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("ctf: interrupted; inspect private lifecycle state before resuming", file=sys.stderr)
        return 4
    finally:
        if store is not None:
            store.close()
        if previous_umask is not None:
            os.umask(previous_umask)


if __name__ == "__main__":
    sys.exit(main())
