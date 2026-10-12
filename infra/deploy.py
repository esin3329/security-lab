#!/usr/bin/env python3
"""Package tracked lab sources and atomically deploy them to an Ubuntu VM.

This transport installs no system packages and starts no lab/game services.
Credentials stay with OpenSSH. Runtime keys, state, logs and worktrees are not
included in the bundle. Use check before deploy; deploy requires an explicit
confirmation of the exact SSH target.
"""

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile


PROJECT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "infra/compose.targets.yml",
    "tools/ctf/practice.py",
    "tools/koth/practice.py",
    "tools/lab/practice.py",
)
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_FILES = 1024


class DeploymentError(Exception):
    """A safe deployment diagnostic without credentials or remote output."""


REMOTE_PROBE = r'''
import json, os, pathlib, shlex, sys
values = {}
if sys.platform != "linux":
    raise SystemExit(2)
for line in pathlib.Path("/etc/os-release").read_text().splitlines():
    if "=" in line and not line.startswith("#"):
        key, value = line.split("=", 1)
        parsed = shlex.split(value)
        values[key] = parsed[0] if parsed else ""
if values.get("ID") != "ubuntu" or sys.version_info < (3, 8):
    raise SystemExit(2)
print(json.dumps({"platform": "linux", "os_id": values["ID"],
                  "os_version": values.get("VERSION_ID", ""),
                  "python": list(sys.version_info[:3]), "uid": os.getuid(),
                  "home": str(pathlib.Path.home())}))
'''


REMOTE_RECEIVE = r'''
import base64, hashlib, io, json, os, pathlib, shutil, stat, sys, tarfile, tempfile

LIMIT = 64 * 1024 * 1024
FILE_LIMIT = 8 * 1024 * 1024
COUNT_LIMIT = 1024
stage = None
root = None
try:
    request = json.loads(base64.urlsafe_b64decode(sys.argv[1]).decode("utf-8"))
    digest = request["sha256"]
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("digest")
    home = pathlib.Path.home().resolve()
    root = pathlib.Path(os.path.expanduser(request["remote_dir"]))
    if not root.is_absolute():
        raise ValueError("absolute destination required")
    # Require every existing ancestor below HOME to be a real directory, not a
    # symlink. Do not let a release write escape into arbitrary host paths.
    relative = root.relative_to(home)
    if not relative.parts or any(p in (".", "..") for p in relative.parts):
        raise ValueError("destination")
    cursor = home
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("destination symlink")
        if cursor.exists() and not cursor.is_dir():
            raise ValueError("destination ancestor")
    if root.exists():
        if root.stat().st_uid != os.getuid():
            raise ValueError("destination owner")
        marker = root / ".security-lab-deployment.json"
        if not marker.is_file() or marker.is_symlink():
            raise ValueError("unmanaged destination")
        if json.loads(marker.read_text()).get("project") != "security-lab":
            raise ValueError("project marker")
    else:
        root.mkdir(parents=True, mode=0o700)
        marker = root / ".security-lab-deployment.json"
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump({"project": "security-lab"}, stream)
            stream.flush()
            os.fsync(stream.fileno())
    os.chmod(root, 0o700)
    releases = root / "releases"
    if releases.is_symlink():
        raise ValueError("releases symlink")
    releases.mkdir(mode=0o700, exist_ok=True)
    if releases.stat().st_uid != os.getuid():
        raise ValueError("releases owner")
    current = root / "current"
    if current.exists() or current.is_symlink():
        if not current.is_symlink():
            raise ValueError("unmanaged current")
        current.resolve(strict=True).relative_to(releases.resolve())
    stage = pathlib.Path(tempfile.mkdtemp(prefix=".incoming-", dir=str(releases)))
    archive_path = stage / "bundle.tar"
    hasher = hashlib.sha256()
    size = 0
    with archive_path.open("xb") as stream:
        while True:
            chunk = sys.stdin.buffer.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > LIMIT:
                raise ValueError("bundle limit")
            hasher.update(chunk)
            stream.write(chunk)
    if hasher.hexdigest() != digest:
        raise ValueError("archive digest")
    payload = stage / "payload"
    payload.mkdir(mode=0o700)
    with tarfile.open(archive_path, mode="r:") as archive:
        members = archive.getmembers()
        if len(members) > COUNT_LIMIT + 1:
            raise ValueError("file count")
        names = set()
        by_name = {}
        for member in members:
            name = member.name
            parts = pathlib.PurePosixPath(name)
            if (parts.is_absolute() or not parts.parts or
                    any(p in (".", "..") for p in parts.parts) or
                    not member.isfile() or member.size > FILE_LIMIT or
                    name in names or "\\" in name):
                raise ValueError("unsafe archive member")
            names.add(name)
            by_name[name] = member
        manifest_member = by_name.get(".security-lab-manifest.json")
        if manifest_member is None:
            raise ValueError("manifest missing")
        source = archive.extractfile(manifest_member)
        if source is None:
            raise ValueError("manifest unreadable")
        with source:
            manifest = json.load(source)
        if manifest.get("project") != "security-lab":
            raise ValueError("manifest project")
        records = manifest.get("files")
        if not isinstance(records, list) or not records or len(records) > COUNT_LIMIT:
            raise ValueError("manifest files")
        expected = {}
        for record in records:
            name = record["path"]
            if name in expected or name == ".security-lab-manifest.json":
                raise ValueError("duplicate manifest path")
            expected[name] = record
        if names != set(expected) | {".security-lab-manifest.json"}:
            raise ValueError("manifest mismatch")
        for name, record in expected.items():
            member = by_name[name]
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("source unreadable")
            destination = payload.joinpath(*pathlib.PurePosixPath(name).parts)
            destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            checksum = hashlib.sha256()
            written = 0
            with source, destination.open("xb") as stream:
                while True:
                    chunk = source.read(65536)
                    if not chunk:
                        break
                    written += len(chunk)
                    checksum.update(chunk)
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            if written != record["size"] or checksum.hexdigest() != record["sha256"]:
                raise ValueError("file integrity")
            executable = record.get("executable")
            if not isinstance(executable, bool):
                raise ValueError("file mode")
            os.chmod(destination, 0o700 if executable else 0o600)
        (payload / ".security-lab-manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        os.chmod(payload / ".security-lab-manifest.json", 0o600)
    # Keep immutable releases instead of overwriting an active checkout. A new
    # private staging directory gives this process unambiguous cleanup ownership.
    release = releases / (digest[:16] + "-" + stage.name[len(".incoming-"):])
    os.rename(payload, release)
    link = stage / "current-link"
    link.symlink_to(pathlib.Path("releases") / release.name)
    os.replace(link, current)
    print(json.dumps({"project": "security-lab", "sha256": digest,
                      "release": str(release), "current": str(current),
                      "files": len(records), "services_started": False}))
except Exception:
    print("deployment: verified installation failed; current release was not replaced unless activation completed",
          file=sys.stderr)
    raise SystemExit(2)
finally:
    if stage is not None:
        shutil.rmtree(stage)
'''


def safe_target(value):
    if (not value or value.startswith("-") or
            re.fullmatch(r"[A-Za-z0-9_.@:\[\]-]+", value) is None):
        raise argparse.ArgumentTypeError("invalid OpenSSH target or alias")
    return value


def safe_port(value):
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("SSH port must be 1..65535") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("SSH port must be 1..65535")
    return port


def source_paths(project):
    result = subprocess.run(["git", "ls-files", "-z"], cwd=project,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=False)
    if result.returncode:
        raise DeploymentError("cannot enumerate tracked project sources")
    try:
        tracked = result.stdout.decode("utf-8").split("\0")
    except UnicodeError:
        raise DeploymentError("tracked source names are not UTF-8") from None
    selected = []
    for name in tracked:
        if not name:
            continue
        relative = Path(name)
        allowed = (name in ("README.md", ".gitignore") or
                   relative.parts[0] in ("infra", "tools", "pwn", "targets", "benchmarks"))
        private = any(part.startswith(".env") or part in (
            ".git", ".worktrees", "__pycache__", ".venv", "node_modules",
            "state", "runtime", "data", "logs") for part in relative.parts)
        if (not allowed or private or relative.suffix.lower() in (
                ".pyc", ".log", ".jsonl", ".db", ".sqlite", ".sqlite3",
                ".pem", ".key", ".p12", ".pfx")):
            continue
        path = project / relative
        if not path.is_file() or path.is_symlink():
            raise DeploymentError("tracked source is missing or is not a regular file")
        path.resolve().relative_to(project.resolve())
        if path.stat().st_size > MAX_FILE_BYTES:
            raise DeploymentError("tracked source exceeds the deployment file limit")
        selected.append((name, path))
    included = {name for name, _ in selected}
    if not all(name in included for name in REQUIRED):
        raise DeploymentError("practice entrypoints are not integrated and tracked yet")
    if len(selected) > MAX_FILES:
        raise DeploymentError("deployment file count exceeds the limit")
    return sorted(selected)


def make_bundle(project, destination):
    paths = source_paths(project)
    records = []
    temporary_name = None
    try:
        # Build privately, then publish with an exclusive link. Never truncate an
        # operator's existing output file, including a raced-in symlink.
        with tempfile.NamedTemporaryFile(mode="w+b", prefix=".lab-bundle-",
                                         dir=destination.parent, delete=False) as output:
            temporary_name = Path(output.name)
            with tarfile.open(fileobj=output, mode="w:") as archive:
                for name, path in paths:
                    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(descriptor, "rb") as source:
                        details = os.fstat(source.fileno())
                        if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_FILE_BYTES:
                            raise DeploymentError("tracked source is not a bounded regular file")
                        raw = source.read(MAX_FILE_BYTES + 1)
                    if len(raw) > MAX_FILE_BYTES:
                        raise DeploymentError("tracked source exceeds the deployment file limit")
                    executable = bool(details.st_mode & stat.S_IXUSR)
                    record = {"path": name, "size": len(raw),
                              "sha256": hashlib.sha256(raw).hexdigest(),
                              "executable": executable}
                    info = tarfile.TarInfo(name)
                    info.size = len(raw)
                    info.mode = 0o700 if executable else 0o600
                    info.mtime = 0
                    archive.addfile(info, io.BytesIO(raw))
                    records.append(record)
                manifest = {"project": "security-lab", "files": records}
                raw_manifest = json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode("utf-8")
                info = tarfile.TarInfo(".security-lab-manifest.json")
                info.size = len(raw_manifest)
                info.mode = 0o600
                archive.addfile(info, io.BytesIO(raw_manifest))
            output.flush()
            os.fsync(output.fileno())
            if output.tell() > MAX_BUNDLE_BYTES:
                raise DeploymentError("deployment bundle exceeds the size limit")
        hasher = hashlib.sha256()
        with temporary_name.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(chunk)
        try:
            os.link(temporary_name, destination)
        except FileExistsError:
            raise DeploymentError("bundle output already exists; choose a new path") from None
        return {"sha256": hasher.hexdigest(), "files": len(records)}
    finally:
        if temporary_name is not None:
            temporary_name.unlink()


def ssh_prefix(arguments):
    executable = shutil.which(arguments.ssh_executable)
    if executable is None:
        raise DeploymentError("configured OpenSSH executable is unavailable")
    command = [executable, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", "ConnectTimeout=10", "-p", str(arguments.port)]
    if arguments.jump:
        command.extend(["-J", arguments.jump])
    if arguments.identity:
        command.extend(["-i", arguments.identity])
    if arguments.ssh_config:
        command.extend(["-F", arguments.ssh_config])
    command.append(arguments.target)
    return command


def remote_command(script, argument=None):
    command = "python3 -c " + shlex.quote(script)
    if argument is not None:
        command += " " + shlex.quote(argument)
    return command


def check_vm(arguments):
    command = ssh_prefix(arguments) + [remote_command(REMOTE_PROBE)]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=30)
    except subprocess.TimeoutExpired:
        raise DeploymentError("SSH VM metadata check timed out") from None
    if result.returncode:
        raise DeploymentError("SSH VM metadata check failed; verify the server VM route and authentication")
    try:
        metadata = json.loads(result.stdout)
        if (metadata["platform"] != "linux" or metadata["os_id"] != "ubuntu" or
                tuple(metadata["python"]) < (3, 8)):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise DeploymentError("remote endpoint did not prove the required Ubuntu/Python runtime") from None
    return metadata


def deploy(arguments, archive_path, bundle):
    if arguments.approve_target != arguments.target:
        raise DeploymentError("deploy requires --approve-target matching the exact --target")
    metadata = check_vm(arguments)
    request = {"sha256": bundle["sha256"], "remote_dir": arguments.remote_dir}
    encoded = base64.urlsafe_b64encode(json.dumps(request).encode("utf-8")).decode("ascii")
    command = ssh_prefix(arguments) + [remote_command(REMOTE_RECEIVE, encoded)]
    try:
        with archive_path.open("rb") as stream:
            result = subprocess.run(command, stdin=stream, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=300)
    except subprocess.TimeoutExpired:
        raise DeploymentError("deployment transfer timed out; inspect remote state before retrying") from None
    if result.returncode:
        raise DeploymentError("remote deployment rejected or failed; active release must be inspected before retrying")
    try:
        receipt = json.loads(result.stdout)
        if receipt["sha256"] != bundle["sha256"] or receipt["services_started"] is not False:
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise DeploymentError("remote deployment receipt is unverifiable; do not blindly retry") from None
    receipt["os_id"] = metadata["os_id"]
    receipt["os_version"] = metadata["os_version"]
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("command", choices=("plan", "pack", "check", "deploy"))
    parser.add_argument("--target", type=safe_target)
    parser.add_argument("--port", type=safe_port, default=22)
    parser.add_argument("--jump", type=safe_target)
    parser.add_argument("--identity")
    parser.add_argument("--ssh-config")
    parser.add_argument("--ssh-executable", default="ssh")
    parser.add_argument("--remote-dir", default="~/.local/share/security-lab/app")
    parser.add_argument("--approve-target")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.command in ("check", "deploy") and not arguments.target:
            raise DeploymentError("--target is required for a server VM connection")
        if arguments.command == "check":
            result = check_vm(arguments)
            result["services_started"] = False
        elif arguments.command == "pack":
            if arguments.output is None:
                raise DeploymentError("pack requires --output for the deployment archive")
            destination = arguments.output.expanduser().absolute()
            result = make_bundle(PROJECT, destination)
            result["bundle"] = str(destination)
            result["services_started"] = False
        else:
            with tempfile.TemporaryDirectory(prefix="security-lab-deployment-") as temporary:
                archive_path = Path(temporary) / "bundle.tar"
                bundle = make_bundle(PROJECT, archive_path)
                result = bundle if arguments.command == "plan" else deploy(arguments, archive_path, bundle)
                if arguments.command == "plan":
                    result["services_started"] = False
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except (DeploymentError, OSError, ValueError, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, DeploymentError) else "local deployment preparation failed"
        print("deployment: " + message, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
