"""Operator-owned configuration and transactional private KoTH storage."""

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from typing import Iterator


class Rejected(Exception):
    """Safe diagnostic containing no submitted values or subprocess output."""

    def __init__(self, message: str, code: int = 2) -> None:
        super().__init__(message)
        self.code = code


def identifier(value: str) -> str:
    """Restrict public participant and round identifiers to safe metadata."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value):
        raise Rejected("invalid participant or round identifier")
    return value


def outside_git(path: Path) -> Path:
    """Reject relative paths, symlink components and any enclosing Git checkout."""
    if not path.is_absolute() or path.resolve() != path:
        raise Rejected("private paths must be absolute and have no symlink components")
    for parent in (path, *path.parents):
        if (parent / ".git").exists():
            raise Rejected("private state and operator inputs must be outside Git")
    return path


def private_file(path: Path) -> None:
    """Require a single-link operator-owned regular file with exact mode 0600."""
    outside_git(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise Rejected("operator files must be owned regular single-link files, mode 0600")


def read_private(path: Path) -> bytes:
    """Read a bounded configuration file without following a final symlink."""
    private_file(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        raise Rejected("private configuration exceeds its size limit")
    return raw


def unique_object(pairs: list[tuple[str, str]]) -> dict:
    """Reject duplicate JSON keys rather than accept ambiguous operator input."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("duplicate JSON key")
        result[key] = value
    return result


def decode(raw: bytes | str) -> dict:
    """Parse strict JSON without echoing malformed or secret input."""
    try:
        value = json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected("invalid JSON") from None
    if not isinstance(value, dict):
        raise Rejected("JSON must be an object")
    return value


def reject_constant(_value: str) -> None:
    raise Rejected("non-finite JSON constants are not permitted")


def executable(value: str) -> str:
    """Require an explicitly selected absolute executable, never a shell string."""
    if (not isinstance(value, str) or not Path(value).is_absolute()
            or not Path(value).is_file() or not os.access(value, os.X_OK)):
        raise Rejected("an explicit absolute executable is required")
    return value


def bounded_integer(value: int, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise Rejected("integer configuration outside permitted bounds")
    return value


@dataclass(frozen=True, slots=True)
class Config:
    participants: tuple[str, ...]
    round_id: str
    contest_machine_id: str
    host: str
    port: int
    user: str
    client: str
    known_hosts: str
    identity_file: str
    remote_python: str
    marker: str
    services: tuple[str, ...]
    round_seconds: int
    tick_seconds: int
    probe_timeout: int
    reset_argv: tuple[str, ...]
    reset_timeout: int

    @classmethod
    def parse(cls, data: dict) -> "Config":
        """Parse the single operator boundary; no production fixture defaults."""
        required = {
            "version", "approved_target", "manager_outside_contest", "participants",
            "round_id", "contest_machine_id", "ssh", "marker", "services", "reset_argv",
        }
        optional = {"round_seconds", "tick_seconds", "probe_timeout", "reset_timeout"}
        if not required <= data.keys() or data.keys() - required - optional:
            raise Rejected("configuration has missing or unsupported fields")
        if (type(data["version"]) is not int or data["version"] != 1
                or data["approved_target"] is not True or data["manager_outside_contest"] is not True):
            raise Rejected("explicit approved VM and outside-manager attestations are required")
        roster = data["participants"]
        if not isinstance(roster, list) or not 1 <= len(roster) <= 64:
            raise Rejected("an explicit participant roster is required")
        participants = tuple(identifier(item) for item in roster)
        if len(set(participants)) != len(participants):
            raise Rejected("participant roster contains duplicates")
        ssh = data["ssh"]
        if not isinstance(ssh, dict) or set(ssh) != {
            "host", "port", "user", "client", "known_hosts", "identity_file", "remote_python",
        }:
            raise Rejected("explicit SSH endpoint, port, client, trust and identity are required")
        host, user = ssh["host"], ssh["user"]
        if (not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", host)
                or not isinstance(user, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", user)):
            raise Rejected("invalid SSH endpoint metadata")
        for field in ("known_hosts", "identity_file"):
            if not isinstance(ssh[field], str) or any(c in ssh[field] for c in '\n\r%~"\\'):
                raise Rejected("invalid SSH private file path")
            private_file(Path(ssh[field]))
            if Path(ssh[field]).stat().st_size == 0:
                raise Rejected("SSH trust and identity files must not be empty")
        python = ssh["remote_python"]
        if not isinstance(python, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+", python):
            raise Rejected("explicit absolute guest Python executable is required")
        marker = data["marker"]
        if (not isinstance(marker, str) or not marker.startswith("/") or len(marker) > 1024
                or "\x00" in marker or any(p in (".", "..") for p in marker.split("/"))):
            raise Rejected("marker must be an absolute guest path")
        units = data["services"]
        if (not isinstance(units, list) or not 1 <= len(units) <= 16
                or any(not isinstance(u, str) or not re.fullmatch(
                    r"[A-Za-z0-9_][A-Za-z0-9_.@-]{0,120}\.service", u) for u in units)
                or len(set(units)) != len(units)):
            raise Rejected("explicit unique required systemd services are required")
        machine = data["contest_machine_id"]
        if not isinstance(machine, str) or not re.fullmatch(r"[0-9a-f]{32}", machine):
            raise Rejected("explicit contest machine identity is required")
        manager = Path("/etc/machine-id").read_text(encoding="ascii").strip()
        if not re.fullmatch(r"[0-9a-f]{32}", manager) or machine == manager:
            raise Rejected("judge must run outside the contest VM")
        reset = data["reset_argv"]
        if (not isinstance(reset, list) or len(reset) > 128
                or any(not isinstance(a, str) or not a or "\x00" in a or len(a) > 4096 for a in reset)):
            raise Rejected("reset_argv must be an explicit argv array or empty when unregistered")
        if reset:
            executable(reset[0])
        tick = bounded_integer(data.get("tick_seconds", 5), 2, 3600)
        duration = bounded_integer(data.get("round_seconds", 900), tick, 86400)
        timeout = bounded_integer(data.get("probe_timeout", min(4, tick - 1)), 1, tick - 1)
        return cls(
            participants, identifier(data["round_id"]), machine, host,
            bounded_integer(ssh["port"], 1, 65535), user, executable(ssh["client"]),
            ssh["known_hosts"], ssh["identity_file"], python, marker, tuple(units),
            duration, tick, timeout, tuple(reset),
            bounded_integer(data.get("reset_timeout", 120), 1, 3600),
        )


SCHEMA = """
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE rounds (
    id TEXT PRIMARY KEY, lifecycle TEXT NOT NULL,
    boot_id TEXT, start_ns INTEGER, deadline_ns INTEGER, closed_reason TEXT,
    last_owner TEXT, created_utc TEXT NOT NULL
);
CREATE TABLE ticks (
    round_id TEXT NOT NULL REFERENCES rounds(id), slot INTEGER NOT NULL,
    sampled_ns INTEGER NOT NULL, finished_ns INTEGER,
    observation TEXT NOT NULL, owner TEXT, points INTEGER NOT NULL DEFAULT 0,
    transition INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(round_id, slot), CHECK(points IN (0,1))
);
CREATE TABLE resets (
    attempt INTEGER PRIMARY KEY, old_round TEXT NOT NULL REFERENCES rounds(id),
    new_round TEXT NOT NULL, result TEXT NOT NULL, started_utc TEXT NOT NULL,
    finished_utc TEXT, command_exit INTEGER, pre_boot_id TEXT NOT NULL,
    post_boot_id TEXT
);
"""


def state_directory(path: Path, create: bool = False) -> Path:
    """Keep score state outside Git in an operator-owned 0700 directory."""
    outside_git(path)
    if create and not path.exists():
        path.mkdir(mode=0o700)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise Rejected("state directory must be operator-owned with mode 0700")
    for child in path.iterdir():
        if child.name not in {"judge.sqlite3", "judge.sqlite3-journal", "controller.lock"}:
            raise Rejected("unexpected file in private state directory")
        try:
            private_file(child)
        except FileNotFoundError:
            # DELETE-mode SQLite removes its journal at commit. Status may
            # enumerate it just before another controller completes a commit.
            if child.name != "judge.sqlite3-journal":
                raise
    return path


@contextmanager
def controller(path: Path) -> Iterator[None]:
    """One mutating controller per state directory, including during SSH/reset."""
    fd = os.open(path / "controller.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "rb") as lock:
        private_file(path / "controller.lock")
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Rejected("another controller owns this state directory", 4) from None
        yield


@contextmanager
def database(path: Path, create: bool = False, readonly: bool = False) -> Iterator[sqlite3.Connection]:
    """SQLite FULL synchronous transactions; no guest-owned score endpoint."""
    file = path / "judge.sqlite3"
    if create:
        with os.fdopen(os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb"):
            pass
    private_file(file)
    connection = sqlite3.connect(
        file.as_uri() + ("?mode=ro" if readonly else "?mode=rw"),
        uri=True, isolation_level=None, timeout=2,
    )
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        if not readonly:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
        yield connection
    finally:
        connection.close()


@contextmanager
def transaction(db: sqlite3.Connection, readonly: bool = False) -> Iterator[None]:
    db.execute("BEGIN" if readonly else "BEGIN IMMEDIATE")
    try:
        yield
    finally:
        # On exceptions, including SIGINT, preserve previously committed rows.
        db.execute("ROLLBACK" if sys.exc_info()[0] else "COMMIT")
