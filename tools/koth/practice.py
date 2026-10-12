#!/usr/bin/env python3
"""External-manager KoTH controller; Linux Python 3.10+ standard library only.

python3 tools/koth/practice.py <init|observe|run|status|reset> --state-dir ABS
Exit 0: completed operation. 2: refused configuration/state/I/O.
Exit 3: uncredited observation or failed real reset. 4: duplicate controller/tick.
Exit 130: interrupted; round deadline is retained and no missing sample credited.

No command installs software, scans addresses, accepts scores, or runs attacks.
"""

import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import sqlite3
import sys
import threading
import time

from judge import (
    configuration, current_round, emit, identifier, pause, sample, start,
    status, utc,
)
from observer import observe, execute
from state import (
    Config, Rejected, SCHEMA, controller, database, decode, read_private,
    state_directory, transaction,
)


class Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        self.exit(2, "koth: invalid arguments; use --help\n")


def arguments() -> argparse.Namespace:
    parser = Parser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
    for name in ("init", "observe", "run", "status", "reset"):
        command = commands.add_parser(name, allow_abbrev=False)
        command.add_argument("--state-dir", required=True, type=Path)
        match name:
            case "init":
                command.add_argument("--config", required=True, type=Path,
                                     help="operator-owned 0600 JSON outside Git")
            case "observe":
                command.add_argument("--round", required=True)
            case "run":
                command.add_argument("--round", required=True)
                command.add_argument("--resume", action="store_true")
            case "status":
                command.add_argument("--round", help="optional closed historical round")
            case "reset":
                command.add_argument("--confirm-round", required=True)
                command.add_argument("--new-round", required=True)
                command.add_argument("--retry-failed-reset", action="store_true",
                                     help="explicitly rerun the registered snapshot argv")
                command.add_argument("--verify-only", action="store_true",
                                     help="recheck a completed command without rerunning it")
    return parser.parse_args()


def initialize(args: argparse.Namespace, path: Path) -> int:
    data = decode(read_private(args.config))
    config = Config.parse(data)
    with database(path, create=True) as db:
        db.executescript("BEGIN IMMEDIATE;\n" + SCHEMA)
        try:
            db.executemany("INSERT INTO metadata(key,value) VALUES(?,?)", [
                ("schema_version", "1"),
                ("config", json.dumps(data, separators=(",", ":"), allow_nan=False)),
                ("current_round", config.round_id),
            ])
            db.execute(
                "INSERT INTO rounds(id,lifecycle,created_utc) VALUES(?,'ready',?)",
                (config.round_id, utc()),
            )
            db.execute("COMMIT")
        except (sqlite3.Error, ValueError):
            db.execute("ROLLBACK")
            raise
    emit({"round_id": config.round_id, "lifecycle": "ready", "network_verified": False,
          "reset_registered": bool(config.reset_argv)})
    return 0


def play(args: argparse.Namespace, db: sqlite3.Connection, config: Config) -> int:
    if not config.reset_argv:
        raise Rejected("snapshot reset prerequisite is missing; sampling is disabled", 3)
    single = args.command == "observe"
    if not start(db, config, args.round, getattr(args, "resume", False), single):
        emit(status(db, args.round, True))
        if single:
            raise Rejected("round expired; no tick was observed")
        return 0
    failure = False
    sleeper = threading.Event()
    try:
        while True:
            row = current_round(db, args.round)
            now = time.monotonic_ns()
            width = config.tick_seconds * 1_000_000_000
            slot = (now - row["start_ns"]) // width
            exists = db.execute(
                "SELECT 1 FROM ticks WHERE round_id=? AND slot=?", (args.round, slot),
            ).fetchone()
            if exists and not single and now < row["deadline_ns"]:
                # Wait on the manager deadline, not client timestamps. No backfill.
                due = min(row["start_ns"] + (slot + 1) * width, row["deadline_ns"])
                sleeper.wait(max(0, (due - time.monotonic_ns()) / 1_000_000_000))
                continue
            receipt = sample(db, config, args.round)
            if receipt is None:
                break
            emit(receipt)
            failure = failure or not bool(receipt["points"])
            if single:
                break
    finally:
        pause(db, args.round)
    emit(status(db, args.round, True))
    return 3 if failure else 0


def reset(args: argparse.Namespace, db: sqlite3.Connection, config: Config) -> int:
    """Run the operator snapshot argv; require actual reboot evidence afterward."""
    old = current_round(db, args.confirm_round)
    new = identifier(args.new_round)
    if not config.reset_argv:
        raise Rejected("snapshot reset argv is unregistered", 3)
    if new == old["id"] or db.execute("SELECT 1 FROM rounds WHERE id=?", (new,)).fetchone():
        raise Rejected("new round must have a fresh explicit identifier")
    if args.verify_only and args.retry_failed_reset:
        raise Rejected("verification-only and command retry are mutually exclusive")
    last = db.execute("SELECT * FROM resets ORDER BY attempt DESC LIMIT 1").fetchone()
    recovering = old["lifecycle"] in ("resetting", "reset_failed")
    if args.retry_failed_reset and not recovering:
        raise Rejected("command retry requires an unresolved previous reset")
    if recovering and not (args.retry_failed_reset or args.verify_only):
        raise Rejected("previous reset is unresolved; explicitly verify or retry", 3)
    if args.verify_only:
        if (not recovering or last is None or last["old_round"] != old["id"]
                or last["new_round"] != new or last["command_exit"] != 0):
            raise Rejected("no successful command awaiting this exact reset verification", 3)
        attempt = last["attempt"]
        before_boot = last["pre_boot_id"]
    else:
        before = observe(config)
        if not before.identity or not before.boot_id:
            raise Rejected("cannot verify approved VM identity before reset", 3)
        before_boot = before.boot_id
        with transaction(db):
            db.execute(
                "UPDATE rounds SET lifecycle='resetting',last_owner=NULL,closed_reason='snapshot_reset' WHERE id=?",
                (old["id"],),
            )
            cursor = db.execute(
                "INSERT INTO resets(old_round,new_round,result,started_utc,pre_boot_id) "
                "VALUES(?,?,'executing',?,?)", (old["id"], new, utc(), before_boot),
            )
            attempt = cursor.lastrowid
        try:
            result = execute(config.reset_argv, config.reset_timeout, capture=False)
        except KeyboardInterrupt:
            with transaction(db):
                db.execute("UPDATE resets SET result='interrupted',finished_utc=? WHERE attempt=?",
                           (utc(), attempt))
                db.execute("UPDATE rounds SET lifecycle='reset_failed' WHERE id=?", (old["id"],))
            raise
        with transaction(db):
            db.execute(
                "UPDATE resets SET command_exit=?,result=?,finished_utc=? WHERE attempt=?",
                (result.exit_code, "awaiting_verification" if result.exit_code == 0 and not result.failure
                 else result.failure or "command_failed", utc(), attempt),
            )
        if result.failure or result.exit_code != 0:
            with transaction(db):
                db.execute("UPDATE rounds SET lifecycle='reset_failed' WHERE id=?", (old["id"],))
            raise Rejected("real snapshot reset command failed; round remains unplayable", 3)
    after = observe(config)
    verified = bool(after.identity and after.healthy and after.boot_id and after.boot_id != before_boot)
    with transaction(db):
        db.execute(
            "UPDATE resets SET result=?,finished_utc=?,post_boot_id=? WHERE attempt=?",
            ("verified" if verified else "verification_failed", utc(), after.boot_id, attempt),
        )
        if verified:
            db.execute("UPDATE rounds SET lifecycle='closed' WHERE id=?", (old["id"],))
            db.execute("INSERT INTO rounds(id,lifecycle,created_utc) VALUES(?,'ready',?)", (new, utc()))
            db.execute("UPDATE metadata SET value=? WHERE key='current_round'", (new,))
        else:
            db.execute("UPDATE rounds SET lifecycle='reset_failed' WHERE id=?", (old["id"],))
    if not verified:
        raise Rejected("reset lacks changed VM boot identity and healthy services; no new round created", 3)
    emit({"closed_round": old["id"], "new_round": new, "lifecycle": "ready",
          "reset_attempt": attempt, "reset": "verified_reboot_and_health"})
    return 0


def controller_active(path: Path) -> bool:
    with os.fdopen(os.open(path / "controller.lock", os.O_RDONLY | os.O_NOFOLLOW), "rb") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False


def interrupted(_signum: int, _frame) -> None:
    raise KeyboardInterrupt


def main() -> int:
    os.umask(0o077)
    try:
        args = arguments()
        signal.signal(signal.SIGTERM, interrupted)
        path = state_directory(args.state_dir, create=args.command == "init")
        if args.command == "status":
            with database(path, readonly=True) as db:
                emit(status(db, args.round, controller_active(path)))
            return 0
        with controller(path):
            if args.command == "init":
                return initialize(args, path)
            with database(path) as db:
                config = configuration(db)
                match args.command:
                    case "observe" | "run":
                        return play(args, db, config)
                    case "reset":
                        return reset(args, db, config)
        raise Rejected("unsupported command")
    except Rejected as exc:
        print("koth: " + str(exc), file=sys.stderr)
        return exc.code
    except (OSError, sqlite3.Error, ValueError, KeyError, TypeError, RecursionError):
        print("koth: protected state, configuration or system operation failed", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("koth: interrupted; no missing sample credited; inspect protected status", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
