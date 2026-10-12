"""Manager-clock sampling and round lifecycle. One point is one verified sample."""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import time

from observer import observe
from state import Config, Rejected, decode, identifier, transaction


def utc() -> str:
    """Audit time only: never used to compute slots, duration, or points."""
    return datetime.now(timezone.utc).isoformat()


def boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()


def emit(data: dict) -> None:
    print(json.dumps(data, separators=(",", ":"), allow_nan=False), flush=True)


def configuration(db: sqlite3.Connection) -> Config:
    rows = dict(db.execute("SELECT key,value FROM metadata"))
    if rows.get("schema_version") != "1" or "config" not in rows or "current_round" not in rows:
        raise Rejected("private state schema is incomplete or unsupported")
    return Config.parse(decode(rows["config"]))


def current_round(db: sqlite3.Connection, requested: str) -> sqlite3.Row:
    identifier(requested)
    row = db.execute("SELECT value FROM metadata WHERE key='current_round'").fetchone()
    if row is None or requested != row[0]:
        raise Rejected("explicit round does not match the current round")
    result = db.execute("SELECT * FROM rounds WHERE id=?", (requested,)).fetchone()
    if result is None:
        raise Rejected("current round is missing")
    return result


def close(db: sqlite3.Connection, round_id: str, reason: str) -> None:
    db.execute(
        "UPDATE rounds SET lifecycle='closed',closed_reason=?,last_owner=NULL WHERE id=?",
        (reason, round_id),
    )


def check_clock(db: sqlite3.Connection, row: sqlite3.Row) -> bool:
    """Persist closure rather than reuse monotonic offsets across manager boots."""
    if row["start_ns"] is None:
        return True
    if row["boot_id"] != boot_id() or time.monotonic_ns() < row["start_ns"]:
        with transaction(db):
            close(db, row["id"], "manager_clock_invalid")
        raise Rejected("manager reboot or clock discontinuity closed the round; reset required")
    if time.monotonic_ns() >= row["deadline_ns"]:
        with transaction(db):
            close(db, row["id"], "deadline")
        return False
    return True


def start(db: sqlite3.Connection, config: Config, round_id: str, resume: bool, single: bool) -> bool:
    row = current_round(db, round_id)
    if row["lifecycle"] not in ("ready", "running", "paused"):
        raise Rejected("round is not playable; inspect status and reset explicitly")
    if not check_clock(db, row):
        return False
    if row["start_ns"] is not None and not single and not resume:
        raise Rejected("an existing round requires run --resume")
    now = time.monotonic_ns()
    with transaction(db):
        if row["start_ns"] is None:
            db.execute(
                "UPDATE rounds SET start_ns=?,deadline_ns=?,boot_id=?,lifecycle='running' WHERE id=?",
                (now, now + config.round_seconds * 1_000_000_000, boot_id(), round_id),
            )
        else:
            db.execute("UPDATE rounds SET lifecycle='running' WHERE id=?", (round_id,))
    return True


def sample(db: sqlite3.Connection, config: Config, round_id: str) -> dict | None:
    """Reserve a unique slot before network I/O; incomplete probes earn zero."""
    row = current_round(db, round_id)
    if not check_clock(db, row):
        return None
    now = time.monotonic_ns()
    width = config.tick_seconds * 1_000_000_000
    slot = (now - row["start_ns"]) // width
    prior = db.execute(
        "SELECT owner FROM ticks WHERE round_id=? AND slot=? AND points=1",
        (round_id, slot - 1),
    ).fetchone()
    previous_owner = prior[0] if prior else None
    try:
        with transaction(db):
            db.execute(
                "INSERT INTO ticks(round_id,slot,sampled_ns,observation) VALUES(?,?,?,'incomplete')",
                (round_id, slot, now),
            )
            db.execute("UPDATE rounds SET last_owner=NULL WHERE id=?", (round_id,))
    except sqlite3.IntegrityError:
        raise Rejected("this judge-clock tick is already reserved or recorded", 4) from None
    observation = observe(config)
    finished = time.monotonic_ns()
    reason = observation.reason
    owner = observation.owner
    # A slow sample cannot stand in for a sample of a later slot or after end.
    if finished >= row["deadline_ns"] or (finished - row["start_ns"]) // width != slot:
        reason, owner = "late_probe", None
    credited = int(reason == "approved" and owner is not None and observation.healthy)
    if not credited:
        owner = None
    transition = int(bool(credited) and owner != previous_owner)
    with transaction(db):
        db.execute(
            "UPDATE ticks SET finished_ns=?,observation=?,owner=?,points=?,transition=? "
            "WHERE round_id=? AND slot=?",
            (finished, reason, owner, credited, transition, round_id, slot),
        )
        db.execute("UPDATE rounds SET last_owner=? WHERE id=?", (owner, round_id))
        if finished >= row["deadline_ns"]:
            close(db, round_id, "deadline")
    return {
        "round_id": round_id, "slot": slot, "observation": reason,
        "owner": owner, "points": credited, "transition": bool(transition),
        "scoring": "sampled_tick_not_continuous_holdtime",
    }


def pause(db: sqlite3.Connection, round_id: str) -> None:
    """Stop sampling, not the original deadline; downtime is never backfilled."""
    row = current_round(db, round_id)
    if row["lifecycle"] == "running":
        if check_clock(db, row):
            with transaction(db):
                db.execute("UPDATE rounds SET lifecycle='paused',last_owner=NULL WHERE id=?", (round_id,))


def status(db: sqlite3.Connection, requested: str | None, active: bool) -> dict:
    """Read one consistent protected result; never contact the guest."""
    with transaction(db, readonly=True):
        metadata = dict(db.execute("SELECT key,value FROM metadata"))
        if metadata.get("schema_version") != "1":
            raise Rejected("private state schema is incomplete or unsupported")
        data = decode(metadata["config"])
        roster = tuple(identifier(p) for p in data["participants"])
        selected = identifier(requested or metadata["current_round"])
        row = db.execute("SELECT * FROM rounds WHERE id=?", (selected,)).fetchone()
        if row is None:
            raise Rejected("requested round not found")
        points = {p: 0 for p in roster}
        for owner, count in db.execute(
            "SELECT owner,SUM(points) FROM ticks WHERE round_id=? AND points=1 GROUP BY owner", (selected,),
        ):
            if owner not in points:
                raise Rejected("score state contains a participant outside its roster")
            points[owner] = count
        last = db.execute(
            "SELECT slot,observation,owner,points FROM ticks WHERE round_id=? ORDER BY slot DESC LIMIT 1",
            (selected,),
        ).fetchone()
        count, credited, transitions = db.execute(
            "SELECT COUNT(*),COALESCE(SUM(points),0),COALESCE(SUM(transition),0) FROM ticks WHERE round_id=?",
            (selected,),
        ).fetchone()
        lifecycle = row["lifecycle"]
        remaining = None
        effective = lifecycle
        if row["start_ns"] is not None and lifecycle in ("running", "paused"):
            if row["boot_id"] != boot_id() or time.monotonic_ns() < row["start_ns"]:
                effective = "clock_invalid"
            else:
                now = time.monotonic_ns()
                remaining = max(0, (row["deadline_ns"] - now) // 1_000_000_000)
                if now >= row["deadline_ns"]:
                    effective = "expired"
        history = [
            {"round_id": r["id"], "lifecycle": r["lifecycle"], "closed_reason": r["closed_reason"]}
            for r in db.execute("SELECT id,lifecycle,closed_reason FROM rounds ORDER BY rowid")
        ]
        resets = [
            {"attempt": r["attempt"], "old_round": r["old_round"], "new_round": r["new_round"],
             "result": r["result"], "command_exit": r["command_exit"]}
            for r in db.execute("SELECT * FROM resets ORDER BY attempt")
        ]
        return {
            "schema_version": 1, "current_round": metadata["current_round"],
            "round_id": selected, "stored_lifecycle": lifecycle, "effective_lifecycle": effective,
            "controller_active": active, "remaining_seconds": remaining,
            "round_seconds": data.get("round_seconds", 900), "tick_seconds": data.get("tick_seconds", 5),
            "points": points, "reserved_ticks": count, "credited_ticks": credited,
            "uncredited_ticks": count - credited, "acquisitions_or_transitions": transitions,
            "latest_sample": dict(last) if last else None,
            "history": history, "resets": resets,
            "scoring": "sampled_tick_not_continuous_holdtime",
            "reset_registered": bool(data["reset_argv"]),
        }
