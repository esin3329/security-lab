#!/usr/bin/env python3
"""Validate a completed measurement and append one record to a JSONL file.

Usage: python3 tools/strix/metrics.py --record completed.json --output runs.jsonl
Exit 0: one validated record appended and fsynced. Exit 2: rejected or I/O failed.
No metrics, timestamps, versions, IDs or defaults are generated here.

The schema beside this checkout's benchmarks directory is the policy source.
POSIX flock is required; every writer must use this recorder and the filesystem
must support its locks. Existing rows are never repaired, normalized or removed.
An incomplete tail after process/power loss blocks subsequent writes for review.
"""

import argparse
from datetime import datetime, timedelta
import errno
import json
import math
import os
from pathlib import Path
import stat
import sys


class Rejected(Exception):
    """A safe diagnostic that contains no submitted field values."""


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        # argparse's usual message can echo arbitrary arguments, including keys.
        self.exit(2, "metrics: invalid arguments; use --record JSON --output JSONL\n")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("JSON contains a duplicate object key")
        result[key] = value
    return result


def _finite_float(text):
    number = float(text)
    if not math.isfinite(number):
        raise Rejected("JSON contains a non-finite number")
    return number


def _reject_constant(_text):
    raise Rejected("JSON contains a non-standard numeric constant")


def _load_json(raw, source):
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=_finite_float,
            parse_constant=_reject_constant,
        )
    except Rejected as exc:
        raise Rejected(f"{source}: {exc}") from None
    except (UnicodeError, ValueError, RecursionError):
        raise Rejected(f"{source}: invalid or truncated UTF-8 JSON") from None


def _utc_date_time(value):
    if not isinstance(value, str):
        return True  # The schema's type assertion handles non-strings.
    # fromisoformat accepts UTC Z only on newer Python; normalize it explicitly.
    if not value.endswith(("Z", "+00:00")):
        return False
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    return parsed.utcoffset() == timedelta(0)


def _validator():
    try:
        from jsonschema import Draft7Validator, FormatChecker
    except ImportError:
        raise Rejected("jsonschema is unavailable; see tools/strix/requirements.txt") from None

    schema_path = Path(__file__).resolve().parents[2] / "benchmarks" / "metrics.schema.json"
    schema = _load_json(schema_path.read_bytes(), "metrics schema")
    try:
        Draft7Validator.check_schema(schema)
    except Exception:
        raise Rejected("metrics schema is invalid") from None
    # A base jsonschema installation need not include its optional RFC 3339
    # package. Always install our calendar/UTC check on this validator instance.
    checker = FormatChecker(formats=[])
    checker.checks("date-time", raises=(ValueError, OverflowError))(_utc_date_time)
    return Draft7Validator(schema, format_checker=checker)


def _encode_record(record, validator, source):
    if not validator.is_valid(record):
        raise Rejected(f"{source}: violates metrics.schema.json")
    try:
        # Compact UTF-8 plus one LF; embedded newlines in notes remain escaped.
        return (json.dumps(record, ensure_ascii=False, allow_nan=False,
                           separators=(",", ":")) + "\n").encode("utf-8")
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected(f"{source}: cannot encode an unambiguous JSONL record") from None


def _open_regular(path, flags):
    # Avoid following a final symlink or waiting on a FIFO before fstat.
    descriptor = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise Rejected("record and output must be regular files")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _existing_ids(descriptor, validator):
    seen = set()
    # A duplicate descriptor keeps the lock held on the original descriptor.
    with os.fdopen(os.dup(descriptor), "rb") as existing:
        for line_number, raw in enumerate(existing, 1):
            source = f"existing JSONL line {line_number}"
            if not raw.endswith(b"\n"):
                raise Rejected(f"{source}: missing final LF; log may be truncated")
            record = _load_json(raw, source)
            _encode_record(record, validator, source)
            run_id = record["run_id"]
            if run_id in seen:
                raise Rejected("existing JSONL contains a duplicate run_id")
            seen.add(run_id)
    return seen


def _unchanged_output(path, descriptor, initial):
    current = os.fstat(descriptor)
    named = os.stat(path, follow_symlinks=False)
    if ((current.st_dev, current.st_ino, current.st_size) !=
            (initial.st_dev, initial.st_ino, initial.st_size) or
            (named.st_dev, named.st_ino) != (initial.st_dev, initial.st_ino)):
        raise Rejected("output changed or was replaced during validation")


def _write_record(descriptor, payload, original_size):
    try:
        # One append syscall under the exclusive lock prevents interleaved rows.
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise OSError(errno.EIO, "short append")
        os.fsync(descriptor)
    except (OSError, KeyboardInterrupt):
        # Only undo bytes from this failed append. Never trim an existing row.
        # This is failure recovery, not permission to repair pre-existing logs.
        try:
            size = os.fstat(descriptor).st_size
            if not original_size <= size <= original_size + len(payload):
                raise Rejected("output changed during failed append; review it before reuse")
            if size != original_size:
                os.ftruncate(descriptor, original_size)
                os.fsync(descriptor)
        except OSError:
            raise Rejected("append recovery failed; review output before reuse") from None
        raise Rejected("append failed or was interrupted; prior JSONL bytes retained") from None


def append_record(record_path, output_path):
    try:
        import fcntl
    except ImportError:
        raise Rejected("POSIX file locking is required; use Python on Linux/WSL") from None

    validator = _validator()
    input_descriptor = _open_regular(record_path, os.O_RDONLY)
    with os.fdopen(input_descriptor, "rb") as source:
        record = _load_json(source.read(), "record")
    payload = _encode_record(record, validator, "record")

    # Do not create directories, rewrite existing data or open in truncation mode.
    output_descriptor = _open_regular(output_path, os.O_RDWR | os.O_CREAT | os.O_APPEND)
    try:
        fcntl.flock(output_descriptor, fcntl.LOCK_EX)
        initial = os.fstat(output_descriptor)
        seen = _existing_ids(output_descriptor, validator)
        if record["run_id"] in seen:
            raise Rejected("run_id is already present in the output JSONL")
        _unchanged_output(output_path, output_descriptor, initial)
        _write_record(output_descriptor, payload, initial.st_size)
    finally:
        # fsync is the commit point. A close error must not turn a committed
        # append into exit 2 or mask a prior rejection. The CLI then exits, also
        # releasing any descriptor/lock the OS has not already released.
        try:
            os.close(output_descriptor)
        except OSError:
            pass


def main():
    parser = _ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--record", required=True, type=Path,
                        help="UTF-8 JSON file containing one completed measurement")
    parser.add_argument("--output", required=True, type=Path,
                        help="append-only JSONL file; its parent directory must exist")
    try:
        arguments = parser.parse_args()
        append_record(arguments.record, arguments.output)
    except Rejected as exc:
        print(f"metrics: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        # Filenames and arbitrary exception messages can contain secrets. Report
        # only the errno, never submitted JSON, raw tool output or field values.
        print(f"metrics: file/locking operation failed (errno {exc.errno})", file=sys.stderr)
        return 2
    except (ValueError, RecursionError, KeyboardInterrupt):
        print("metrics: invalid data or operation interrupted", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
