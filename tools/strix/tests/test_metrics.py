"""Consumer-visible JSONL invariants; all measurements here are synthetic."""

import errno
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


RECORDER = Path(__file__).resolve().parents[1] / "metrics.py"
SPEC = importlib.util.spec_from_file_location("security_lab_metrics", RECORDER)
WRITER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WRITER)


def measurement(run_id):
    return {
        "run_id": run_id,
        "timestamp": "2026-10-12T03:00:00Z",
        "tool": "manual",
        "tool_version": "1.0.0",
        "target": {"name": "juice-shop", "host_port": "juice-shop:3000"},
        "time_limit_min": 15,
        "repeat_index": 1,
        "metrics": {
            "tp": 2,
            "fp": 1,
            "poc_success_rate": 0.5,
            "duration_sec": 901.25,
            "token_cost": {"tokens": 1234, "cost_usd": 0.12},
            "human_interventions": {"count": 1, "minutes": 2.5},
            "reproducibility": "부분 재현",
            "explainability": 3,
        },
    }


def encoded(record):
    return (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


@unittest.skipUnless(sys.platform.startswith("linux"), "recorder requires Linux/WSL POSIX locks")
class RecorderInvariantTests(unittest.TestCase):
    def test_concurrent_duplicate_id_commits_exactly_once_without_rewriting_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            destination = folder / "runs.jsonl"
            incoming = folder / "record.json"
            prefix = encoded(measurement("prior-run"))
            record = measurement("concurrent-run")
            destination.write_bytes(prefix)
            incoming.write_bytes(encoded(record))
            command = [sys.executable, str(RECORDER), "--record", str(incoming), "--output", str(destination)]
            first = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            second = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                first_output = first.communicate(timeout=30)
                second_output = second.communicate(timeout=30)
            finally:
                for process in (first, second):
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
            self.assertEqual(sorted((first.returncode, second.returncode)), [0, 2], (first_output, second_output))
            self.assertEqual(destination.read_bytes(), prefix + encoded(record))

    def test_fsync_failure_rolls_back_only_the_uncommitted_append(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            destination = folder / "runs.jsonl"
            incoming = folder / "record.json"
            prefix = encoded(measurement("prior-run"))
            destination.write_bytes(prefix)
            incoming.write_bytes(encoded(measurement("uncommitted-run")))
            real_fsync = WRITER.os.fsync
            failed = False

            def fail_first_fsync(descriptor):
                nonlocal failed
                if not failed:
                    failed = True
                    raise OSError(errno.EIO, "simulated storage failure")
                return real_fsync(descriptor)

            with mock.patch.object(WRITER.os, "fsync", side_effect=fail_first_fsync):
                with self.assertRaises(WRITER.Rejected):
                    WRITER.append_record(incoming, destination)
            self.assertEqual(destination.read_bytes(), prefix)

    def test_truncated_existing_tail_is_rejected_without_repair(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            destination = folder / "runs.jsonl"
            incoming = folder / "record.json"
            damaged = encoded(measurement("prior-run"))[:-1]
            destination.write_bytes(damaged)
            incoming.write_bytes(encoded(measurement("next-run")))
            result = subprocess.run(
                [sys.executable, str(RECORDER), "--record", str(incoming), "--output", str(destination)],
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(destination.read_bytes(), damaged)


if __name__ == "__main__":
    unittest.main()
