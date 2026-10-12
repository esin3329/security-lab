"""Exercise the real receiver's ownership and atomic activation boundaries."""

import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "deploy.py"
SPEC = importlib.util.spec_from_file_location("security_lab_deploy", SOURCE)
DEPLOY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEPLOY)


def archive_for(path="tools/example.txt", content=b"first release", recorded_digest=None):
    buffer = io.BytesIO()
    manifest = {
        "project": "security-lab",
        "files": [{"path": path, "size": len(content),
                   "sha256": recorded_digest or hashlib.sha256(content).hexdigest(),
                   "executable": False}],
    }
    with tarfile.open(fileobj=buffer, mode="w:") as archive:
        info = tarfile.TarInfo(path)
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
        encoded = json.dumps(manifest).encode("utf-8")
        info = tarfile.TarInfo(".security-lab-manifest.json")
        info.size = len(encoded)
        archive.addfile(info, io.BytesIO(encoded))
    return buffer.getvalue()


@unittest.skipUnless(sys.platform.startswith("linux"), "Ubuntu receiver filesystem semantics")
class DeploymentBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.destination = self.home / "app"

    def receive(self, payload):
        request = {"sha256": hashlib.sha256(payload).hexdigest(),
                   "remote_dir": str(self.destination)}
        encoded = base64.urlsafe_b64encode(json.dumps(request).encode()).decode("ascii")
        environment = os.environ.copy()
        environment["HOME"] = str(self.home)
        return subprocess.run(
            [sys.executable, "-c", DEPLOY.REMOTE_RECEIVE, encoded],
            input=payload, capture_output=True, env=environment, timeout=30,
        )

    def activate_first(self):
        result = self.receive(archive_for())
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertFalse(receipt["services_started"])
        self.assertEqual((self.destination / "current").resolve(), Path(receipt["release"]))
        return (self.destination / "current").resolve()

    def test_corrupt_file_cannot_replace_the_active_release(self):
        active = self.activate_first()
        bad = archive_for(content=b"tampered release", recorded_digest=hashlib.sha256(b"expected").hexdigest())
        result = self.receive(bad)
        self.assertEqual(result.returncode, 2)
        self.assertEqual((self.destination / "current").resolve(), active)
        self.assertEqual((active / "tools/example.txt").read_bytes(), b"first release")

    def test_archive_traversal_cannot_write_outside_release_or_activate(self):
        active = self.activate_first()
        result = self.receive(archive_for(path="../escaped.txt", content=b"untrusted"))
        self.assertEqual(result.returncode, 2)
        self.assertEqual((self.destination / "current").resolve(), active)
        self.assertFalse((self.destination / "releases/escaped.txt").exists())
        self.assertFalse((self.home / "escaped.txt").exists())

    def test_unmanaged_destination_is_not_overwritten(self):
        self.destination.mkdir()
        user_file = self.destination / "user-data.txt"
        user_file.write_bytes(b"unrelated user data")
        result = self.receive(archive_for())
        self.assertEqual(result.returncode, 2)
        self.assertEqual(user_file.read_bytes(), b"unrelated user data")
        self.assertFalse((self.destination / "current").exists())

    def test_destination_symlink_cannot_redirect_deployment(self):
        outside = self.home / "unrelated"
        outside.mkdir()
        user_file = outside / "user-data.txt"
        user_file.write_bytes(b"unrelated user data")
        self.destination.symlink_to(outside, target_is_directory=True)
        result = self.receive(archive_for())
        self.assertEqual(result.returncode, 2)
        self.assertEqual(user_file.read_bytes(), b"unrelated user data")
        self.assertFalse((outside / "releases").exists())


if __name__ == "__main__":
    unittest.main()
