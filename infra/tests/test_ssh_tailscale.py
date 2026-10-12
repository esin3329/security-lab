"""Exercise infra/ssh-tailscale.sh's argv translation against a stub binary."""

import os
from pathlib import Path
import shutil
import stat
import subprocess
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "ssh-tailscale.sh"
BASH = shutil.which("bash")

# The exact argv shape infra/deploy.py's ssh_prefix() + remote_command() build.
DEPLOY_STYLE_ARGV = [
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes",
    "-o", "ConnectTimeout=10",
    "-p", "22",
    "-i", "/home/user/.ssh/id_rsa",
    "-F", "/home/user/.ssh/config",
    "user@<operator-vm-ip>",
    "python3 -c 'print(1)'",
]


class SshTailscaleAdapterTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(self._noop)

    def _noop(self):
        pass

    def _stub_dir(self, record_path):
        """Build a temp dir containing a 'tailscale' stub that records its argv."""
        directory = Path(self.enterContext(
            __import__("tempfile").TemporaryDirectory()))
        stub = directory / "tailscale"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' \"$@\" > " + str(record_path) + "\n"
            "exit 0\n",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        return directory

    def run_adapter(self, argv, env_overrides=None):
        record_path = Path(self.enterContext(
            __import__("tempfile").TemporaryDirectory())) / "argv.txt"
        stub_dir = self._stub_dir(record_path)
        environment = os.environ.copy()
        environment["SECURITY_LAB_TAILSCALE_BIN"] = str(stub_dir / "tailscale")
        if env_overrides:
            environment.update(env_overrides)
        result = subprocess.run(
            [BASH, str(SCRIPT), *argv],
            capture_output=True, env=environment, timeout=10,
        )
        recorded = (record_path.read_text().splitlines()
                    if record_path.exists() else [])
        return result, recorded

    def test_deploy_style_flags_are_stripped_target_and_command_survive(self):
        result, recorded = self.run_adapter(DEPLOY_STYLE_ARGV)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(recorded, ["ssh", "user@<operator-vm-ip>", "python3 -c 'print(1)'"])

    def test_missing_target_is_rejected(self):
        result, recorded = self.run_adapter(["-o", "BatchMode=yes"])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(recorded, [])
        self.assertIn(b"no SSH target", result.stderr)

    def test_unresolved_tailscale_binary_fails_closed(self):
        # A deliberately-missing override, rather than a broken PATH, keeps
        # this deterministic: a real tailscale install (native or the
        # Windows fallback path) on the machine running this test must
        # never be reached, let alone actually invoked against a real VM.
        argv = ["user@<operator-vm-ip>", "echo hi"]
        environment = os.environ.copy()
        environment["SECURITY_LAB_TAILSCALE_BIN"] = "/nonexistent-security-lab-test-binary"
        result = subprocess.run(
            [BASH, str(SCRIPT), *argv],
            capture_output=True, env=environment, timeout=10,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"is set but not executable", result.stderr)


if __name__ == "__main__":
    unittest.main()
