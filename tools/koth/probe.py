#!/usr/bin/env python3
"""Read-only guest probe, sent to Python over authenticated OpenSSH.

Input is one manager-created JSON object on stdin. Output never includes marker
contents, command output, paths, credentials, or guest timestamps. This is not a
guest scoreboard. It requires Linux, Python 3 and systemd.

Health semantics (active, not application-level readiness):
https://raw.githubusercontent.com/systemd/systemd/v255/man/systemctl.xml
The versioned source is documentation provenance, not a VM package pin.
"""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def main() -> int:
    """Return only bounded structured observations from the contest VM."""
    config = json.loads(sys.stdin.buffer.read(65537))
    machine_id = Path("/etc/machine-id").read_text(encoding="ascii").strip()
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    if machine_id != config["contest_machine_id"]:
        print('{"version":1,"identity":false}')
        return 0
    owner = None
    marker = "failed"
    try:
        fd = os.open(config["marker"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if stat.S_ISREG(info.st_mode) and info.st_size <= 128:
                raw = source.read(129)
                # Exact participant ID, optionally followed by one LF. No trim
                # of arbitrary whitespace and no unknown value in the response.
                if raw.endswith(b"\n"):
                    raw = raw[:-1]
                for index, participant in enumerate(config["participants"]):
                    if raw == participant.encode("ascii"):
                        owner = index
                        break
                marker = "approved" if owner is not None else "unknown"
    except FileNotFoundError:
        marker = "missing"
    except OSError:
        marker = "failed"
    services = []
    for unit in config["services"]:
        try:
            result = subprocess.run(
                ["/usr/bin/systemctl", "is-active", "--quiet", "--", unit],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=0.5, shell=False,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            )
            services.append(result.returncode == 0)
        except (OSError, subprocess.TimeoutExpired):
            services.append(False)
    print(json.dumps({
        "version": 1, "identity": True, "boot_id": boot_id,
        "marker": marker, "owner_index": owner, "services": services,
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        # No traceback containing untrusted guest data.
        sys.exit(1)
