"""Bounded real OpenSSH transport and safe guest observation parsing.

Official option contract: https://man.openbsd.org/ssh_config
Official client contract: https://man.openbsd.org/ssh
No installer, public target default, credential discovery, or fixture fallback.
"""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import subprocess
import time

from state import Config, Rejected, decode, private_file


@dataclass(frozen=True, slots=True)
class ProcessResult:
    exit_code: int | None
    output: bytes
    failure: str | None


def execute(
    argv: tuple[str, ...] | list[str], timeout: float,
    payload: bytes = b"", limit: int = 8192,
    capture: bool = True, env: dict[str, str] | None = None,
    capture_stderr: bool = False,
) -> ProcessResult:
    """Bound I/O and lifetime; stderr is discarded except local client metadata."""
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE if capture and not capture_stderr else subprocess.DEVNULL,
            stderr=subprocess.PIPE if capture_stderr else subprocess.DEVNULL,
            shell=False, start_new_session=True,
            env=env,
        )
    except OSError:
        return ProcessResult(None, b"", "spawn_failed")
    try:
        output = bytearray()
        sent = 0
        with selectors.DefaultSelector() as selector:
            if process.stdin is None:
                raise Rejected("transport stdin unavailable", 3)
            os.set_blocking(process.stdin.fileno(), False)
            if payload:
                selector.register(process.stdin, selectors.EVENT_WRITE, "input")
            else:
                process.stdin.close()
            stream = process.stderr if capture_stderr else process.stdout
            if stream is not None:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, "output")
            while selector.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return ProcessResult(None, b"", "timeout")
                for key, _ in selector.select(min(remaining, 0.2)):
                    if key.data == "input":
                        try:
                            sent += os.write(key.fd, payload[sent:sent + 4096])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            selector.unregister(key.fileobj)
                            process.stdin.close()
                            continue
                        if sent == len(payload):
                            selector.unregister(key.fileobj)
                            process.stdin.close()
                    else:
                        try:
                            chunk = os.read(key.fd, 4096)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            output.extend(chunk)
                            if len(output) > limit:
                                return ProcessResult(None, b"", "oversized_output")
        return ProcessResult(process.wait(), bytes(output), None)
    finally:
        # Also executes on SIGINT, SIGTERM handled as an interruption, or parser
        # exceptions. Kill the complete local command group, not just a wrapper.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        if process.stdin is not None:
            process.stdin.close()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


@dataclass(frozen=True, slots=True)
class Observation:
    reason: str
    owner: str | None = None
    boot_id: str | None = None
    healthy: bool = False
    identity: bool = False


def observe(config: Config) -> Observation:
    """Read the exact approved server VM; no raw remote value is published."""
    deadline = time.monotonic() + config.probe_timeout
    for path in (config.identity_file, config.known_hosts):
        private_file(Path(path))
    # OpenSSH -V writes stderr. Check it privately, with a strict bounded timeout;
    # this metadata is neither guest output nor a credential.
    version = execute(
        [config.client, "-V"], config.probe_timeout, limit=1024,
        capture_stderr=True, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
    )
    if version.failure:
        return Observation("client_unavailable")
    if version.exit_code != 0 or not re.match(rb"OpenSSH_[0-9]+\.[0-9]+", version.output):
        return Observation("client_not_openssh")
    probe = Path(__file__).with_name("probe.py").read_text(encoding="utf-8")
    command = shlex.join([config.remote_python, "-I", "-S", "-c", probe])
    argv = [
        config.client, "-F", "/dev/null", "-T", "-p", str(config.port),
        "-l", config.user, "-i", config.identity_file,
    ]
    options = {
        "BatchMode": "yes", "StrictHostKeyChecking": "yes",
        "UserKnownHostsFile": '"' + config.known_hosts + '"',
        "GlobalKnownHostsFile": "/dev/null", "UpdateHostKeys": "no",
        "IdentitiesOnly": "yes", "IdentityAgent": "none", "ForwardAgent": "no",
        "ClearAllForwardings": "yes", "ForwardX11": "no", "PermitLocalCommand": "no",
        "ProxyCommand": "none", "ProxyJump": "none", "ControlMaster": "no",
        "ControlPath": "none", "ConnectionAttempts": "1",
        "ConnectTimeout": str(config.probe_timeout),
        "ServerAliveInterval": "1", "ServerAliveCountMax": "1", "LogLevel": "ERROR",
        "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no",
        "PreferredAuthentications": "publickey",
    }
    for key, value in options.items():
        argv.extend(["-o", key + "=" + value])
    argv.extend(["--", config.host, command])
    payload = json.dumps({
        "participants": config.participants, "marker": config.marker,
        "services": config.services, "contest_machine_id": config.contest_machine_id,
    }, separators=(",", ":")).encode("utf-8")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return Observation("timeout")
    result = execute(
        argv, remaining, payload,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
    )
    if result.failure:
        return Observation(result.failure)
    if result.exit_code != 0:
        return Observation("ssh_failed")
    try:
        data = decode(result.output)
    except Rejected:
        return Observation("invalid_probe")
    if type(data.get("version")) is not int or data["version"] != 1:
        return Observation("invalid_probe")
    if data.get("identity") is False and set(data) == {"version", "identity"}:
        return Observation("identity_mismatch")
    if set(data) != {"version", "identity", "boot_id", "marker", "owner_index", "services"}:
        return Observation("invalid_probe")
    boot, marker, index, services = (
        data["boot_id"], data["marker"], data["owner_index"], data["services"],
    )
    if (data["identity"] is not True or not isinstance(boot, str)
            or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot)
            or marker not in ("approved", "missing", "unknown", "failed")
            or not isinstance(services, list) or len(services) != len(config.services)
            or any(type(item) is not bool for item in services)):
        return Observation("invalid_probe")
    healthy = all(services)
    if marker == "approved":
        if type(index) is not int or not 0 <= index < len(config.participants):
            return Observation("invalid_probe")
        return Observation(
            "approved" if healthy else "unhealthy",
            config.participants[index] if healthy else None, boot, healthy, True,
        )
    if index is not None:
        return Observation("invalid_probe")
    return Observation(marker, None, boot, healthy, True)
