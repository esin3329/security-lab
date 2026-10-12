#!/usr/bin/env python3
"""Shared controller primitives for tools/lab: errors, scope policy, state, execution.

Only the Python standard library is used. All child processes are spawned
with argv lists (no shell). Secrets are never printed, logged, or stored in Git.
Runs only on server Ubuntu Linux; WSL/dev-PC environments are refused.
"""

import hashlib
import itertools
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

ALLOW_HOST_PORTS = ("juice-shop:3000", "127.0.0.1:3000", "localhost:3000")
EXECUTABLE_HOST_PORT = "juice-shop:3000"
TIME_LIMIT_MIN = 15
SCAN_TIMEOUT_SEC = 900

EXIT_OK = 0
EXIT_REFUSED = 2
EXIT_PREREQ = 3
EXIT_FAILED = 4
EXIT_TIMEOUT = 10
EXIT_FINDINGS = 12
EXIT_POST = 13

_diag_counter = itertools.count(1)


class Refused(Exception):
    """Scope/usage refusal. Maps to exit 2."""


class Prereq(Exception):
    """Missing prerequisite (fail-closed, precise). Maps to exit 3."""


class Failed(Exception):
    """Action failed; cause preserved without secrets. Maps to exit 4."""


def eprint(message):
    print(message, file=sys.stderr)


def require_server_linux():
    """Admit only server Ubuntu Linux: refuse Windows, macOS, and WSL/dev-PC."""
    if os.name != "posix" or sys.platform != "linux":
        raise Refused("서버 Ubuntu Linux에서만 실행합니다 (현재 플랫폼 거부).")
    try:
        with open("/proc/version", "r", encoding="utf-8", errors="replace") as handle:
            version = handle.read()
        with open("/proc/sys/kernel/osrelease", "r", encoding="utf-8",
                  errors="replace") as handle:
            release = handle.read()
    except OSError:
        raise Refused("Linux 커널 식별 불가로 실행을 거부합니다.")
    blob = (version + " " + release).lower()
    if "microsoft" in blob or "wsl" in blob:
        raise Refused("WSL/개발 PC 환경에서는 실행하지 않습니다 (서버 Ubuntu VM 전용).")


def check_target_url(raw):
    """Validate an http(s) URL against the exact allowlist.

    Returns (scheme, host_port, origin). Raises Refused otherwise.
    """
    if not isinstance(raw, str) or raw == "":
        raise Refused("target URL이 비어 있습니다.")
    if re.search(r"\s|[\x00-\x1f\x7f]", raw) or "\\" in raw:
        raise Refused("URL의 공백/제어 문자/backslash는 지원하지 않습니다.")
    try:
        parts = urllib.parse.urlsplit(raw)
        if parts.scheme not in ("http", "https"):
            raise Refused("http/https 스킴만 허용됩니다.")
        if not parts.hostname:
            raise Refused("호스트가 없습니다.")
        if "@" in parts.netloc:
            raise Refused("userinfo가 있는 URL은 허용하지 않습니다.")
        if parts.fragment:
            raise Refused("fragment가 있는 URL은 허용하지 않습니다.")
        host = parts.hostname.lower()
        try:
            port = parts.port
        except ValueError:
            raise Refused("포트 형식이 아닙니다.")
        if port is None:
            port = 443 if parts.scheme == "https" else 80
    except Refused:
        raise
    except Exception:
        raise Refused("URL 형식이 아닙니다.")
    host_port = "%s:%d" % (host, port)
    if host_port not in ALLOW_HOST_PORTS:
        raise Refused("allowlist에 없는 host:port입니다: %s" % host_port)
    return parts.scheme, host_port, "%s://%s" % (parts.scheme, host_port)


_FORBIDDEN_PREFIXES = ("/proc", "/sys", "/dev")


def check_artifact(raw_path):
    """Validate an authorized local artifact path. Returns the resolved path."""
    if not isinstance(raw_path, str) or raw_path == "":
        raise Refused("artifact 경로가 비어 있습니다.")
    if "\x00" in raw_path:
        raise Refused("경로에 NUL 문자가 있습니다.")
    absolute = os.path.abspath(raw_path)
    if not os.path.exists(absolute):
        raise Refused("artifact 경로가 존재하지 않습니다: %s" % absolute)
    resolved = os.path.realpath(absolute)
    for prefix in _FORBIDDEN_PREFIXES:
        if resolved == prefix or resolved.startswith(prefix + os.sep):
            raise Refused("가상/장치 경로(%s)는 허용하지 않습니다." % prefix)
    return resolved


def checkout_root():
    """Absolute path of the checkout containing tools/lab."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(os.path.dirname(here))


def _enforce_owned_dir(path):
    try:
        st = os.stat(path)
    except OSError as exc:
        raise Failed("state dir 확인 실패 (errno %s)" % exc.errno)
    if not stat.S_ISDIR(st.st_mode):
        raise Failed("state 경로가 디렉터리가 아닙니다: %s" % path)
    if st.st_uid != os.getuid():
        raise Failed("state dir 소유자가 현재 사용자가 아닙니다: %s" % path)
    if stat.S_IMODE(st.st_mode) != 0o700:
        try:
            os.chmod(path, 0o700)
            st = os.stat(path)
        except OSError as exc:
            raise Failed("state dir 권한 강제 실패 (errno %s)" % exc.errno)
        if stat.S_IMODE(st.st_mode) != 0o700:
            raise Failed("state dir 0700 강제 실패: %s" % path)


def _inside_git(path):
    """True when path sits under any Git checkout (worktrees included)."""
    current = os.path.realpath(path)
    while True:
        marker = os.path.join(current, ".git")
        try:
            if os.path.isdir(marker) or os.path.isfile(marker):
                return True
        except OSError:
            return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def state_root(explicit=None):
    """Private operator state dir on the server VM, enforced 0700 + owned.

    Refuses any Git-backed path (origin and every other checkout included),
    symlinked finals, and non-absolute paths. Never in Git.
    """
    base = explicit or os.environ.get("SECURITY_LAB_STATE") or os.path.join(
        os.path.expanduser("~"), ".security-lab")
    if not isinstance(base, str) or not os.path.isabs(base):
        raise Refused("state dir는 절대 경로여야 합니다.")
    if os.path.islink(base):
        raise Refused("state dir 심볼릭 링크는 허용하지 않습니다.")
    if _inside_git(base):
        raise Refused("state dir는 Git 관리 경로 밖이어야 합니다 (원본·다른 checkout 포함).")
    try:
        os.makedirs(base, mode=0o700, exist_ok=True)
    except OSError as exc:
        raise Failed("state dir 생성 실패 (errno %s)" % exc.errno)
    if os.path.islink(base):
        raise Failed("state dir 심볼릭 링크 감지")
    _enforce_owned_dir(base)
    return base


def tool_state(root, tool):
    path = os.path.join(root, tool)
    if os.path.islink(path):
        raise Failed("tool state 심볼릭 링크 감지: %s" % tool)
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
    except OSError as exc:
        raise Failed("tool state dir 생성 실패 (errno %s)" % exc.errno)
    if os.path.islink(path):
        raise Failed("tool state 심볼릭 링크 감지: %s" % tool)
    _enforce_owned_dir(path)
    return path


def write_private_file(path, data):
    """Write bytes with enforced 0600, no symlink following, no overwrite."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise Failed("이미 존재하는 파일을 덮어쓰지 않습니다: %s" % path)
    except OSError as exc:
        raise Failed("파일을 만들 수 없습니다: %s (errno %s)" % (path, exc.errno))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() \
                or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1:
            raise Failed("private 파일 소유/권한 검증 실패: %s" % path)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Failed:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    except OSError as exc:
        try:
            os.close(fd)
        except OSError:
            pass
        raise Failed("파일 쓰기 실패: %s (errno %s)" % (path, exc.errno))


def write_receipt(path, obj):
    """Write a secret-free JSON receipt; refuse to overwrite."""
    payload = (json.dumps(obj, ensure_ascii=False, indent=2,
                          sort_keys=True) + "\n").encode("utf-8")
    write_private_file(path, payload)


def which(name):
    return shutil.which(name)


def _write_diag(diag_dir, tag, name, data):
    if diag_dir is None:
        return None
    try:
        os.makedirs(diag_dir, mode=0o700, exist_ok=True)
    except OSError:
        return None
    path = os.path.join(diag_dir, "%s.%d.%d.%s" % (
        tag, os.getpid(), next(_diag_counter), name))
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except OSError:
        return None
    return path


def run_capture(argv, timeout=30, env=None, cwd=None, out_limit=1 << 20,
                diag_dir=None, diag_tag="cmd"):
    """Run argv (list only) with bounded capture and private diagnostics.

    Returns dict(exit, out, err, timed_out, truncated, diag_out, diag_err).
    Bounded: in-memory bytes are capped at out_limit. Full outputs are also
    written to 0600 diag files when diag_dir is set; failure messages carry
    the category/exit/diag path, never raw content. Raises Failed on spawn
    errors.
    """
    if not isinstance(argv, (list, tuple)) or not argv:
        raise Failed("내부 오류: 빈 argv")
    child_env = None
    if env is not None:
        child_env = dict(os.environ)
        child_env.update(env)
    try:
        proc = subprocess.Popen(
            list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, cwd=cwd, env=child_env,
            start_new_session=True)
    except FileNotFoundError:
        raise Failed("실행 파일을 찾을 수 없습니다: %s" % argv[0])
    except (OSError, ValueError):
        raise Failed("프로세스를 시작하지 못했습니다: %s" % argv[0])
    try:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            out, err = proc.communicate()
            diag_out = _write_diag(diag_dir, diag_tag, "stdout.log", out[:out_limit])
            diag_err = _write_diag(diag_dir, diag_tag, "stderr.log", err[:out_limit])
            return {"exit": -1, "out": b"", "err": b"",
                    "timed_out": True, "truncated": True,
                    "diag_out": diag_out, "diag_err": diag_err}
    finally:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            proc.wait()
    truncated = False
    if len(out) > out_limit:
        out = out[:out_limit]
        truncated = True
    if len(err) > out_limit:
        err = err[:out_limit]
        truncated = True
    diag_out = _write_diag(diag_dir, diag_tag, "stdout.log", out)
    diag_err = _write_diag(diag_dir, diag_tag, "stderr.log", err)
    return {"exit": proc.returncode, "out": out, "err": err,
            "timed_out": False, "truncated": truncated,
            "diag_out": diag_out, "diag_err": diag_err}


def docker_endpoint():
    """Local Unix-socket Docker endpoint only. Refuses remote/TCP endpoints."""
    raw = os.environ.get("DOCKER_HOST") or "unix:///var/run/docker.sock"
    if not re.fullmatch(r"unix:///[A-Za-z0-9._/\-]+", raw):
        raise Refused("로컬 Unix-socket Docker endpoint만 지원합니다.")
    return raw


def docker_base():
    """argv prefix pinning the CLI to the local endpoint; drops context overrides."""
    return ["docker", "--host", docker_endpoint()]


def docker_json(argv, timeout=30):
    """Run a docker metadata command and parse stdout JSON. Raises Failed."""
    result = run_capture(docker_base() + list(argv), timeout=timeout)
    if result["timed_out"]:
        raise Failed("Docker metadata 명령 시간 초과")
    if result["exit"] != 0:
        raise Failed("Docker metadata 명령 실패 (exit %d)" % result["exit"])
    try:
        return json.loads(result["out"].decode("utf-8"))
    except (UnicodeError, ValueError):
        raise Failed("Docker metadata가 유효한 JSON이 아닙니다.")


def assert_exact_image(ref, digests, what):
    """Enforce an exact registry-pinned image. Returns (image_id, arch).

    digests: {"index": sha256, "amd64": {"manifest","config"}, ...}.
    Tag refs additionally require the tag locally; digest refs
    (name@sha256:...) match RepoDigests instead (untagged pulls have no
    RepoTags). Any mismatch refuses (no pull, no trust-on-first-use).
    """
    data = docker_json(["image", "inspect", ref])
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise Failed("%s image inspect 형식이 예상과 다릅니다." % what)
    info = data[0]
    arch = info.get("Architecture")
    if arch not in ("amd64", "arm64") or arch not in digests:
        raise Failed("%s 아키텍처(%s) pin이 없습니다." % (what, arch))
    want = digests[arch]
    if info.get("Id") != want["config"]:
        raise Failed("%s 이미지 ID가 pin과 다릅니다 (exact mismatch)." % what)
    if "@sha256:" in ref:
        repo = ref.split("@")[0]
        if repo + "@" + digests["index"] not in (info.get("RepoDigests") or []):
            raise Failed("%s index digest가 pin과 다릅니다." % what)
    else:
        if digests.get("index") not in (info.get("RepoDigests") or []):
            raise Failed("%s index digest가 pin과 다릅니다." % what)
        if ref not in (info.get("RepoTags") or []):
            raise Failed("%s 태그가 로컬에 없습니다: %s" % (what, ref))
    return info["Id"], arch


def download_to(url, dest_path, sha256_hex, timeout=300):
    """Download an official release asset and verify its sha256. Raises Failed."""
    expected = sha256_hex.lower() if isinstance(sha256_hex, str) else ""
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise Failed("내부 오류: pin된 sha256 형식이 아닙니다.")
    try:
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="lab-download-")
    except Exception:
        raise Failed("임시 파일을 만들 수 없습니다.")
    digest = hashlib.sha256()
    try:
        with os.fdopen(tmp_fd, "wb") as handle:
            try:
                with urllib.request.urlopen(url, timeout=timeout) as response:
                    while True:
                        chunk = response.read(1 << 20)
                        if not chunk:
                            break
                        digest.update(chunk)
                        handle.write(chunk)
            except Exception:
                raise Failed("공식 asset 다운로드 실패: %s" % url)
        if digest.hexdigest() != expected:
            raise Failed("sha256 불일치: %s" % url)
        try:
            os.replace(tmp_path, dest_path)
        except OSError as exc:
            raise Failed("파일 이동 실패 (errno %s)" % exc.errno)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
