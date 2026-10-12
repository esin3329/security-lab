#!/usr/bin/env python3
"""REA (rea-agents@6.4.0, MIT) installer/doctor/launcher.

Pinned source: https://github.com/morluto/rea (release rea-agents-6.4.0).
Verified CLI: `analyze-javascript-application <dir> --json`,
`analyze <bin> --provider <id> --json`, `providers --json`,
`doctor [--provider <id>] --json`, `--help`. Exits: 0 / 1 / 128+N.

Install never touches global npm state or managed external files: the
official tarball is sha512-verified into private state, dependencies come
from the pinned commit lockfile, and the launcher + MCP use the installed
absolute node/script paths (no npx re-resolve). Native deep analysis uses a
pinned Ghidra 12.1.4 install; Hopper/IDA stay explicit prerequisites
(proprietary licenses, installed by the operator).
"""

import json
import os
import re
import shutil
import subprocess
import time

from . import common

TOOL = "rea"
VERSION = "6.4.0"
COMMIT = "a56f7bb668ab23fec8d33f7af353ac7ed2fe1895"
TARBALL_URL = "https://registry.npmjs.org/rea-agents/-/rea-agents-6.4.0.tgz"
TARBALL_SHA512 = ("Vj1zWfSlna5bphGoaoI/TcVBuYvze9u+OyPC3Shz8YkBqaCTqB4COnnRoX7XDwM"
                  "pwI24ZlFEel2yEj0k8LTWEQ==")
LOCK_URL = ("https://raw.githubusercontent.com/morluto/rea/"
            "a56f7bb668ab23fec8d33f7af353ac7ed2fe1895/package-lock.json")

GHIDRA_VERSION = "12.1.4"
GHIDRA_ZIP_URL = ("https://github.com/NationalSecurityAgency/ghidra/releases/download/"
                  "Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip")
GHIDRA_ZIP_SHA256 = "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"


def _node():
    found = common.which("node")
    if found is None:
        raise common.Prereq("node 실행 파일이 없습니다 (engines: ^22.19.0 || ^24.11.0 || >=26.0.0).")
    try:
        real = os.path.realpath(found)
    except OSError:
        raise common.Prereq("node 경로를 확인할 수 없습니다.")
    result = common.run_capture([real, "--version"], timeout=30)
    if result["timed_out"] or result["exit"] != 0:
        raise common.Prereq("node 버전을 확인하지 못했습니다.")
    text = result["out"].decode("utf-8", "replace").strip()
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+).*", text)
    if not match:
        raise common.Prereq("node 버전 형식을 확인할 수 없습니다.")
    major, minor = int(match.group(1)), int(match.group(2))
    if not ((major == 22 and minor >= 19) or (major == 24 and minor >= 11)
            or major >= 26):
        raise common.Prereq(
            "node %s은(는) REA engines(^22.19.0 || ^24.11.0 || >=26.0.0)를 만족하지 않습니다."
            % text)
    if common.which("npm") is None:
        raise common.Prereq("npm 실행 파일이 없습니다.")
    return real, text


def _pkg_paths(state_tool):
    pkg = os.path.join(state_tool, "pkg")
    return pkg, os.path.join(pkg, "package.json"), os.path.join(pkg, "scripts", "rea.mjs")


def _installed_version(pkg_json):
    try:
        with open(pkg_json, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    version = data.get("version")
    name = data.get("name")
    if name != "rea-agents" or not isinstance(version, str):
        return None
    return version


def _script(state_tool):
    _, _, script = _pkg_paths(state_tool)
    if not (os.path.isfile(script) and os.access(script, os.R_OK)):
        raise common.Prereq("REA 설치물이 없습니다. 먼저 install을 실행하십시오.")
    return script


def _diag(state_tool):
    path = os.path.join(state_tool, "diagnostics")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def install(ctx):
    """Private-prefix install: sha512 tarball verify + lock install, no globals."""
    node_abs, node_version = _node()
    pkg, pkg_json, script = _pkg_paths(ctx.state_tool)
    if os.path.exists(pkg):
        raise common.Failed("기존 REA state 패키지가 있습니다. 삭제는 운영자가 직접 수행하십시오.")
    os.makedirs(pkg, mode=0o700, exist_ok=True)
    import base64
    import hashlib
    import tarfile
    import tempfile
    import urllib.request
    tmpdir = tempfile.mkdtemp(prefix="rea-pkg-")
    try:
        archive = os.path.join(tmpdir, "rea-agents.tgz")
        try:
            with urllib.request.urlopen(TARBALL_URL, timeout=300) as response:
                digest = hashlib.sha512()
                with open(archive, "wb") as handle:
                    while True:
                        chunk = response.read(1 << 20)
                        if not chunk:
                            break
                        digest.update(chunk)
                        handle.write(chunk)
        except Exception:
            raise common.Failed("공식 npm tarball 다운로드 실패")
        if digest.digest() != base64.b64decode(TARBALL_SHA512):
            raise common.Failed("npm tarball sha512 불일치")
        try:
            with tarfile.open(archive, "r:gz") as tar:
                top = {name.split("/")[0] for name in tar.getnames() if "/" in name}
                if top != {"package"}:
                    raise common.Failed("tarball 최상위 구조가 예상과 다릅니다.")
                tar.extractall(path=tmpdir)
        except (tarfile.TarError, OSError, EOFError):
            raise common.Failed("tarball 압축 해제 실패")
        extracted = os.path.join(tmpdir, "package")
        for name in os.listdir(extracted):
            src, dst = os.path.join(extracted, name), os.path.join(pkg, name)
            if os.path.isdir(src) and not os.path.islink(src):
                shutil.copytree(src, dst, symlinks=True)
            else:
                shutil.copy2(src, dst)
        lock_dst = os.path.join(pkg, "package-lock.json")
        if os.path.exists(lock_dst):
            raise common.Failed("tarball에 예상 밖 lock이 있습니다.")
        lock_sha = _fetch_lock(LOCK_URL, lock_dst)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    if _installed_version(pkg_json) != VERSION:
        raise common.Failed("설치된 rea-agents 버전이 pin(%s)과 다릅니다." % VERSION)
    if not os.path.isfile(script):
        raise common.Failed("REA 진입 스크립트가 없습니다: scripts/rea.mjs")
    result = common.run_capture(
        ["npm", "ci", "--prefix", pkg, "--no-audit", "--no-fund"],
        timeout=1800, diag_dir=_diag(ctx.state_tool), diag_tag="npm-ci")
    if result["timed_out"]:
        raise common.Failed("npm ci 시간 초과 (diag: %s)" % result["diag_err"])
    if result["exit"] != 0:
        raise common.Failed("npm ci 실패 (exit %d, diag: %s)"
                            % (result["exit"], result["diag_err"]))
    if _installed_version(pkg_json) != VERSION:
        raise common.Failed("lock 설치 후 버전이 pin과 다릅니다.")
    snippet_path = os.path.join(ctx.state_tool, "mcp.json")
    try:
        if os.path.exists(snippet_path):
            os.remove(snippet_path)
    except OSError as exc:
        raise common.Failed("기존 MCP snippet 교체 실패 (errno %s)" % exc.errno)
    common.write_receipt(snippet_path, {"mcpServers": {"rea": {
        "command": node_abs, "args": [script, "mcp"]}}})
    if ctx.with_ghidra:
        _install_ghidra(ctx)
    receipt = {
        "tool": TOOL, "action": "install", "version": VERSION,
        "commit": COMMIT, "node": node_version, "node_abs": node_abs,
        "package": pkg, "script": script, "ghidra": bool(ctx.with_ghidra),
        "lock_observed_sha256": lock_sha,
        "mcp_snippet": snippet_path,
        "note": "MCP 등록은 운영자가 에이전트 설정에 위 JSON을 직접 붙여넣어 수행합니다.",
    }
    common.write_receipt(os.path.join(ctx.state_tool, "install-receipt.json"), receipt)
    print("REA %s 설치 확인. MCP snippet: %s" % (VERSION, snippet_path))
    return common.EXIT_OK


def _fetch_lock(url, dest):
    """Fetch the lockfile from the pinned commit; return observed sha256.

    The lock has no separately published checksum upstream. Integrity of the
    dependency tree is enforced by npm ci against this exact file, and its
    observed digest is stored in the install receipt for review.
    """
    import hashlib
    import urllib.request
    digest = hashlib.sha256()
    try:
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise common.Failed("lockfile이 이미 존재합니다.")
    except OSError as exc:
        raise common.Failed("lockfile 생성 실패 (errno %s)" % exc.errno)
    try:
        with os.fdopen(fd, "wb") as handle:
            try:
                with urllib.request.urlopen(url, timeout=120) as response:
                    while True:
                        chunk = response.read(1 << 20)
                        if not chunk:
                            break
                        digest.update(chunk)
                        handle.write(chunk)
            except Exception:
                raise common.Failed("pin된 lockfile 다운로드 실패")
    except common.Failed:
        try:
            os.remove(dest)
        except OSError:
            pass
        raise
    except OSError as exc:
        try:
            os.remove(dest)
        except OSError:
            pass
        raise common.Failed("lockfile 저장 실패 (errno %s)" % exc.errno)
    return digest.hexdigest()


def _install_ghidra(ctx):
    """Pinned Ghidra 12.1.4 into private state + JDK prerequisite gate."""
    java = common.which("java")
    javac = common.which("javac")
    if java is None or javac is None:
        raise common.Prereq("64-bit full JDK 21+이 필요합니다 (java/javac 없음).")
    result = common.run_capture([java, "-version"], timeout=30)
    text = (result["out"] + result["err"]).decode("utf-8", "replace")
    major = None
    match = re.search(r'version "(\d+)', text)
    if match:
        major = int(match.group(1))
    if "64-bit" not in text.lower():
        raise common.Prereq("64-bit JDK가 아닙니다.")
    if major is None or major < 21:
        raise common.Prereq("JDK 21+ major를 확인하지 못했습니다.")
    home = os.path.join(ctx.state_tool, "ghidra")
    if os.path.exists(home):
        raise common.Failed("기존 Ghidra state가 있습니다. 삭제는 운영자가 직접 수행하십시오.")
    os.makedirs(home, mode=0o700, exist_ok=True)
    archive = os.path.join(home, "ghidra.zip")
    common.download_to(GHIDRA_ZIP_URL, archive, GHIDRA_ZIP_SHA256)
    import zipfile
    try:
        with zipfile.ZipFile(archive) as zf:
            tops = {name.split("/")[0] for name in zf.namelist() if "/" in name}
            if len(tops) != 1:
                raise common.Failed("Ghidra zip 최상위 구조가 예상과 다릅니다.")
            zf.extractall(path=home)
    except (zipfile.BadZipFile, OSError):
        raise common.Failed("Ghidra 압축 해제 실패")
    try:
        os.remove(archive)
    except OSError:
        pass
    found = [name for name in os.listdir(home)
             if name.startswith("ghidra_") and os.path.isdir(os.path.join(home, name))]
    if len(found) != 1 or GHIDRA_VERSION not in found[0]:
        raise common.Failed("Ghidra 설치 dir를 확인하지 못했습니다.")
    ghidra_dir = os.path.join(home, found[0])
    receipt = {
        "tool": TOOL, "provider": "ghidra", "version": GHIDRA_VERSION,
        "dir": ghidra_dir, "zip_sha256": GHIDRA_ZIP_SHA256,
        "env": {"GHIDRA_INSTALL_DIR": ghidra_dir},
    }
    common.write_receipt(os.path.join(ctx.state_tool, "ghidra-receipt.json"), receipt)
    print("Ghidra %s 설치 확인: %s" % (GHIDRA_VERSION, ghidra_dir))


def _ghidra_dir(ctx):
    path = os.path.join(ctx.state_tool, "ghidra")
    if not os.path.isdir(path):
        return None
    for name in os.listdir(path):
        full = os.path.join(path, name)
        if name.startswith("ghidra_") and os.path.isdir(full):
            return full
    return None


def doctor(ctx):
    """Readiness: node/npm engines, pinned package, rea doctor, provider gates."""
    node_abs, node_version = _node()
    script = _script(ctx.state_tool)
    if _installed_version(os.path.join(ctx.state_tool, "pkg", "package.json")) != VERSION:
        raise common.Prereq("rea-agents pin(%s)이 설치되어 있지 않습니다." % VERSION)
    argv = [node_abs, script, "doctor", "--json"]
    env = dict(os.environ)
    ghidra = _ghidra_dir(ctx.state_tool)
    if ctx.provider == "ghidra":
        if ghidra is None:
            raise common.Prereq("Ghidra가 설치되어 있지 않습니다 (--with-ghidra install 필요).")
        env["GHIDRA_INSTALL_DIR"] = ghidra
        argv = [node_abs, script, "doctor", "--provider", "ghidra", "--json"]
    elif ctx.provider in ("hopper", "ida"):
        raise common.Prereq(
            "hopper/ida는 proprietary 라이선스로 운영자가 직접 설치·설정해야 합니다.")
    elif ctx.provider is not None:
        raise common.Refused("알 수 없는 provider입니다: %s" % ctx.provider)
    result = common.run_capture(argv, timeout=300, env=env,
                                diag_dir=_diag(ctx.state_tool), diag_tag="doctor")
    out_path = os.path.join(ctx.state_tool, "doctor-output.json")
    try:
        if os.path.exists(out_path):
            os.remove(out_path)
    except OSError as exc:
        raise common.Failed("기존 doctor 출력 교체 실패 (errno %s)" % exc.errno)
    with open(out_path, "wb") as handle:
        handle.write(result["out"][: 1 << 20])
    try:
        os.chmod(out_path, 0o600)
    except OSError:
        pass
    if result["timed_out"]:
        raise common.Prereq("rea doctor 시간 초과 (diag: %s)" % result["diag_err"])
    if result["exit"] == 1:
        raise common.Prereq("rea doctor 필수 검사 실패 (출력: %s)" % out_path)
    if result["exit"] != 0:
        raise common.Failed("rea doctor 실패 (exit %d, diag: %s)"
                            % (result["exit"], result["diag_err"]))
    print("REA ready (rea-agents %s, node %s). doctor 출력: %s"
          % (VERSION, node_version, out_path))
    return common.EXIT_OK


def _spawn_evidence(argv, ctx, label):
    evidence_path = os.path.join(ctx.state_tool, "evidence-%s.json" % label)
    err_path = os.path.join(ctx.state_tool, "evidence-%s.stderr.log" % label)
    for existing in (evidence_path, err_path):
        try:
            if os.path.exists(existing):
                os.remove(existing)
        except OSError as exc:
            raise common.Failed("기존 evidence 교체 실패 (errno %s)" % exc.errno)
    out_fd = os.open(evidence_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600)
    err_fd = os.open(err_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600)
    try:
        with open(os.devnull, "rb") as null_in:
            with os.fdopen(out_fd, "wb") as out_handle:
                with os.fdopen(err_fd, "wb") as err_handle:
                    proc = subprocess.Popen(
                        argv, stdin=null_in, stdout=out_handle,
                        stderr=err_handle, start_new_session=True)
    except FileNotFoundError:
        raise common.Failed("실행 파일을 찾을 수 없습니다: %s" % argv[0])
    except OSError:
        raise common.Failed("REA를 시작하지 못했습니다.")
    deadline = time.monotonic() + common.SCAN_TIMEOUT_SEC
    timed_out = False
    code = None
    try:
        while True:
            try:
                code = proc.wait(timeout=5)
                break
            except subprocess.TimeoutExpired:
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
    finally:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, 9)
            except (OSError, ProcessLookupError):
                pass
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
    if timed_out:
        raise common.Failed("REA 실행 시간 초과(내부 900초)")
    try:
        size = os.path.getsize(evidence_path)
    except OSError:
        size = -1
    if code != 0:
        raise common.Failed(
            "REA 실패 (exit %d). evidence: %s (%d bytes)" % (code, evidence_path, size))
    print("REA 분석 완료. evidence: %s (%d bytes)" % (evidence_path, size))
    return common.EXIT_OK


def run(ctx):
    """Analyze one authorized local artifact. URLs are refused."""
    if ctx.artifact is None:
        raise common.Refused("REA run에는 --artifact <로컬 경로>가 필요합니다.")
    if ctx.target is not None:
        raise common.Refused("REA run은 URL target을 받지 않습니다. --artifact만 사용합니다.")
    node_abs, _ = _node()
    script = _script(ctx.state_tool)
    if _installed_version(os.path.join(ctx.state_tool, "pkg", "package.json")) != VERSION:
        raise common.Prereq("rea-agents pin(%s)이 설치되어 있지 않습니다." % VERSION)
    path = common.check_artifact(ctx.artifact)
    env = dict(os.environ)
    is_dir = os.path.isdir(path)
    if is_dir or path.endswith(".asar"):
        argv = [node_abs, script, "analyze-javascript-application", path, "--json"]
    else:
        if ctx.provider is None:
            raise common.Prereq(
                "네이티브 바이너리 분석에는 승인된 provider가 필요합니다: --provider ghidra "
                "(--with-ghidra install) 또는 hopper/ida 직접 설치.")
        if ctx.provider == "ghidra":
            ghidra = _ghidra_dir(ctx.state_tool)
            if ghidra is None:
                raise common.Prereq("Ghidra가 설치되어 있지 않습니다.")
            env["GHIDRA_INSTALL_DIR"] = ghidra
        elif ctx.provider in ("hopper", "ida"):
            raise common.Prereq(
                "hopper/ida는 proprietary 라이선스로 운영자가 직접 설치·설정해야 합니다.")
        else:
            raise common.Refused("알 수 없는 provider입니다: %s" % ctx.provider)
        check = common.run_capture(
            [node_abs, script, "doctor", "--provider", ctx.provider, "--json"],
            timeout=300, env=env,
            diag_dir=_diag(ctx.state_tool), diag_tag="provider")
        if check["timed_out"] or check["exit"] != 0:
            raise common.Prereq("provider '%s' 준비 실패 (diag: %s)"
                                % (ctx.provider, check["diag_err"]))
        argv = [node_abs, script, "analyze", path, "--provider", ctx.provider, "--json"]
    label = "%d" % int(time.time())
    return _spawn_evidence(argv, ctx, label)
