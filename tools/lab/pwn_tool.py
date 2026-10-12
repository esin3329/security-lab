#!/usr/bin/env python3
"""pwn lab (pwn/Dockerfile recipe, read-only use) installer/doctor/launcher.

The Dockerfile itself is never modified here. Build context and tag follow
the recipe exactly: `docker build -t pwn-lab:fixed -f pwn/Dockerfile pwn/`
with the checkout as cwd. Every check and run executes the real
GDB/pwntools/pwndbg entrypoints inside owned ephemeral containers
(network none, read-only single-artifact mount, label-verified removal).
"""

import os
import uuid

from . import common

TOOL = "pwn"
IMAGE_TAG = "pwn-lab:fixed"


def _paths(checkout):
    dockerfile = os.path.join(checkout, "pwn", "Dockerfile")
    context = os.path.join(checkout, "pwn")
    for path in (dockerfile, context,
                 os.path.join(context, "challenges"),
                 os.path.join(context, "exploits")):
        if not os.path.exists(path):
            raise common.Prereq("pwn recipe 경로가 없습니다: %s" % path)
    return dockerfile, context


def _image_id():
    try:
        data = common.docker_json(["image", "inspect", IMAGE_TAG], timeout=60)
    except common.Failed:
        return None
    if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
        return data[0].get("Id")
    return None


def install(ctx):
    """Build the pinned recipe image. Long timeout; cause preserved."""
    dockerfile, context = _paths(ctx.checkout)
    result = common.run_capture(
        common.docker_base() + ["build", "-t", IMAGE_TAG,
                                "-f", dockerfile, context],
        timeout=1800, cwd=ctx.checkout)
    if result["timed_out"]:
        raise common.Failed("pwn 이미지 빌드 시간 초과")
    if result["exit"] != 0:
        raise common.Failed("pwn 이미지 빌드 실패 (exit %d)" % result["exit"])
    image_id = _image_id()
    if not image_id:
        raise common.Failed("빌드 후 이미지를 확인하지 못했습니다.")
    receipt = {
        "tool": TOOL, "action": "install", "image": IMAGE_TAG,
        "image_id": image_id,
        "recipe": "pwn/Dockerfile (checkout read-only use)",
    }
    common.write_receipt(
        os.path.join(ctx.state_tool, "install-receipt.json"), receipt)
    print("pwn 이미지 빌드 확인: %s (%s)" % (IMAGE_TAG, image_id))
    return common.EXIT_OK


def _owned_run(argv, label, mounts=()):
    """Run one owned ephemeral check container with guaranteed cleanup.

    Unique name + pwn-run label, network none, cap-drop ALL, read-only
    single-file mounts via --mount (commas in paths are refused fail-closed
    since -v splits on colons and --mount splits on commas). After the run,
    ownership (owned label + pinned image id) is verified before rm -f, then
    absence is verified. Failure causes are preserved, never masked.
    """
    name = "pwn-%s" % uuid.uuid4().hex[:8]
    cmd = common.docker_base() + ["run", "--rm", "--name", name,
                                  "--label", "pwn-run-owned=true",
                                  "--network", "none", "--cap-drop", "ALL"]
    for src, dst in mounts:
        if "," in src or "," in dst or "\n" in src or "\n" in dst:
            raise common.Refused("mount 경로에 쉼표/개행을 사용할 수 없습니다.")
        cmd += ["--mount", "type=bind,src=%s,dst=%s,readonly" % (src, dst)]
    cmd += [IMAGE_TAG] + list(argv)
    proc_result = None
    primary = None
    try:
        proc_result = common.run_capture(cmd, timeout=300)
    except BaseException as exc:
        primary = exc
    cleanup_failure = _cleanup_owned(name)
    if primary is not None:
        if cleanup_failure is not None:
            common.eprint("[정리 실패] %s" % cleanup_failure)
        raise primary
    if cleanup_failure is not None:
        raise cleanup_failure
    if proc_result["timed_out"]:
        raise common.Prereq("%s 확인 시간 초과" % label)
    if proc_result["exit"] != 0:
        raise common.Prereq("%s 확인 실패 (exit %d)" % (label, proc_result["exit"]))
    return proc_result


def _cleanup_owned(name):
    """Verify ownership, rm -f, verify absence. Returns None or Failed.

    Never raises: every internal failure is converted so callers can
    preserve the primary cause alongside cleanup causes.
    """
    try:
        try:
            data = common.docker_json(
                ["container", "inspect", name], timeout=60)
        except common.Failed:
            data = None
        if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
            info = data[0]
            labels = (info.get("Config") or {}).get("Labels") or {}
            if labels.get("pwn-run-owned") != "true":
                return common.Failed("소유하지 않은 컨테이너라 정리하지 않습니다: %s" % name)
            result = common.run_capture(
                common.docker_base() + ["container", "rm", "--force", name],
                timeout=120)
            if result["timed_out"] or result["exit"] != 0:
                return common.Failed("owned 컨테이너 정리 실패: %s" % name)
        gone = common.run_capture(
            common.docker_base() + ["ps", "-a", "-q", "--filter", "name=^/%s$" % name],
            timeout=60)
        if gone["timed_out"] or gone["exit"] != 0:
            return common.Failed("컨테이너 잔류 확인 실패: %s" % name)
        if gone["out"].strip() != b"":
            return common.Failed("ephemeral 컨테이너가 잔류합니다: %s" % name)
        return None
    except common.Failed as exc:
        return exc
    except Exception:
        return common.Failed("정리 중 예상 밖 오류: %s" % name)


def _container_check(argv, label, mounts=()):
    _owned_run(argv, label, mounts=mounts)


def _gdb_version():
    result = _owned_run(["gdb", "--version"], "gdb")
    first = result["out"].decode("utf-8", "replace").splitlines()
    return first[0].strip() if first else "unknown"


def _pwntools_version():
    result = _owned_run(["python3", "-m", "pip", "show", "pwntools"], "pwntools")
    for line in result["out"].decode("utf-8", "replace").splitlines():
        if line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
            if version != "4.14.0":
                raise common.Prereq(
                    "pwntools 버전이 pin(4.14.0)과 다릅니다: %s" % version)
            return version
    raise common.Prereq("pwntools 버전을 확인하지 못했습니다.")


def _built_image_id(ctx):
    """Install receipt ownership: current image must match the built record."""
    current = _image_id()
    if current is None:
        raise common.Prereq("pwn 이미지가 없습니다. 먼저 install을 실행하십시오.")
    receipt_path = os.path.join(ctx.state_tool, "install-receipt.json")
    if not os.path.isfile(receipt_path):
        raise common.Prereq("빌드 ownership 기록이 없습니다. install을 다시 실행하십시오.")
    try:
        with open(receipt_path, "r", encoding="utf-8") as handle:
            import json
            recorded = json.load(handle).get("image_id")
    except (OSError, ValueError):
        raise common.Prereq("빌드 ownership 기록을 읽지 못했습니다.")
    if recorded != current:
        raise common.Prereq("현재 이미지가 pin된 빌드와 다릅니다. install을 다시 실행하십시오.")
    return current


def _assert_gone(name):
    result = common.run_capture(
        common.docker_base() + ["ps", "-a", "-q", "--filter",
                                "name=^/%s$" % name],
        timeout=60)
    if result["timed_out"] or result["exit"] != 0:
        raise common.Failed("컨테이너 잔류 확인 실패")
    if result["out"].strip() != b"":
        raise common.Failed("ephemeral 컨테이너가 잔류합니다: %s" % name)


def doctor(ctx):
    """Readiness: recipe files, owned image, gdb/pwntools/pwndbg checks."""
    _paths(ctx.checkout)
    if common.which("docker") is None:
        raise common.Prereq("docker 실행 파일이 없습니다.")
    _built_image_id(ctx)
    gdb_version = _gdb_version()
    _pwntools_version()
    _container_check(["test", "-d", "/opt/pwndbg"], "pwndbg checkout")
    print("pwn ready (%s / pwntools==4.14.0 / /opt/pwndbg 확인)." % gdb_version)
    return common.EXIT_OK


def run(ctx):
    """Run approved GDB/pwndbg/pwntools entrypoints on one local artifact.

    Owned ephemeral container, network none, artifact mounted read-only as
    /pwn/target, no other mounts, no writes outside the container.
    """
    if ctx.artifact is None:
        raise common.Refused("pwn run에는 --artifact <로컬 바이너리>가 필요합니다.")
    artifact = common.check_artifact(ctx.artifact)
    if not os.path.isfile(artifact):
        raise common.Refused("artifact는 파일이어야 합니다.")
    image_id = _built_image_id(ctx)
    name = "pwn-%s" % uuid.uuid4().hex[:8]
    gdb_version = _gdb_version()
    pwn_version = _pwntools_version()
    _container_check(["test", "-d", "/opt/pwndbg"], "pwndbg checkout",
                     name=name + "-check")
    _assert_gone(name + "-check")
    _container_check(["python3", "-c", "import pwn"], "pwntools entrypoint",
                     name=name + "-pwn",
                     mounts=((artifact, "/pwn/target"),))
    _assert_gone(name + "-pwn")
    _container_check(["gdb", "-q", "-batch", "/pwn/target",
                      "-ex", "info files", "-ex", "quit"],
                     "gdb artifact load (image gdbinit+pwndbg)",
                     name=name, mounts=((artifact, "/pwn/target"),))
    _assert_gone(name)
    receipt = {
        "tool": TOOL, "action": "run", "image": IMAGE_TAG,
        "image_id": image_id, "artifact": "local file (path not stored)",
        "gdb": gdb_version, "pwntools": pwn_version,
        "container": "owned ephemeral, network none, artifact :ro",
        "note": "대화형 실습은 recipe의 승인 명령으로 운영자가 직접 진입합니다.",
    }
    path = os.path.join(ctx.state_tool, "run-receipt.json")
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError as exc:
        raise common.Failed("기존 run receipt 교체 실패 (errno %s)" % exc.errno)
    common.write_receipt(path, receipt)
    print("pwn entrypoint 실행 확인 (%s, %s)." % (gdb_version, pwn_version))
    return common.EXIT_OK
