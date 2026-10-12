#!/usr/bin/env python3
"""Strix (v1.7.0, Apache-2.0) installer/doctor/launcher.

Pinned source: https://github.com/usestrix/strix (release v1.7.0).
Verified CLI (https://docs.strix.ai/usage/cli): `strix -n --target <url>
--scan-mode quick`; headless exits 0 clean / 1 fatal / 2 findings.
Sandbox image ghcr.io/usestrix/strix-sandbox:1.3.0 comes from the official
installer; its registry digest is NOT independently verified.

This is the clean replacement for the obsolete PowerShell wrapper: user
supplied extra args do not exist (fixed argv is built internally, so the
omitted-StrixArgs bug class is gone), the version check is exact, argv
boundaries use list-form spawn, the 900s limit is internal, label containers
are cleaned by ownership, and temp/secret/sidecar ownership is enforced.
Raw scanner output is discarded; stdout carries only safe metadata.
"""

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

from . import common

TOOL = "strix"
VERSION = "1.7.0"
COMMIT = "55bc07991aacb1c26a81b43e7ca53148730d2019"
ASSET_URL = ("https://github.com/usestrix/strix/releases/download/v1.7.0/"
             "strix-1.7.0-linux-x86_64.tar.gz")
ASSET_SHA256 = "b8cd7e84d63cbeff6726301a9e08fddedf40fc6a4edcdb4edda8a853b3312de6"
SANDBOX_IMAGE = "ghcr.io/usestrix/strix-sandbox:1.3.0"
SANDBOX_DIGESTS = {
    "index": "sha256:f6906c3114e504fd1a218fcf028d7a0e46851118403a438b63956de6ea7c4331",
    "amd64": {
        "manifest": "sha256:e5e5d9927f15ca95ad49804ef7d22439771cd27378f400da6edd47556799baff",
        "config": "sha256:bc4947dc64c97f58be4fa0200292346917543c5ed4b1c6a914fe9d6c40786aa0",
    },
    "arm64": {
        "manifest": "sha256:38f9eea087079763312877eaf59047c3bd61ece67ab3479c1da63dc48fe50587",
        "config": "sha256:e9da9c4c3a03d6ddb5a536df74b46e8d3ebf24467ac47d3af86270135ddfcebc",
    },
}
TARGET_IMAGE = "bkimminich/juice-shop:v17.1.1"
LOGICAL_NETWORK = "targets-net"
TARGET_NAME = "juice-shop"
SCAN_MODE = "quick"

HUMAN_METRIC_KEYS = ("tp", "fp", "poc_success_rate", "token_cost",
                     "human_interventions", "reproducibility", "explainability")


def _lock(checkout):
    path = os.path.join(checkout, "tools", "strix", "strix.lock.json")
    if not os.path.isfile(path):
        raise common.Failed("strix.lock.json이 없습니다: %s" % path)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        raise common.Failed("strix.lock.json을 읽지 못했습니다.")
    if not isinstance(data, dict):
        raise common.Failed("strix.lock.json 형식이 예상과 다릅니다.")
    expected = {
        "release": "v" + VERSION,
        "commit": COMMIT,
        "sandbox_image": SANDBOX_IMAGE,
        "runtime_backend": "docker",
        "sandbox_network": LOGICAL_NETWORK,
        "internal_timeout_sec": common.SCAN_TIMEOUT_SEC,
    }
    for key, want in expected.items():
        if data.get(key) != want:
            raise common.Failed("lock pin 불일치: %s" % key)
    if json.dumps(data.get("sandbox_digests"), sort_keys=True) != json.dumps(
            SANDBOX_DIGESTS, sort_keys=True):
        raise common.Failed("lock pin 불일치: sandbox_digests")
    return data


def _allowlist(checkout):
    path = os.path.join(checkout, "tools", "strix", "targets.allow")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = [ln.strip() for ln in handle if ln.strip()
                     and not ln.lstrip().startswith("#")]
    except OSError:
        raise common.Failed("targets.allow를 읽지 못했습니다.")
    if (len(lines) != 3 or len(set(lines)) != 3
            or set(lines) != set(common.ALLOW_HOST_PORTS)):
        raise common.Failed("allowlist가 승인된 3개와 다릅니다.")
    return lines


def _compose_file(checkout):
    path = os.path.join(checkout, "infra", "compose.targets.yml")
    if not os.path.isfile(path):
        raise common.Failed("compose.targets.yml이 없습니다.")
    return path


def _one_item(data, what):
    if not isinstance(data, list) or len(data) != 1 \
            or not isinstance(data[0], dict):
        raise common.Failed("%s inspect 형식이 예상과 다릅니다." % what)
    return data[0]


def _assert_compose_network(checkout):
    """Render compose config and verify actual container/network/image metadata.

    Returns the engine network name. Nothing is created, pulled, or changed.
    """
    compose = _compose_file(checkout)
    result = common.run_capture(
        common.docker_base() + ["compose", "-f", compose, "config", "--format", "json"],
        timeout=60)
    if result["timed_out"] or result["exit"] != 0:
        raise common.Failed("compose config 확인 실패")
    try:
        config = json.loads(result["out"].decode("utf-8"))
    except (UnicodeError, ValueError):
        raise common.Failed("compose config가 유효한 JSON이 아닙니다.")
    try:
        services = config["services"]
        networks = config["networks"]
        if set(services) != {"juice-shop"} or set(networks) != {LOGICAL_NETWORK}:
            raise common.Failed("compose는 승인된 단일 target/망만 정의해야 합니다.")
        service = services["juice-shop"]
        network = networks[LOGICAL_NETWORK]
        if service["image"] != TARGET_IMAGE \
                or service.get("container_name") != TARGET_NAME \
                or service.get("restart") != "unless-stopped":
            raise common.Failed("compose target/image 정책 불일치")
        if network.get("internal") is not True or network.get("driver") != "bridge" \
                or not network.get("name"):
            raise common.Failed("compose 망 정책 불일치")
        ports = service.get("ports")
        if not isinstance(ports, list) or len(ports) != 1:
            raise common.Failed("compose는 승인된 loopback 포트 하나만 게시해야 합니다.")
        port = ports[0]
        if not isinstance(port, dict) or port.get("host_ip") != "127.0.0.1" \
                or str(port.get("target")) != "3000" \
                or str(port.get("published")) != "3000" \
                or port.get("protocol") != "tcp":
            raise common.Failed("compose 포트 정책 불일치")
    except (KeyError, TypeError, AttributeError):
        raise common.Failed("compose config 형식이 예상과 다릅니다.")
    target = _one_item(
        common.docker_json(["container", "inspect", TARGET_NAME]), "target container")
    try:
        labels = target["Config"]["Labels"] or {}
        project = labels.get("com.docker.compose.project")
        if not isinstance(project, str) \
                or not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project):
            raise common.Failed("target Compose project 신원 없음")
        if target.get("Name") != "/" + TARGET_NAME \
                or target["Config"].get("Image") != TARGET_IMAGE \
                or labels.get("com.docker.compose.service") != "juice-shop" \
                or target["State"].get("Running") is not True \
                or target["State"].get("Status") != "running" \
                or (target.get("HostConfig") or {}).get("RestartPolicy", {}).get("Name") \
                != "unless-stopped":
            raise common.Failed("target 컨테이너 신원/이미지/실행 상태 불일치")
        if not re.fullmatch(r"[0-9a-f]{64}", target.get("Id") or ""):
            raise common.Failed("target 컨테이너 ID 형식 오류")
        target_image = _one_item(
            common.docker_json(["image", "inspect", TARGET_IMAGE]), "target image")
        common.assert_exact_image(SANDBOX_IMAGE, SANDBOX_DIGESTS, "sandbox")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", target_image.get("Id") or "") \
                or TARGET_IMAGE not in (target_image.get("RepoTags") or []):
            raise common.Failed(
                "승인된 로컬 이미지 태그가 준비되지 않았습니다: %s" % TARGET_IMAGE)
        if target.get("Image") != target_image.get("Id"):
            raise common.Failed("실행 중인 target이 pin된 이미지와 다릅니다.")
        endpoints = (target.get("NetworkSettings") or {}).get("Networks") or {}
        if not isinstance(endpoints, dict) or len(endpoints) != 1:
            raise common.Failed("target은 정확히 하나의 망 endpoint를 가져야 합니다.")
        engine_name = list(endpoints)[0]
        endpoint = endpoints[engine_name]
        if engine_name != network.get("name") \
                or not re.fullmatch(r"[0-9a-f]{64}", endpoint.get("NetworkID") or "") \
                or not re.fullmatch(r"[0-9a-f]{64}", endpoint.get("EndpointID") or "") \
                or TARGET_NAME not in (endpoint.get("Aliases") or []):
            raise common.Failed("target endpoint/망 이름/alias 불일치")
        net = _one_item(
            common.docker_json(["network", "inspect", endpoint["NetworkID"]]), "network")
        if net.get("Id") != endpoint["NetworkID"] or net.get("Name") != engine_name \
                or net.get("Internal") is not True or net.get("Driver") != "bridge" \
                or (net.get("Labels") or {}).get("com.docker.compose.network") != LOGICAL_NETWORK \
                or (net.get("Labels") or {}).get("com.docker.compose.project") != project:
            raise common.Failed("실제 Docker 망이 승인된 internal Compose 망이 아닙니다.")
        members = net.get("Containers") or {}
        member = members.get(target["Id"]) or {}
        if member.get("Name") != TARGET_NAME \
                or member.get("EndpointID") != endpoint["EndpointID"]:
            raise common.Failed("target 망 멤버십 불일치")
        published = (target.get("NetworkSettings") or {}).get("Ports") or {}
        bindings = published.get("3000/tcp")
        if not isinstance(bindings, list) or len(bindings) != 1 \
                or bindings[0].get("HostIp") != "127.0.0.1" \
                or bindings[0].get("HostPort") != "3000":
            raise common.Failed("target이 승인된 loopback 포트에 게시되지 않았습니다.")
        for key, value in published.items():
            if key != "3000/tcp" and value is not None:
                raise common.Failed("target에 추가 게시 포트가 있습니다.")
    except (KeyError, TypeError, AttributeError):
        raise common.Failed("Docker metadata 형식이 예상과 다릅니다.")
    return engine_name, target["Id"]


def _strix_binary(state_tool):
    candidate = os.path.join(state_tool, "bin", "strix")
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    found = common.which("strix")
    if found is None:
        raise common.Prereq("strix 실행 파일이 없습니다. 먼저 install을 실행하십시오.")
    return found


def _exact_version(binary, workdir):
    result = common.run_capture([binary, "--version"], timeout=60, cwd=workdir)
    if result["timed_out"] or result["exit"] != 0:
        return False
    return result["out"].decode("utf-8", "replace").strip() == "strix " + VERSION


def _run_container_ids(run_id):
    result = common.run_capture(
        common.docker_base() + ["ps", "-a", "--no-trunc", "-q", "--filter",
                                "label=strix-run-id=" + run_id],
        timeout=60)
    if result["timed_out"] or result["exit"] != 0:
        raise common.Failed("run 컨테이너 조회 실패")
    ids = []
    seen = set()
    for line in result["out"].decode("utf-8", "replace").splitlines():
        cid = line.strip()
        if not re.fullmatch(r"[0-9a-f]{64}", cid) or cid in seen:
            raise common.Failed("컨테이너 조회 결과가 손상되었습니다.")
        seen.add(cid)
        ids.append(cid)
    return ids


def _remove_owned_containers(run_id, approved_target_id):
    """Remove only current-run labeled containers. Returns (removed, failures)."""
    failures = []
    removed = 0
    try:
        ids = _run_container_ids(run_id)
    except common.Failed:
        return 0, ["run container query failed"]
    for cid in ids:
        try:
            info = _one_item(
                common.docker_json(["container", "inspect", cid]), "run container")
            labels = (info.get("Config") or {}).get("Labels") or {}
            if info.get("Id") != cid or cid == approved_target_id \
                    or labels.get("strix-run-id") != run_id:
                raise common.Failed("ownership mismatch")
            result = common.run_capture(
                common.docker_base() + ["container", "rm", "--force", cid],
                timeout=120)
            if result["timed_out"] or result["exit"] != 0:
                raise common.Failed("owned container removal failed")
            removed += 1
        except common.Failed:
            failures.append("ownership inspection or owned container removal failed")
    try:
        if _run_container_ids(run_id):
            failures.append("current-run containers remain")
    except common.Failed:
        failures.append("final run container query failed")
    return removed, failures


def install(ctx):
    """Download the pinned asset, verify sha256, extract, pull sandbox image."""
    bindir = os.path.join(ctx.state_tool, "bin")
    os.makedirs(bindir, mode=0o700, exist_ok=True)
    binary = os.path.join(bindir, "strix")
    if os.path.exists(binary):
        raise common.Failed("기존 strix 바이너리가 있습니다. 삭제는 운영자가 직접 수행하십시오.")
    tmpdir = tempfile.mkdtemp(prefix="strix-install-")
    try:
        archive = os.path.join(tmpdir, "strix.tar.gz")
        common.download_to(ASSET_URL, archive, ASSET_SHA256)
        import tarfile
        try:
            with tarfile.open(archive, "r:gz") as tar:
                members = tar.getmembers()
                if len(members) != 1 or not members[0].isfile():
                    raise common.Failed("asset 내용물이 예상과 다릅니다.")
                member = members[0]
                member.name = "strix"
                tar.extract(member, path=bindir)
        except (tarfile.TarError, OSError, EOFError):
            raise common.Failed("asset 압축 해제 실패")
        try:
            os.chmod(binary, 0o755)
        except OSError as exc:
            raise common.Failed("바이너리 권한 설정 실패 (errno %s)" % exc.errno)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    if not _exact_version(binary, ctx.state_tool):
        raise common.Failed("설치된 바이너리가 exact strix %s가 아닙니다." % VERSION)
    pull = common.run_capture(
        common.docker_base() + ["pull", SANDBOX_IMAGE], timeout=1800)
    if pull["timed_out"] or pull["exit"] != 0:
        raise common.Failed("sandbox 이미지 pull 실패")
    try:
        image_id, arch = common.assert_exact_image(
            SANDBOX_IMAGE, SANDBOX_DIGESTS, "sandbox")
    except common.Failed as exc:
        raise common.Failed("sandbox 이미지 확인 실패: %s" % exc)
    receipt = {
        "tool": TOOL, "action": "install", "version": VERSION, "commit": COMMIT,
        "asset_sha256": ASSET_SHA256, "binary": binary,
        "sandbox_image": SANDBOX_IMAGE, "sandbox_observed": {
            "id": image_id, "arch": arch,
            "index": SANDBOX_DIGESTS["index"]},
        "digest_note": "tag가 아닌 registry digest exact-match로 강제했습니다.",
    }
    common.write_receipt(os.path.join(ctx.state_tool, "install-receipt.json"), receipt)
    print("Strix %s 설치 확인. 바이너리: %s" % (VERSION, binary))
    return common.EXIT_OK


def doctor(ctx):
    """Readiness: pins, binary exact version, sandbox image, compose metadata, LLM env."""
    _lock(ctx.checkout)
    _allowlist(ctx.checkout)
    binary = _strix_binary(ctx.state_tool)
    if not _exact_version(binary, ctx.state_tool):
        raise common.Prereq("exact strix %s 바이너리가 아닙니다." % VERSION)
    try:
        common.assert_exact_image(SANDBOX_IMAGE, SANDBOX_DIGESTS, "sandbox")
    except common.Failed as exc:
        raise common.Prereq("sandbox 이미지 pin 불일치: %s" % exc)
    engine_name, _ = _assert_compose_network(ctx.checkout)
    missing = [key for key in ("STRIX_LLM", "LLM_API_KEY")
               if not (os.environ.get(key) or "").strip()]
    if missing:
        raise common.Prereq("운영자 env가 없습니다: %s (기본 모델을 생성하지 않습니다.)"
                            % ", ".join(missing))
    print("Strix ready (exact %s, sandbox ok, network %s)." % (VERSION, engine_name))
    return common.EXIT_OK


def _load_human_metrics(path):
    try:
        with open(path, "rb") as handle:
            raw = handle.read().decode("utf-8")
    except (OSError, UnicodeError):
        raise common.Failed("metrics 입력 파일을 읽지 못했습니다.")
    import json as _json

    def _no_dupes(pairs):
        seen = {}
        for key, value in pairs:
            if key in seen:
                raise common.Failed("metrics JSON에 중복 키가 있습니다.")
            seen[key] = value
        return seen

    decoder = _json.JSONDecoder(object_pairs_hook=_no_dupes)
    try:
        obj, end = decoder.raw_decode(raw)
    except ValueError:
        raise common.Failed("metrics 입력이 유효한 JSON이 아닙니다.")
    if raw[end:].strip() != "":
        raise common.Failed("metrics 입력 뒤에 추가 내용이 있습니다.")
    if not isinstance(obj, dict):
        raise common.Failed("metrics 입력은 객체여야 합니다.")
    if set(obj) != set(HUMAN_METRIC_KEYS):
        raise common.Failed(
            "metrics 입력은 사람 확정 7지표만 포함해야 합니다 (duration_sec/full-record/추가 필드 금지).")
    return obj


def run(ctx):
    """Execute one pinned scan against juice-shop:3000 with full cleanup."""
    if ctx.target is None:
        raise common.Refused("Strix run에는 --target <allowlist URL>이 필요합니다.")
    if ctx.strix_args:
        raise common.Refused("추가 Strix 인자는 허용되지 않습니다.")
    if not 1 <= ctx.repeat_index <= 3:
        raise common.Refused("repeat_index는 1~3이어야 합니다.")
    if (ctx.metrics_record is None) != (ctx.jsonl_out is None):
        return _refuse(13, "기록에는 --metrics-record와 --jsonl-out을 함께 지정해야 합니다.")
    if ctx.jsonl_out is not None and not os.path.isdir(
            os.path.dirname(os.path.abspath(ctx.jsonl_out))):
        return _refuse(13, "JSONL 목적지 디렉터리가 없습니다.")
    _lock(ctx.checkout)
    _allowlist(ctx.checkout)
    _, host_port, origin = common.check_target_url(ctx.target)
    if host_port != common.EXECUTABLE_HOST_PORT:
        return _refuse(14, "실제 실행 대상은 juice-shop:3000뿐입니다.")
    if common.which("docker") is None:
        return _refuse(9, "docker 실행 파일이 없습니다.")
    try:
        engine_name, approved_target_id = _assert_compose_network(ctx.checkout)
    except (common.Failed, common.Refused, common.Prereq) as exc:
        return _refuse(9, "Docker metadata 전제조건 실패: %s" % exc)
    try:
        binary = _strix_binary(ctx.state_tool)
    except common.Prereq as exc:
        return _refuse(9, str(exc))
    missing = [key for key in ("STRIX_LLM", "LLM_API_KEY")
               if not (os.environ.get(key) or "").strip()]
    if missing:
        return _refuse(8, "운영자 env가 없습니다: %s" % ", ".join(missing))

    start_mono = time.monotonic()
    start_utc = time.gmtime()
    run_guid = uuid.uuid4().hex
    run_id = "%s-juice-shop-strix-%03d-%s" % (
        time.strftime("%Y-%m-%d", start_utc), ctx.repeat_index, run_guid[:8])
    workdir = tempfile.mkdtemp(prefix="strix-run-")
    if not _exact_version(binary, workdir):
        shutil.rmtree(workdir, ignore_errors=True)
        return _refuse(9, "strix 바이너리가 exact %s가 아닙니다." % VERSION)

    child_env = {}
    for key, value in os.environ.items():
        if key.upper() in ("STRIX_IMAGE", "STRIX_RUNTIME_BACKEND",
                           "STRIX_DOCKER_SANDBOX_NETWORK", "STRIX_RUN_ID",
                           "DOCKER_HOST", "DOCKER_CONTEXT"):
            continue
        child_env[key] = value
    child_env["STRIX_IMAGE"] = SANDBOX_IMAGE
    child_env["STRIX_RUNTIME_BACKEND"] = "docker"
    child_env["STRIX_DOCKER_SANDBOX_NETWORK"] = engine_name
    child_env["STRIX_RUN_ID"] = run_id
    child_env["DOCKER_HOST"] = common.docker_endpoint()

    argv = [binary, "-n", "--target", ctx.target, "--scan-mode", SCAN_MODE]
    proc = None
    timed_out = False
    launch_error = ""
    strix_exit = -1
    try:
        try:
            with open(os.devnull, "rb") as null_in:
                with open(os.devnull, "wb") as null_out:
                    proc = subprocess.Popen(
                        argv, stdin=null_in, stdout=null_out, stderr=null_out,
                        cwd=workdir, env=child_env, start_new_session=True)
        except (FileNotFoundError, OSError) as exc:
            launch_error = "scanner start failed"
            strix_exit = -1
        if proc is not None:
            deadline = start_mono + common.SCAN_TIMEOUT_SEC
            code = None
            while True:
                try:
                    code = proc.wait(timeout=0.2)
                    break
                except subprocess.TimeoutExpired:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
            if timed_out:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
                proc.wait()
            else:
                strix_exit = code
    finally:
        cleanup_failures = []
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cleanup_failures.append("scanner process tree cleanup failed")
        if proc is not None:
            try:
                removed, failures = _remove_owned_containers(run_id, approved_target_id)
            except Exception:
                removed, failures = 0, ["run container cleanup failed"]
            cleanup_failures.extend(failures)
        else:
            removed = 0
        try:
            shutil.rmtree(workdir)
        except OSError:
            cleanup_failures.append("raw output working directory cleanup failed")

    end_utc = time.gmtime()
    duration = time.monotonic() - start_mono
    if launch_error:
        wrapper_exit, scan_status, strix_text = 11, "launch-failed", "launch-failed"
    elif timed_out:
        wrapper_exit, scan_status, strix_text = 10, "timeout", "timeout"
    elif strix_exit == 0:
        wrapper_exit, scan_status, strix_text = 0, "clean", "0"
    elif strix_exit == 2:
        wrapper_exit, scan_status, strix_text = common.EXIT_FINDINGS, "findings", "2"
    else:
        wrapper_exit, scan_status, strix_text = 11, "fatal", str(strix_exit)

    if wrapper_exit == 11 and not launch_error and not timed_out:
        common.eprint("[실패] Strix 치명적 오류(상위 종료 %s). 원시 출력은 저장하지 않습니다."
                      % strix_text)
    elif wrapper_exit == common.EXIT_FINDINGS:
        print("[완료] Strix 발견 보고(상위 종료 2). 판정 전 JSONL 기록 없음.")
    elif wrapper_exit == 0:
        print("[완료] Strix 발견 없음(상위 종료 0).")
    elif wrapper_exit == 10:
        common.eprint("[실패] 내부 900초 상한 초과. 정리 후 미기록.")
    if cleanup_failures:
        for failure in cleanup_failures:
            common.eprint("[정리 실패] %s" % failure)

    def stamp(moment):
        return time.strftime("%Y-%m-%dT%H:%M:%S", moment) + "Z"

    meta = {
        "run_id": run_id,
        "timestamp": stamp(start_utc),
        "utc_end": stamp(end_utc),
        "tool": TOOL,
        "tool_version": VERSION,
        "tool_commit": COMMIT,
        "sandbox_image": SANDBOX_IMAGE,
        "runtime_backend": "docker",
        "sandbox_network": engine_name,
        "scan_mode": SCAN_MODE,
        "target": {"name": "juice-shop", "host_port": host_port},
        "target_origin": origin,
        "time_limit_min": common.TIME_LIMIT_MIN,
        "repeat_index": ctx.repeat_index,
        "duration_sec": duration,
        "strix_exit": strix_text,
        "scan_status": scan_status,
        "cleanup_status": ("failed" if cleanup_failures
                            else ("ok" if proc is not None else "not-needed")),
        "removed_containers": removed,
        "cleanup_failures": list(cleanup_failures),
        "record_status": ("not-requested" if ctx.metrics_record is None
                           else "not-attempted"),
        "wrapper_exit": wrapper_exit,
    }
    post_errors = []
    sidecar_created = False
    if ctx.meta_out is not None:
        try:
            payload = (json.dumps(meta, ensure_ascii=False, indent=2,
                                  sort_keys=True) + "\n").encode("utf-8")
            fd = os.open(ctx.meta_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(payload)
            except OSError as exc:
                post_errors.append("sidecar write failed (errno %s)" % exc.errno)
            else:
                sidecar_created = True
        except FileExistsError:
            post_errors.append("sidecar가 이미 존재하여 덮어쓰지 않습니다.")
        except OSError as exc:
            post_errors.append("sidecar 생성 실패 (errno %s)" % exc.errno)

    if ctx.metrics_record is not None:
        if wrapper_exit not in (0, common.EXIT_FINDINGS):
            meta["record_status"] = "not-attempted: incomplete run"
            common.eprint("[기록 실패] 미완결 실행이라 기록하지 않습니다.")
        else:
            try:
                human = _load_human_metrics(ctx.metrics_record)
            except common.Failed as exc:
                meta["record_status"] = "refused: %s" % exc
                post_errors.append("metrics 입력 거부")
            else:
                full = {
                    "run_id": run_id,
                    "timestamp": meta["timestamp"],
                    "tool": TOOL,
                    "tool_version": VERSION,
                    "target": {"name": "juice-shop", "host_port": host_port},
                    "time_limit_min": common.TIME_LIMIT_MIN,
                    "repeat_index": ctx.repeat_index,
                    "metrics": dict(human, duration_sec=duration),
                }
                full_tmp = os.path.join(
                    tempfile.gettempdir(), "strix-full-%s.json" % run_guid)
                try:
                    payload = (json.dumps(full, ensure_ascii=False, allow_nan=False,
                                          separators=(",", ":")) + "\n").encode("utf-8")
                    fd = os.open(full_tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    try:
                        with os.fdopen(fd, "wb") as handle:
                            handle.write(payload)
                    except OSError as exc:
                        raise common.Failed("full record 쓰기 실패")
                    writer = os.path.join(ctx.checkout, "tools", "strix", "metrics.py")
                    result = common.run_capture(
                        [sys.executable, writer, "--record", full_tmp,
                         "--output", ctx.jsonl_out],
                        timeout=120)
                    if result["exit"] == 0:
                        meta["record_status"] = "appended"
                    else:
                        meta["record_status"] = "writer exit %d" % result["exit"]
                        post_errors.append("writer가 거부했습니다 (exit %d)" % result["exit"])
                except (common.Failed, OSError) as exc:
                    meta["record_status"] = "failed"
                    post_errors.append(str(exc))
                finally:
                    try:
                        if os.path.exists(full_tmp):
                            os.remove(full_tmp)
                    except OSError:
                        post_errors.append("임시 full record 삭제 실패")
        if ctx.meta_out is not None and sidecar_created:
            meta["wrapper_exit"] = wrapper_exit
            try:
                payload = (json.dumps(meta, ensure_ascii=False, indent=2,
                                      sort_keys=True) + "\n").encode("utf-8")
                with open(ctx.meta_out, "wb") as handle:
                    handle.write(payload)
            except OSError:
                post_errors.append("sidecar 갱신 실패")

    if wrapper_exit in (0, common.EXIT_FINDINGS):
        if cleanup_failures:
            post_errors.append("정리 실패")
        if post_errors:
            for message in post_errors:
                common.eprint("[후속 처리 실패] %s" % message)
            wrapper_exit = common.EXIT_POST
    else:
        for message in post_errors:
            common.eprint("[경고] %s" % message)
    meta["wrapper_exit"] = wrapper_exit
    if sidecar_created:
        try:
            payload = (json.dumps(meta, ensure_ascii=False, indent=2,
                                  sort_keys=True) + "\n").encode("utf-8")
            with open(ctx.meta_out, "wb") as handle:
                handle.write(payload)
        except OSError as exc:
            common.eprint("[후속 처리 실패] sidecar 갱신 실패 (errno %s)" % exc.errno)
            if wrapper_exit in (0, common.EXIT_FINDINGS):
                wrapper_exit = common.EXIT_POST
    elif ctx.meta_out is None:
        print("[요약] run_id=%s origin=%s duration=%.3f scan=%s cleanup=%s exit=%d"
              % (run_id, origin, duration, scan_status,
                 meta["cleanup_status"], wrapper_exit))
    return wrapper_exit


def _refuse(code, message):
    common.eprint("[거부] %s" % message)
    return code
