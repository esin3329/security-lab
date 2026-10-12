#!/usr/bin/env python3
"""ARTEX-KO (v0.3.15-ko.1, AGPL-3.0) installer/doctor/launcher.

Pinned source: https://github.com/jiwoochris/artex-ko
(release v0.3.15-ko.1, digest-pinned images below).
Verified surface (pinned tag source): loopback UI 127.0.0.1:8787 + /setup,
ARTEX_SETUP_TOKEN (verbatim, never logged) / ARTEX_ADMIN_PASSWORD headless
init, LLM env, and the real authenticated API: /api/auth/status|init|login,
/api/health, /api/llm, /api/llm/test, POST /api/tasks (createTask launches
immediately), POST /api/tasks/{id}/scope (keyword kind verified in
db/task_scope.go), task intercept allow rules (exact_domain, enforced in
db.EvaluateAssetGate), POST /api/tasks/{id}/control pause|resume.
Update endpoints (/api/update/*) are never called; the service runs on a
read-only rootfs without a Docker socket, so update apply cannot execute.

The launcher creates one authenticated scoped practice task for
juice-shop:3000 only, with an exact-domain allow rule inside the create
body (deny-by-default, no post-create race) plus a scope record, then
verifies it. Failures after creation pause the task and roll back owned
attachments; state DB and unrelated resources are never touched.
"""

import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from . import common

TOOL = "artex"
VERSION = "v0.3.15-ko.1"
IMAGE = ("ghcr.io/jiwoochris/artex-ko@sha256:"
         "cda198c05578bf1ef09cf4992aa5cd370ca76447e7c3b3c8e3cd308c593b3d75")
IMAGE_DIGESTS = {
    "index": "sha256:cda198c05578bf1ef09cf4992aa5cd370ca76447e7c3b3c8e3cd308c593b3d75",
    "amd64": {
        "manifest": "sha256:0443b506ddc9a5aa4172e3f595fbeef157ecdbf66a4ec0f3a2803d23a3d6dca0",
        "config": "sha256:6e3e9bf2295a3f4de174a8c0dadc076bc4a0f2b64ecc639638bad4ec20068200",
    },
    "arm64": {
        "manifest": "sha256:780a103dba4bc24398e6819cdd7c89ffb3fb07635cd6c7227768ab6a4aca312e",
        "config": "sha256:176c1197b35d83b1a73858b27312156c2c978e6a6b2de82e4ee7748c16fdcc12",
    },
}
POSTGRES_IMAGE = ("postgres@sha256:"
                  "721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea")
POSTGRES_DIGESTS = {
    "index": "sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea",
    "amd64": {
        "manifest": "sha256:1a66d744c1b459e13b05a8fca341da84cb63383e99ce262210efee5a319d4551",
        "config": "sha256:81bd698b4594e751a3269e4dcd3e03a4a0ec0daf7b72e7aa1abd43cce9887542",
    },
    "arm64": {
        "manifest": "sha256:2c942175a1255a9abe0366e48c1b401d9f50f835b04dfea13f111609b5530df7",
        "config": "sha256:ef738a34a8651d11b2bace81c55c7e2187f786b484add6c83070884340074368",
    },
}
UI_PORT = 8787
TASK_TIMEOUT_SEC = 900
COMPOSE_PROJECT = "security-lab-artex"
ARTEX_SERVICE = "artex"
POSTGRES_SERVICE = "postgres"

ENV_TEMPLATE = (
    "# ARTEX-KO operator env (private state, 0600). Values are never stored in Git.\n"
    "# POSTGRES_PASSWORD/ARTEX_SETUP_TOKEN/ARTEX_ADMIN_PASSWORD are generated\n"
    "# per install so upstream console fallbacks never trigger. Model access\n"
    "# requires an explicit ARTEX_LLM_PROVIDER + ARTEX_LLM_MODEL plus an approved\n"
    "# local gateway endpoint in ARTEX_LLM_BASE_URL (keys alone are not enough\n"
    "# and direct arbitrary internet is refused).\n"
    "POSTGRES_USER=artex\n"
    "POSTGRES_PASSWORD={pg_password}\n"
    "POSTGRES_DB=artex\n"
    "ANTHROPIC_API_KEY=\n"
    "OPENAI_API_KEY=\n"
    "ARTEX_LLM_PROVIDER=\n"
    "ARTEX_LLM_MODEL=\n"
    "ARTEX_LLM_BASE_URL=\n"
    "ARTEX_LLM_PROXY=\n"
    "ARTEX_SETUP_TOKEN={setup_token}\n"
    "ARTEX_ADMIN_PASSWORD={admin_password}\n"
    "ARTEX_CORS_ORIGINS=\n"
    "ARTEX_LANG=\n"
)


def _repo_compose(checkout):
    path = os.path.join(checkout, "tools", "artex-ko", "docker-compose.pinned.yml")
    if not os.path.isfile(path):
        raise common.Failed("pinned compose가 없습니다: %s" % path)
    return path


def _state_compose(state_tool):
    return os.path.join(state_tool, "docker-compose.yml")


def _env_path(state_tool):
    return os.path.join(state_tool, "artex.env")


def _compose_base(state_tool):
    return ["docker", "--host", common.docker_endpoint(), "compose",
            "-p", COMPOSE_PROJECT, "-f", _state_compose(state_tool),
            "--env-file", _env_path(state_tool)]


def _read_env(path):
    values = {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    except OSError as exc:
        raise common.Failed("env 파일을 읽지 못했습니다 (errno %s)" % exc.errno)
    return values


def _container_id(state_tool, service, digests=None):
    result = common.run_capture(
        _compose_base(state_tool) + ["ps", "-q", service], timeout=60)
    if result["timed_out"] or result["exit"] != 0:
        raise common.Failed("compose ps 실패: %s" % service)
    lines = [line.strip() for line in
             result["out"].decode("utf-8", "replace").splitlines() if line.strip()]
    if len(lines) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", lines[0]):
        raise common.Failed("서비스 컨테이너가 정확히 1개가 아닙니다: %s" % service)
    info = common.docker_json(["container", "inspect", lines[0]], timeout=60)
    if not isinstance(info, list) or len(info) != 1 or not isinstance(info[0], dict):
        raise common.Failed("container inspect 형식이 예상과 다릅니다.")
    item = info[0]
    full = item.get("Id") or ""
    if not re.fullmatch(r"[0-9a-f]{64}", full):
        raise common.Failed("컨테이너 ID 형식 오류")
    labels = (item.get("Config") or {}).get("Labels") or {}
    if labels.get("com.docker.compose.project") != COMPOSE_PROJECT \
            or labels.get("com.docker.compose.service") != service:
        raise common.Failed("소유하지 않은 컨테이너입니다: %s" % service)
    if digests is not None:
        image_ref = item.get("Image") or ""
        try:
            image = common.docker_json(["image", "inspect", image_ref], timeout=60)
        except common.Failed:
            raise common.Failed("실행 중 이미지 확인 실패: %s" % service)
        if not isinstance(image, list) or len(image) != 1 \
                or not isinstance(image[0], dict):
            raise common.Failed("실행 중 이미지 형식 오류: %s" % service)
        allowed = {digests["amd64"]["config"], digests["arm64"]["config"]}
        if image[0].get("Id") not in allowed:
            raise common.Failed("실행 중 이미지가 pin과 다릅니다: %s" % service)
    return full


def _inspect_container(cid):
    data = common.docker_json(["container", "inspect", cid], timeout=60)
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise common.Failed("container inspect 형식이 예상과 다릅니다.")
    return data[0]


def _engine_network(checkout):
    """Discover the actual internal targets engine network (no hardcoded name)."""
    compose = os.path.join(checkout, "infra", "compose.targets.yml")
    result = common.run_capture(
        common.docker_base() + ["compose", "-f", compose, "config", "--format", "json"],
        timeout=60)
    if result["timed_out"] or result["exit"] != 0:
        raise common.Failed("targets compose config 확인 실패")
    try:
        config = json.loads(result["out"].decode("utf-8"))
        networks = config["networks"]
        if set(networks) != {"targets-net"}:
            raise common.Failed("targets compose 망 정책 불일치")
        if not networks["targets-net"].get("name"):
            raise common.Failed("targets 망 이름 없음")
    except (UnicodeError, ValueError, KeyError, TypeError, AttributeError):
        raise common.Failed("targets compose config 형식이 예상과 다릅니다.")
    target = _one_container("juice-shop")
    endpoints = (target.get("NetworkSettings") or {}).get("Networks") or {}
    if not isinstance(endpoints, dict) or len(endpoints) != 1:
        raise common.Failed("target endpoint 확인 실패")
    engine_name = list(endpoints)[0]
    endpoint = endpoints[engine_name]
    if not isinstance(endpoint, dict) \
            or not re.fullmatch(r"[0-9a-f]{64}", endpoint.get("NetworkID") or "") \
            or not re.fullmatch(r"[0-9a-f]{64}", endpoint.get("EndpointID") or ""):
        raise common.Failed("target endpoint ID 형식 오류")
    net = common.docker_json(["network", "inspect", endpoint["NetworkID"]],
                             timeout=60)
    if not isinstance(net, list) or len(net) != 1 or not isinstance(net[0], dict):
        raise common.Failed("network inspect 형식이 예상과 다릅니다.")
    info = net[0]
    if info.get("Name") != engine_name or info.get("Internal") is not True \
            or info.get("Driver") != "bridge":
        raise common.Failed("실제 targets 망이 internal bridge가 아닙니다.")
    members = info.get("Containers") or {}
    member = members.get(target.get("Id")) or {}
    if member.get("EndpointID") != endpoint.get("EndpointID"):
        raise common.Failed("target 망 멤버십 불일치")
    return engine_name


def _one_container(name):
    data = common.docker_json(["container", "inspect", name], timeout=60)
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise common.Failed("container inspect 형식이 예상과 다릅니다: %s" % name)
    return data[0]


def _api(method, path, token, payload):
    """Call the pinned ARTEX API over loopback. Returns parsed JSON.

    Raises Failed with endpoint+status only (no bodies, no secrets).
    """
    url = "http://127.0.0.1:%d%s" % (UI_PORT, path)
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            status = response.status
            raw = response.read(1 << 20)
    except urllib.error.HTTPError as exc:
        raise common.Failed("ARTEX API %s %s -> HTTP %d" % (method, path, exc.code))
    except Exception:
        raise common.Failed("ARTEX API %s %s 호출 실패" % (method, path))
    if status < 200 or status >= 300:
        raise common.Failed("ARTEX API %s %s -> HTTP %d" % (method, path, status))
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise common.Failed("ARTEX API %s %s 응답이 JSON이 아닙니다." % (method, path))
    if not isinstance(data, dict):
        raise common.Failed("ARTEX API %s %s 응답 형식이 예상과 다릅니다." % (method, path))
    return data


def _login(values):
    """Admin auth from private env only. Token stays in memory, never stored."""
    password = values.get("ARTEX_ADMIN_PASSWORD") or ""
    if not password:
        raise common.Prereq("ARTEX_ADMIN_PASSWORD가 비어 있습니다.")
    status = _api("GET", "/api/auth/status", None, None)
    if status.get("initialized") is not True:
        token_value = values.get("ARTEX_SETUP_TOKEN") or ""
        if not token_value:
            raise common.Prereq("초기 설정 토큰이 없습니다 (로그 토큰 수집 금지).")
        _api("POST", "/api/auth/init",
             None, {"password": password, "setup_token": token_value})
    result = _api("POST", "/api/auth/login", None,
                  {"username": "ARTEX", "password": password})
    token = result.get("token")
    if not isinstance(token, str) or not token:
        raise common.Failed("ARTEX 로그인 토큰을 받지 못했습니다.")
    return token


def _gateway_host_ok(raw_url):
    """Approved local LLM gateway endpoints only (no DNS, no network).

    Allowed: loopback/private IP literals, localhost, single-label names,
    *.local, *.internal. Everything else (global IPs, public dotted names)
    is refused as direct arbitrary internet.
    """
    try:
        parts = urllib.parse.urlsplit(raw_url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    host = parts.hostname.lower()
    if host in ("localhost", "localhost.localdomain"):
        return True
    if "@" in (parts.netloc or ""):
        return False
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_loopback or addr.is_private
    except ValueError:
        pass
    if "." not in host:
        return True
    if host.endswith(".local") or host.endswith(".internal"):
        return True
    return False


def _gateway_member(host):
    """Gateway must be a registered member of an internal docker network.

    Loopback/private literals alone are NOT auto-approval: from inside the
    service container, loopback is the container itself. No DNS tricks are
    used here, only docker-inspected membership. Returns the network name.
    """
    lowered = host.lower()
    if lowered in ("localhost", "localhost.localdomain"):
        raise common.Prereq(
            "loopback 게이트웨이는 컨테이너에서 도달 불가: internal망 멤버 endpoint를 등록하십시오.")
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_loopback:
            raise common.Prereq(
                "loopback 게이트웨이는 컨테이너에서 도달 불가: internal망 멤버 endpoint를 등록하십시오.")
    except ValueError:
        pass
    result = common.run_capture(
        common.docker_base() + ["network", "ls", "--format", "{{.Name}}"], timeout=60)
    if result["timed_out"] or result["exit"] != 0:
        raise common.Failed("docker 망 목록 확인 실패")
    names = [line.strip() for line in result["out"].decode("utf-8", "replace").splitlines()
             if line.strip()]
    for name in names:
        try:
            info = common.docker_json(["network", "inspect", name], timeout=60)
        except common.Failed:
            continue
        if not isinstance(info, list) or len(info) != 1 \
                or not isinstance(info[0], dict):
            continue
        if info[0].get("Internal") is not True:
            continue
        members = info[0].get("Containers") or {}
        if not isinstance(members, dict):
            continue
        for _, member in members.items():
            if not isinstance(member, dict):
                continue
            cname = (member.get("Name") or "").lower().lstrip("/")
            ipv4 = (member.get("IPv4Address") or "").split("/")[0].lower()
            if lowered == cname or (ipv4 != "" and lowered == ipv4):
                return info[0].get("Name") or name
    raise common.Prereq(
        "게이트웨이가 internal망 멤버가 아닙니다 (operator 등록 필요): %s" % host)


def _llm_ready(token, values):
    """Explicit provider+model+gateway plus a real connection test."""
    provider = (values.get("ARTEX_LLM_PROVIDER") or "").strip()
    model = (values.get("ARTEX_LLM_MODEL") or "").strip()
    base_url = (values.get("ARTEX_LLM_BASE_URL") or "").strip()
    api_key = (values.get("ANTHROPIC_API_KEY") or "").strip() or \
              (values.get("OPENAI_API_KEY") or "").strip()
    if not provider or not model:
        raise common.Prereq("ARTEX_LLM_PROVIDER/MODEL이 명시되지 않았습니다.")
    if not base_url:
        raise common.Prereq(
            "승인된 로컬 LLM 게이트웨이 endpoint(ARTEX_LLM_BASE_URL)가 필요합니다.")
    if not _gateway_host_ok(base_url):
        raise common.Prereq("게이트웨이 endpoint가 승인된 로컬 범위가 아닙니다.")
    if not api_key:
        raise common.Prereq("게이트웨이 credential이 없습니다.")
    current = _api("GET", "/api/llm", token, None)
    if current.get("configured") is not True:
        raise common.Prereq("서버 LLM이 configured 상태가 아닙니다.")
    for field, want in (("provider", provider), ("model", model),
                        ("base_url", base_url)):
        if not isinstance(current.get(field), str) \
                or current.get(field).strip() != want:
            raise common.Prereq(
                "서버 활성 설정과 운영자 요청 불일치: %s" % field)
    gateway_net = _gateway_member(urllib.parse.urlsplit(base_url).hostname.lower())
    test = _api("POST", "/api/llm/test", token, {
        "provider": provider, "model": model,
        "base_url": base_url, "api_key": api_key,
    })
    if test.get("ok") is not True:
        raise common.Prereq("LLM 연결 테스트 실패 (provider/model/credential 확인 필요).")
    return {"provider": provider, "model": model,
            "latency_ms": test.get("latency_ms"), "gateway_network": gateway_net}


def _pause_task(token, task_id):
    """Stop a task via the verified pause action. Returns (ok, detail).

    Never raises: callers collect the result into rollback failures.
    """
    try:
        _api("POST", "/api/tasks/%s/control" % task_id, token, {"action": "pause"})
    except common.Failed as exc:
        return False, "task pause 실패: %s" % exc
    try:
        verify = _api("GET", "/api/tasks/%s" % task_id, token, None)
    except common.Failed as exc:
        return False, "task 중지 미확인: %s" % exc
    if verify.get("id") != task_id or verify.get("status") != "paused":
        return False, "task 중지 미확인 (paused 아님)"
    return True, "paused"


def _service_digests(service):
    if service == ARTEX_SERVICE:
        return IMAGE_DIGESTS
    return POSTGRES_DIGESTS


def _assert_attachments(state_tool, engine_name, require_engine):
    """Owned containers sit only on internal nets (no hardcoded names).

    postgres: exactly one attachment, internal. artex: one or two
    attachments, every attached net inspected internal:true; with
    require_engine the discovered engine net must be among them. Anything
    else fails. Returns True when the engine attachment is present.
    """
    for service, want in ((POSTGRES_SERVICE, 1), (ARTEX_SERVICE, 2)):
        cid = _container_id(state_tool, service, _service_digests(service))
        info = _inspect_container(cid)
        networks = (info.get("NetworkSettings") or {}).get("Networks") or {}
        names = sorted(networks)
        if service == ARTEX_SERVICE and not require_engine:
            if len(names) not in (1, 2):
                raise common.Failed("승인된 망 구성이 아닙니다: %s" % service)
        elif len(names) != want or (service == ARTEX_SERVICE
                                    and engine_name not in names):
            raise common.Failed("승인된 망 구성이 아닙니다: %s" % service)
        for name in names:
            net = common.docker_json(["network", "inspect", name], timeout=60)
            if not isinstance(net, list) or len(net) != 1 \
                    or not isinstance(net[0], dict) \
                    or net[0].get("Internal") is not True:
                raise common.Failed("비-internal 망 연결이 있습니다: %s" % name)
    try:
        artex = _inspect_container(_container_id(
            state_tool, ARTEX_SERVICE, IMAGE_DIGESTS))
        attached = engine_name in ((artex.get("NetworkSettings") or {}).get("Networks")
                                   or {})
    except common.Failed:
        attached = False
    return attached


def install(ctx):
    """Materialize state compose+env, pull pinned images, enforce exact digests."""
    src = _repo_compose(ctx.checkout)
    dst = _state_compose(ctx.state_tool)
    if os.path.exists(dst) or os.path.exists(_env_path(ctx.state_tool)):
        raise common.Failed("기존 ARTEX state가 있습니다. 삭제는 운영자가 직접 수행하십시오.")
    try:
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o600)
    except OSError as exc:
        raise common.Failed("compose 복사 실패 (errno %s)" % exc.errno)
    try:
        os.makedirs(os.path.join(ctx.state_tool, "data"), mode=0o700, exist_ok=True)
    except OSError as exc:
        raise common.Failed("state dir 생성 실패 (errno %s)" % exc.errno)
    env_text = ENV_TEMPLATE.format(
        pg_password=secrets.token_hex(32),
        setup_token=secrets.token_hex(24),
        admin_password=secrets.token_hex(24))
    common.write_private_file(_env_path(ctx.state_tool), env_text.encode("utf-8"))
    result = common.run_capture(
        _compose_base(ctx.state_tool) + ["pull"], timeout=1800,
        diag_dir=os.path.join(ctx.state_tool, "diagnostics"), diag_tag="pull")
    if result["timed_out"]:
        raise common.Failed("이미지 pull 시간 초과 (diag: %s)" % result["diag_err"])
    if result["exit"] != 0:
        raise common.Failed("이미지 pull 실패 (exit %d, diag: %s)"
                            % (result["exit"], result["diag_err"]))
    observed = {}
    for ref, digests, what in ((IMAGE, IMAGE_DIGESTS, "artex"),
                               (POSTGRES_IMAGE, POSTGRES_DIGESTS, "postgres")):
        image_id, _ = common.assert_exact_image(ref, digests, what)
        observed[ref] = image_id
    receipt = {
        "tool": TOOL, "action": "install", "version": VERSION,
        "image": IMAGE, "images_exact": observed,
        "compose": dst, "env_file": _env_path(ctx.state_tool),
        "digest_note": "tag가 아닌 registry digest exact-match로 강제했습니다.",
        "next": ("env 파일에 LLM provider/model/게이트웨이 endpoint를 운영자가 입력하고, "
                 "로컬 UI /setup 상태를 확인한 뒤 doctor를 실행하십시오."),
    }
    common.write_receipt(
        os.path.join(ctx.state_tool, "install-receipt.json"), receipt)
    print("ARTEX-KO %s install 준비 완료. env: %s" % (VERSION, _env_path(ctx.state_tool)))
    return common.EXIT_OK


def _require_env_ready(state_tool):
    values = _read_env(_env_path(state_tool))
    if not values.get("POSTGRES_PASSWORD"):
        raise common.Prereq("POSTGRES_PASSWORD가 비어 있습니다.")
    return values


def doctor(ctx):
    """Readiness: files, exact images, internal nets, health, auth, LLM test."""
    if not os.path.isfile(_state_compose(ctx.state_tool)):
        raise common.Prereq("ARTEX state compose가 없습니다. 먼저 install을 실행하십시오.")
    if not os.path.isfile(_env_path(ctx.state_tool)):
        raise common.Prereq("ARTEX env 파일이 없습니다. 먼저 install을 실행하십시오.")
    values = _require_env_ready(ctx.state_tool)
    for ref, digests, what in ((IMAGE, IMAGE_DIGESTS, "artex"),
                               (POSTGRES_IMAGE, POSTGRES_DIGESTS, "postgres")):
        try:
            common.assert_exact_image(ref, digests, what)
        except common.Failed as exc:
            raise common.Prereq("이미지 pin 불일치: %s" % exc)
    engine_name = _engine_network(ctx.checkout)
    status = {"images_exact": True, "targets_network": engine_name}
    try:
        pg_id = _container_id(ctx.state_tool, POSTGRES_SERVICE, POSTGRES_DIGESTS)
        pg = _inspect_container(pg_id)
        health = ((pg.get("State") or {}).get("Health") or {}).get("Status")
        status["postgres"] = health or "unknown"
    except common.Failed:
        status["postgres"] = "not-running"
    if status["postgres"] != "healthy":
        raise common.Prereq("postgres가 healthy가 아닙니다: %s" % status["postgres"])
    try:
        sock = socket.create_connection(("127.0.0.1", UI_PORT), timeout=10)
        sock.close()
    except OSError:
        raise common.Prereq("로컬 UI 포트(%d)가 닫혀 있습니다." % UI_PORT)
    status["ui_tcp"] = "open"
    token = _login(values)
    health = _api("GET", "/api/health", token, None)
    if health.get("ok") is not True:
        raise common.Prereq("ARTEX health가 ok가 아닙니다.")
    version = health.get("version")
    if not isinstance(version, str) or not version:
        raise common.Prereq("ARTEX 버전을 확인하지 못했습니다.")
    status["server_version"] = version
    llm = _llm_ready(token, values)
    status["llm"] = {"provider": llm["provider"], "model": llm["model"],
                     "latency_ms": llm.get("latency_ms")}
    attached = _assert_attachments(ctx.state_tool, engine_name, False)
    status["attachments"] = "internal-only"
    status["engine_attached"] = bool(attached)
    if not attached:
        raise common.Prereq("targets 망 연결이 없습니다 (run에서 연결 후 재확인).")
    print("ARTEX-KO doctor: %s" % json.dumps(status, ensure_ascii=False, sort_keys=True))
    return common.EXIT_OK


def run(ctx):
    """Create one authenticated scoped practice task for juice-shop:3000.

    Intercept allow rule rides inside the create body (deny-by-default, no
    post-create race) plus a scope record. Failures after creation pause the
    task and roll back owned attachments; state DB is never touched.
    """
    if ctx.target is None:
        raise common.Refused("ARTEX run에는 --target <allowlist URL>이 필요합니다.")
    _, host_port, origin = common.check_target_url(ctx.target)
    if host_port != common.EXECUTABLE_HOST_PORT:
        raise common.Refused("실제 실행 대상은 juice-shop:3000뿐입니다.")
    if not os.path.isfile(_state_compose(ctx.state_tool)):
        raise common.Prereq("ARTEX state가 없습니다. 먼저 install을 실행하십시오.")
    if not os.path.isfile(_env_path(ctx.state_tool)):
        raise common.Prereq("ARTEX env 파일이 없습니다. 먼저 install을 실행하십시오.")
    values = _require_env_ready(ctx.state_tool)
    for ref, digests, what in ((IMAGE, IMAGE_DIGESTS, "artex"),
                               (POSTGRES_IMAGE, POSTGRES_DIGESTS, "postgres")):
        try:
            common.assert_exact_image(ref, digests, what)
        except common.Failed as exc:
            raise common.Prereq("이미지 pin 불일치: %s" % exc)
    up = common.run_capture(
        _compose_base(ctx.state_tool) + ["up", "-d"], timeout=600,
        diag_dir=os.path.join(ctx.state_tool, "diagnostics"), diag_tag="up")
    if up["timed_out"]:
        raise common.Failed("compose up 시간 초과 (diag: %s)" % up["diag_err"])
    if up["exit"] != 0:
        raise common.Failed("compose up 실패 (exit %d, diag: %s)"
                            % (up["exit"], up["diag_err"]))
    pg_id = _container_id(ctx.state_tool, POSTGRES_SERVICE, POSTGRES_DIGESTS)
    healthy = False
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        pg = _inspect_container(pg_id)
        if ((pg.get("State") or {}).get("Health") or {}).get("Status") == "healthy":
            healthy = True
            break
        time.sleep(5)
    if not healthy:
        raise common.Failed("postgres healthy 상태를 확인하지 못했습니다.")
    artex_id = _container_id(ctx.state_tool, ARTEX_SERVICE, IMAGE_DIGESTS)
    engine_name = _engine_network(ctx.checkout)
    attached_by_us = False
    net = common.docker_json(["network", "inspect", engine_name], timeout=60)
    if not isinstance(net, list) or len(net) != 1 or not isinstance(net[0], dict):
        raise common.Failed("network inspect 형식이 예상과 다릅니다.")
    members = net[0].get("Containers") or {}
    if artex_id not in members:
        attach = common.run_capture(
            common.docker_base() + ["network", "connect", engine_name, artex_id],
            timeout=120)
        if attach["timed_out"] or attach["exit"] != 0:
            raise common.Failed("targets 망 연결 실패")
        attached_by_us = True
    _assert_attachments(ctx.state_tool, engine_name, True)
    if ctx.stop_services:
        return _lifecycle_stop(ctx, values, engine_name)
    token = None
    task_id = None
    try:
        token = _login(values)
        health = _api("GET", "/api/health", token, None)
        if health.get("ok") is not True:
            raise common.Failed("ARTEX health가 ok가 아닙니다.")
        # Version is recorded, not exact-matched: upstream default BuildVersion
        # is "dev" and the release-injected value is unverified from source.
        # Exactness is governed by the digest-pinned image instead.
        version = health.get("version")
        if not isinstance(version, str) or not version:
            raise common.Failed("ARTEX 버전을 확인하지 못했습니다.")
        llm = _llm_ready(token, values)
        task = _api("POST", "/api/tasks", token, {
            "description": "security-lab scoped practice",
            "goal": origin,
            "timeout_seconds": common.SCAN_TIMEOUT_SEC,
            "intercept_rules": [{
                "enabled": True,
                "action": "allow",
                "kind": "exact_domain",
                "pattern": "juice-shop",
                "note": "security-lab allowlist",
            }],
        })
        task_id = task.get("id")
        if not isinstance(task_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", task_id):
            raise common.Failed("task 생성 응답 id가 예상 형식이 아닙니다.")
        _api("POST", "/api/tasks/%s/scope" % task_id, token, {
            "kind": "keyword",
            "value": host_port,
            "reason": "security-lab allowlist scope",
        })
        verify = _api("GET", "/api/tasks/%s" % task_id, token, None)
        if verify.get("id") != task_id:
            raise common.Failed("task 확인 응답 id 불일치")
    except KeyboardInterrupt:
        _rollback_owned(token, task_id, attached_by_us, artex_id, engine_name)
        raise
    except (common.Failed, common.Prereq, common.Refused) as exc:
        problems = ["primary: %s" % exc]
        problems.extend(_rollback_owned(token, task_id, attached_by_us,
                                        artex_id, engine_name))
        raise common.Failed("실패 후 롤백: %s" % " | ".join(problems))
    receipt = {
        "tool": TOOL, "action": "run", "version": VERSION,
        "target_origin": origin, "target_host_port": host_port,
        "task_id": task_id, "task_status": verify.get("status", "unknown"),
        "server_version": str(health.get("version", "unknown")),
        "llm": {"provider": llm["provider"], "model": llm["model"]},
        "network": engine_name, "lifecycle": "persistent-explicit",
        "note": "작업은 서버에서 자율 실행됩니다. 완료 판정은 별도 확인이 필요합니다.",
    }
    path = os.path.join(ctx.state_tool, "run-receipt.json")
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError as exc:
        raise common.Failed("기존 run receipt 교체 실패 (errno %s)" % exc.errno)
    common.write_receipt(path, receipt)
    print("ARTEX-KO scoped task 생성: id=%s target=%s" % (task_id, origin))
    return common.EXIT_OK


def _rollback_owned(token, task_id, attached_by_us, artex_id, engine_name):
    """Roll back only this call's owned mutations. Returns failure causes.

    Each step runs in its own independent try. State DB, volumes, and
    unrelated resources are never touched.
    """
    problems = []
    if task_id is not None and token is not None:
        try:
            ok, detail = _pause_task(token, task_id)
        except Exception as exc:
            ok, detail = False, "pause exception: %s" % type(exc).__name__
        if not ok:
            problems.append(detail)
    if attached_by_us:
        if not _detach(artex_id, engine_name):
            problems.append("targets망 detach 미확인")
    return problems


def _lifecycle_stop(ctx, values, engine_name):
    """Explicit stop entrypoint: no new task is created.

    Verifies the privately stored owned task/project, pauses the task with
    upstream-confirmed paused state, brings services down, verifies cleanup,
    and keeps volumes/state. Any failure is nonzero; nothing is hidden.
    """
    receipt_path = os.path.join(ctx.state_tool, "run-receipt.json")
    if not os.path.isfile(receipt_path):
        raise common.Prereq("중지할 stored owned task가 없습니다.")
    try:
        with open(receipt_path, "r", encoding="utf-8") as handle:
            stored = json.load(handle)
    except (OSError, ValueError):
        raise common.Prereq("stored receipt를 읽지 못했습니다.")
    task_id = stored.get("task_id")
    if not isinstance(task_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", task_id):
        raise common.Prereq("stored task id가 예상 형식이 아닙니다.")
    for ref, digests, what in ((IMAGE, IMAGE_DIGESTS, "artex"),
                               (POSTGRES_IMAGE, POSTGRES_DIGESTS, "postgres")):
        try:
            common.assert_exact_image(ref, digests, what)
        except common.Failed as exc:
            raise common.Prereq("이미지 pin 불일치: %s" % exc)
    _container_id(ctx.state_tool, ARTEX_SERVICE, IMAGE_DIGESTS)
    _container_id(ctx.state_tool, POSTGRES_SERVICE, POSTGRES_DIGESTS)
    token = _login(values)
    ok, detail = _pause_task(token, task_id)
    if not ok:
        raise common.Failed("소유 task 중지 미확인: %s" % detail)
    down = common.run_capture(
        _compose_base(ctx.state_tool) + ["down"], timeout=300,
        diag_dir=os.path.join(ctx.state_tool, "diagnostics"), diag_tag="down")
    if down["timed_out"] or down["exit"] != 0:
        raise common.Failed("lifecycle stop 실패 (diag: %s)" % down["diag_err"])
    for service in (ARTEX_SERVICE, POSTGRES_SERVICE):
        left = common.run_capture(
            _compose_base(ctx.state_tool) + ["ps", "-q", service], timeout=60)
        if left["timed_out"] or left["exit"] != 0:
            raise common.Failed("stop 후 잔류 확인 실패: %s" % service)
        if left["out"].strip() != b"":
            raise common.Failed("stop 후 컨테이너 잔류: %s" % service)
    stop_receipt = {
        "tool": TOOL, "action": "stop", "version": VERSION,
        "task_id": task_id, "task_stop": "paused-confirmed",
        "lifecycle": "stopped-volumes-kept",
        "note": "pgdata 볼륨과 state 파일은 유지됩니다.",
    }
    path = os.path.join(ctx.state_tool, "stop-receipt.json")
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError as exc:
        raise common.Failed("기존 stop receipt 교체 실패 (errno %s)" % exc.errno)
    common.write_receipt(path, stop_receipt)
    print("ARTEX-KO lifecycle stop 완료: task=%s paused 확인, 서비스 종료" % task_id)
    return common.EXIT_OK


def _detach(artex_id, engine_name):
    """Best-effort detach of our runtime attachment. Returns True when gone."""
    try:
        common.run_capture(
            common.docker_base() + ["network", "disconnect", engine_name, artex_id],
            timeout=120)
    except common.Failed:
        return False
    try:
        net = common.docker_json(["network", "inspect", engine_name], timeout=60)
        members = net[0].get("Containers") or {}
        return artex_id not in members
    except (common.Failed, IndexError, KeyError, TypeError, AttributeError):
        return False
