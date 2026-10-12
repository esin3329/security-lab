#!/usr/bin/env python3
"""Tool install/doctor/launch controller for the server Ubuntu VM lab.

Runs ON the server VM against its local Linux/Docker engine only.
No dev-PC/WSL execution, no remote engines, no SSH deployment here;
actual install/game/tool runs happen only after the parent verifies
server-VM auth/identity. SSH route and credentials are out of scope:
this controller never collects or copies private keys.

Usage:
    python3 tools/lab/practice.py <install|doctor|run> --tool <rea|artex|strix|pwn> [options]

Common options:
    --target URL            allowlisted http(s) URL (strix/artex run)
    --artifact PATH         authorized local file/dir (rea run)
    --provider ID           REA native provider (hopper|ghidra|ida)
    --repeat-index 1..3     strix run repeat number (default 1)
    --metrics-record PATH   human-confirmed 7-metric JSON (strix record flow)
    --jsonl-out PATH        metrics JSONL destination (with --metrics-record)
    --meta-out PATH         safe metadata sidecar (new file only)
    --state-dir PATH        private operator state root (default ~/.security-lab)
    --with-ghidra           REA install: also install pinned Ghidra 12.1.4
    --stop-services         ARTEX run: do NOT create a task; pause the privately
                            stored owned task (upstream-confirmed) + compose down.
                            Volumes/state kept. Default creates the scoped task
                            and leaves services persistent-explicit

Exit codes: 0 ok/clean, 2 usage/scope refusal, 3 missing prerequisite
(fail-closed, precise), 4 action failed (cause preserved, no secrets),
10 scan timeout, 12 tool-reported findings (strix), 13 post/record failure
after an ok scan, 130 interrupted.

Secrets live only in operator env or 0600/0700 private state outside Git.
Stdout carries safe metadata only: no flags/keys/raw tool output.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lab import artex_tool  # noqa: E402
from lab import common  # noqa: E402
from lab import pwn_tool  # noqa: E402
from lab import rea_tool  # noqa: E402
from lab import strix_tool  # noqa: E402

TOOLS = {
    "rea": rea_tool,
    "artex": artex_tool,
    "strix": strix_tool,
    "pwn": pwn_tool,
}


class Context:
    def __init__(self, args, checkout, state_root, state_tool):
        self.args = args
        self.checkout = checkout
        self.state_root = state_root
        self.state_tool = state_tool
        self.target = args.target
        self.artifact = args.artifact
        self.provider = args.provider
        self.repeat_index = args.repeat_index
        self.metrics_record = args.metrics_record
        self.jsonl_out = args.jsonl_out
        self.meta_out = args.meta_out
        self.strix_args = None
        self.with_ghidra = args.with_ghidra
        self.stop_services = args.stop_services


def build_parser():
    parser = argparse.ArgumentParser(
        description="Owned-lab tool installer/doctor/launcher.",
        allow_abbrev=False)
    parser.add_argument("action", choices=("install", "doctor", "run"))
    parser.add_argument("--tool", required=True,
                        choices=("rea", "artex", "strix", "pwn"))
    parser.add_argument("--target", default=None)
    parser.add_argument("--artifact", default=None)
    parser.add_argument("--provider", default=None)
    parser.add_argument("--repeat-index", type=int, default=1)
    parser.add_argument("--metrics-record", default=None)
    parser.add_argument("--jsonl-out", default=None)
    parser.add_argument("--meta-out", default=None)
    parser.add_argument("--state-dir", default=None)
    parser.add_argument("--with-ghidra", action="store_true",
                        help="REA install에 pinned Ghidra 12.1.4를 함께 설치")
    parser.add_argument("--stop-services", action="store_true",
                        help="ARTEX run 완료 후 task 일시중지+서비스 종료(볼륨/state 유지)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        common.require_server_linux()
    except common.Refused as exc:
        common.eprint("[거부] %s" % exc)
        return common.EXIT_REFUSED
    if args.action == "install" and (
            args.target is not None or args.artifact is not None):
        common.eprint("install에는 --target/--artifact을 사용할 수 없습니다.")
        return common.EXIT_REFUSED
    checkout = common.checkout_root()
    try:
        state_root = common.state_root(args.state_dir)
        state_tool = common.tool_state(state_root, args.tool)
    except common.Refused as exc:
        common.eprint("[거부] %s" % exc)
        return common.EXIT_REFUSED
    except common.Failed as exc:
        common.eprint("[실패] %s" % exc)
        return common.EXIT_FAILED
    ctx = Context(args, checkout, state_root, state_tool)
    module = TOOLS[args.tool]
    try:
        action = getattr(module, args.action)
    except AttributeError:
        common.eprint("내부 오류: 알 수 없는 action")
        return common.EXIT_FAILED
    try:
        return action(ctx)
    except common.Refused as exc:
        common.eprint("[거부] %s" % exc)
        return common.EXIT_REFUSED
    except common.Prereq as exc:
        common.eprint("[선행조건 미충족] %s" % exc)
        return common.EXIT_PREREQ
    except common.Failed as exc:
        common.eprint("[실패] %s" % exc)
        return common.EXIT_FAILED
    except KeyboardInterrupt:
        common.eprint("[중단] 사용자 인터럽트")
        return 130


if __name__ == "__main__":
    sys.exit(main())
