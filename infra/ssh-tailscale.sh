#!/usr/bin/env bash
# infra/ssh-tailscale.sh
#
# --ssh-executable adapter for infra/deploy.py: drives `tailscale ssh`
# instead of plain OpenSSH, for VMs where Tailscale SSH -- not a classic
# authorized_keys entry -- is the trust/auth layer (host-key check and
# session approval happen through the Tailscale coordination server).
#
# infra/deploy.py always builds its ssh argv as:
#   <executable> -o <k=v> -o <k=v> -o <k=v> -p <port> [-J <jump>]
#               [-i <identity>] [-F <ssh_config>] <target> <remote-command>
# None of -o/-p/-J/-i/-F apply to Tailscale's own transport and auth, so
# this adapter discards them (and any value that follows) and forwards
# only <target> <remote-command> to `tailscale ssh`.
#
# Resolution order for the Tailscale binary:
#   1. $SECURITY_LAB_TAILSCALE_BIN (manual override / tests)
#   2. `tailscale` on PATH (native Linux install)
#   3. the default Windows GUI client path, for WSL setups that reach a
#      Tailscale node via the Windows host's tailscaled
#
# Usage (see infra/deploy.py --ssh-executable):
#   python3 infra/deploy.py check --target user@<tailscale-ip-or-name> \
#       --ssh-executable infra/ssh-tailscale.sh
#
# This script performs no auth or host-key handling itself; the exit
# code and all security properties come from `tailscale ssh` alone.
set -euo pipefail

resolve_tailscale() {
  if [[ -n "${SECURITY_LAB_TAILSCALE_BIN:-}" ]]; then
    if [[ -x "${SECURITY_LAB_TAILSCALE_BIN}" ]]; then
      printf '%s\n' "$SECURITY_LAB_TAILSCALE_BIN"
      return 0
    fi
    echo "ssh-tailscale: \$SECURITY_LAB_TAILSCALE_BIN is set but not executable: $SECURITY_LAB_TAILSCALE_BIN" >&2
    return 1
  fi
  if command -v tailscale >/dev/null 2>&1; then
    command -v tailscale
    return 0
  fi
  local win_default="/mnt/c/Program Files/Tailscale/tailscale.exe"
  if [[ -x "$win_default" ]]; then
    printf '%s\n' "$win_default"
    return 0
  fi
  echo "ssh-tailscale: no tailscale binary found (checked \$SECURITY_LAB_TAILSCALE_BIN, PATH, $win_default)" >&2
  return 1
}

TAILSCALE_BIN="$(resolve_tailscale)"

target=""
rest=()
skip_next=0
for arg in "$@"; do
  if [[ $skip_next -eq 1 ]]; then
    skip_next=0
    continue
  fi
  case "$arg" in
    -o|-p|-J|-i|-F)
      skip_next=1
      ;;
    -*)
      ;;
    *)
      if [[ -z "$target" ]]; then
        target="$arg"
      else
        rest+=("$arg")
      fi
      ;;
  esac
done

if [[ -z "$target" ]]; then
  echo "ssh-tailscale: no SSH target found in arguments" >&2
  exit 2
fi

exec "$TAILSCALE_BIN" ssh "$target" "${rest[@]}"
