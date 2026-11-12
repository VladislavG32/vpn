#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/configs/common.sh"
[[ -f data/current/state.json ]] || { echo 'Run install.sh first.' >&2; exit 1; }
portal=0
if [[ -f data/portal/enabled || -f data/portal/requested ]]; then portal=1; fi
vpn_firewall_apply "$AWG_PORT" "$portal"
