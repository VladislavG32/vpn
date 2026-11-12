#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Запустите через sudo bash.' >&2; exit 1; }
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
source "$ROOT/configs/firewall.sh"
source "$ROOT/configs/tuning.sh"
[[ ! -L data ]] || { echo 'data must be a real directory' >&2; exit 1; }
install -d -m 700 data data/generations data/backups
chmod 700 data
exec 9>data/.lock
flock -x 9
export AWG_PORT=51820
export VPN_GENERATION=current
export VPN_TCP_CC
VPN_TCP_CC=$(vpn_tcp_cc)
if [[ -f data/current/state.json ]]; then
    AWG_PORT=$(python3 configs/render.py port)
fi
compose() {
    local profile=()
    if [[ -f data/portal/enabled ]]; then profile=(--profile portal); fi
    docker compose -f "$ROOT/docker-compose.yml" "${profile[@]}" "$@"
}
apply_candidate() {
    local candidate=$1 previous=''
    [[ $candidate == generations/* && $candidate != *..* ]] || return 1
    previous=$(readlink data/current || true)
    # No network/IP conflicts with live services during validation.
    local image=private-vpn:2026-11-12
    docker run --rm --network none --read-only --cap-drop ALL \
        --mount "type=bind,source=$ROOT/data/$candidate/xray.json,target=/etc/xray/config.json,readonly" \
        --entrypoint xray "$image" run -test -c /etc/xray/config.json
    docker run --rm --network none --read-only --cap-drop ALL \
        --mount "type=bind,source=$ROOT/data/$candidate/dnscrypt-proxy.toml,target=/etc/dnscrypt/config.toml,readonly" \
        --mount "type=bind,source=$ROOT/data/$candidate/blocked-domains.txt,target=/etc/dnscrypt/blocked-domains.txt,readonly" \
        --entrypoint dnscrypt-proxy "$image" -check -config /etc/dnscrypt/config.toml
    docker run --rm --network none --read-only --cap-drop ALL --cap-add NET_ADMIN \
        --device /dev/net/tun --tmpfs /run --tmpfs /tmp \
        --mount "type=bind,source=$ROOT/data/$candidate/awg.conf,target=/etc/awg/server.conf,readonly" \
        --entrypoint sh "$image" -ec '
      amneziawg-go awgtest
      trap "ip link del awgtest 2>/dev/null || true" EXIT
      i=0; until [ -S /run/amneziawg/awgtest.sock ]; do i=$((i+1)); [ "$i" -lt 50 ]; sleep 0.1; done
      awg setconf awgtest "$1"
    ' sh /etc/awg/server.conf
    local candidate_port
    candidate_port=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["port"])' "data/$candidate/state.json")
    vpn_firewall_apply "$candidate_port" "${PORTAL_ENABLED:-1}"
    ln -sfn "$candidate" data/.current-next
    mv -Tf data/.current-next data/current
    ln -sfn current/output data/output
    export VPN_GENERATION=current
    AWG_PORT=$(python3 configs/render.py port)
    if ! compose up -d --force-recreate --wait --wait-timeout 180; then
        echo 'Startup failed; rolling back configuration.' >&2
        if [[ -n $previous ]]; then
            ln -sfn "$previous" data/.current-rollback
            mv -Tf data/.current-rollback data/current
            AWG_PORT=$(python3 configs/render.py port)
            compose up -d --force-recreate --wait --wait-timeout 180 || true
        else
            compose down || true
            rm -f data/current data/output
        fi
        return 1
    fi
    python3 configs/render.py show
}
