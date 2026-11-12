#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/configs/common.sh"
case ${1:-status} in
    status)
        compose ps
        compose exec -T dnscrypt sh -ec "dig +time=3 +tries=1 @127.0.0.1 example.com | grep 'status: NOERROR'"
        compose exec -T xray sh -ec 'nc -z 127.0.0.1 443 && nc -z 127.0.0.1 8443'
        compose exec -T awg awg show awg0 latest-handshakes
        ;;
    restart) compose up -d --force-recreate --wait --wait-timeout 180 ;;
    heal)
        # Restart unhealthy/exited services without exposing a Docker socket to containers.
        for service in dnscrypt xray awg portal; do
            id=$(compose ps -a -q "$service")
            [[ -n $id ]] || continue
            state=$(docker inspect --format '{{.State.Status}}:{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$id")
            case $state in
                running:unhealthy|exited:*|dead:*) compose restart "$service" ;;
            esac
        done
        ;;
    logs) compose logs --tail=100 "${2:-xray}" ;;
    backup)
        [[ -L data/current ]] || { echo 'No active configuration' >&2; exit 1; }
        file="data/backups/vpn-$(date -u +%Y%m%dT%H%M%S)-$RANDOM.tar.gpg"
        export GPG_TTY; GPG_TTY=$(tty)
        # Archive active generation only, preserving the relative symlink layout.
        targets=(current "$(readlink data/current)")
        if [[ -d data/portal ]]; then targets+=(portal); fi
        tar -C data -czf - "${targets[@]}" |
            gpg --symmetric --cipher-algo AES256 --output "$file.part"
        mv "$file.part" "$file"
        echo "$ROOT/$file"
        ;;
    migrate)
        [[ $# == 2 ]] || { echo 'manage.sh migrate NEW_PUBLIC_IP_OR_DOMAIN' >&2; exit 1; }
        export ENDPOINT=$2
        candidate=$(python3 configs/render.py candidate denis,vlad,liza,parents,router,svyat,sveta,ruslan '' refresh)
        apply_candidate "$candidate"
        if [[ -f data/portal/enabled ]]; then
            flock -u 9
            bash portal.sh enable
        else
            python3 configs/render.py links
        fi
        ;;
    *) echo 'Usage: manage.sh [status|restart|logs SERVICE|backup|migrate ENDPOINT|heal]' >&2; exit 1 ;;
esac
