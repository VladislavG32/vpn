#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/configs/common.sh"
[[ -f data/current/state.json ]] || { echo 'Сначала выполните install.sh.' >&2; exit 1; }
CERTBOT_IMAGE=certbot/certbot:v5.4.0
certbot_run() {
    docker run --rm -p 0.0.0.0:80:80 \
        --mount "type=bind,source=$ROOT/data/portal/acme,target=/etc/letsencrypt" \
        --mount "type=bind,source=$ROOT/data/portal/work,target=/var/lib/letsencrypt" \
        --mount "type=bind,source=$ROOT/data/portal/logs,target=/var/log/letsencrypt" \
        "$CERTBOT_IMAGE" "$@"
}
copy_certificate() {
    local source=data/portal/acme/live/vpn-portal
    install -d -m 750 -g 101 data/portal/tls
    for name in fullchain.pem privkey.pem; do
        install -m 640 -g 101 "$source/$name" "data/portal/tls/$name.next"
        mv -f "data/portal/tls/$name.next" "data/portal/tls/$name"
    done
}
case ${1:-enable} in
    enable)
        [[ $ROOT =~ ^/[a-zA-Z0-9_./-]+$ ]] || { echo 'Use /opt/vpn or another path without spaces.' >&2; exit 1; }
        echo 'Для страниц нужны открытые 80/tcp (ACME) и 2087/tcp (HTTPS).'
        install -d -m 700 data/portal data/portal/acme data/portal/work data/portal/logs
        address=$(python3 configs/render.py endpoint)
        if python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$address" 2>/dev/null; then
            identifier=(--ip-address "$address")
        else
            identifier=(-d "$address")
        fi
        renewal=(--keep-until-expiring)
        if [[ -f data/portal/address && $(cat data/portal/address) != "$address" ]]; then
            renewal=(--force-renewal)
        fi
        certbot_run certonly --standalone --non-interactive --agree-tos \
            --register-unsafely-without-email --preferred-profile shortlived \
            --cert-name vpn-portal --key-type ecdsa "${renewal[@]}" "${identifier[@]}"
        copy_certificate
        # Render pages and upgrade existing users with persistent random tokens.
        candidate=$(python3 configs/render.py candidate denis,vlad,liza,parents,router,svyat,sveta,ruslan '' refresh)
        apply_candidate "$candidate"
        # Activate only after successful generation and certificate issuance.
        touch data/portal/enabled
        printf '%s\n' "$address" > data/portal/address
        compose up -d --no-deps --wait --wait-timeout 90 portal
        printf '[Unit]\nDescription=Renew VPN portal certificate\nAfter=docker.service\n[Service]\nType=oneshot\nExecStart=/bin/bash %s/portal.sh renew\nTimeoutStartSec=300\n' "$ROOT" > /etc/systemd/system/private-vpn-portal-renew.service
        printf '[Unit]\nDescription=Check short-lived VPN certificate twice daily\n[Timer]\nOnBootSec=10min\nOnUnitActiveSec=12h\nRandomizedDelaySec=30min\nPersistent=true\n[Install]\nWantedBy=timers.target\n' > /etc/systemd/system/private-vpn-portal-renew.timer
        systemctl daemon-reload
        systemctl enable --now private-vpn-portal-renew.timer
        python3 configs/render.py links
        ;;
    renew)
        [[ -f data/portal/enabled ]] || exit 0
        certbot_run renew --cert-name vpn-portal --non-interactive --quiet
        openssl x509 -checkend 86400 -noout -in data/portal/acme/live/vpn-portal/fullchain.pem
        copy_certificate
        compose exec -T portal nginx -t
        compose exec -T portal nginx -s reload
        ;;
    links) python3 configs/render.py links ;;
    *) echo 'Usage: portal.sh [enable|renew|links]' >&2; exit 1 ;;
esac
