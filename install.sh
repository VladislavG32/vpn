#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'sudo bash install.sh' >&2; exit 1; }
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
source /etc/os-release
[[ $ID == ubuntu && ( $VERSION_ID == 22.04 || $VERSION_ID == 24.04 ) ]] || {
    echo 'Supported: Ubuntu 22.04/24.04' >&2; exit 1;
}
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y
apt-get install -y ca-certificates curl gnupg git python3 python3-cryptography qrencode dnsutils openssl util-linux iptables
if ! command -v docker >/dev/null; then
    install -m 0755 -d /etc/apt/keyrings
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' "$(dpkg --print-architecture)" "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
docker compose version >/dev/null || {
    echo 'Install Docker Compose plugin from download.docker.com, then retry.' >&2; exit 1;
}
version=$(docker compose version --short | sed 's/^v//')
dpkg --compare-versions "$version" ge 2.33.1 || { echo 'Compose >= 2.33.1 required' >&2; exit 1; }
systemctl enable --now docker
[[ -c /dev/net/tun ]] || { modprobe tun; }
[[ -c /dev/net/tun ]] || { echo 'VPS must provide /dev/net/tun (KVM recommended)' >&2; exit 1; }
bash setup.sh
# Systemd entry points are reproducible; all VPN credentials remain under ./data.
root_path=$(pwd)
[[ $root_path =~ ^/[a-zA-Z0-9_./-]+$ ]] || {
    echo 'Use an installation path without spaces/special characters, e.g. /opt/vpn' >&2; exit 1;
}
printf '[Unit]\nDescription=VPN health recovery\nAfter=docker.service\n[Service]\nType=oneshot\nExecStart=/bin/bash %s/manage.sh heal\nTimeoutStartSec=240\n' "$root_path" > /etc/systemd/system/private-vpn-health.service
printf '[Unit]\nDescription=Check VPN services every minute\n[Timer]\nOnBootSec=120\nOnUnitActiveSec=60\n[Install]\nWantedBy=timers.target\n' > /etc/systemd/system/private-vpn-health.timer
systemctl daemon-reload
systemctl enable --now private-vpn-health.timer
source configs/firewall.sh
vpn_firewall_install_service "$root_path"
if [[ -f /var/run/reboot-required ]]; then
    echo 'Kernel/system update requires reboot. Reboot manually, then run: sudo bash manage.sh status'
fi
if [[ ${PORTAL_ENABLED:-1} == 1 ]]; then
    if ! bash portal.sh enable; then
        echo 'VPN установлен; веб-страницы пока не включились. Причина и путь к диагностике указаны выше.' >&2
    fi
fi
