#!/usr/bin/env bash
# Add project-specific IPv4 allowances without changing SSH or global policies.
vpn_firewall_apply() {
    local udp_port=$1 portal=${2:-1} port
    [[ $udp_port =~ ^[0-9]+$ && $udp_port -ge 1024 && $udp_port -le 65535 ]] || {
        echo 'Invalid AmneziaWG UDP port' >&2; return 1;
    }
    command -v iptables >/dev/null || { echo 'Install iptables, then retry install.sh.' >&2; return 1; }
    local tcp_ports=(443 8443)
    if [[ $portal == 1 || -f data/portal/enabled ]]; then tcp_ports+=(80 2087); fi
    # Persist allowances in UFW when it is already enabled; never enable/reset it.
    if command -v ufw >/dev/null && LC_ALL=C ufw status | grep -q '^Status: active'; then
        for port in "${tcp_ports[@]}"; do ufw allow "$port/tcp" comment 'private-vpn'; done
        ufw allow "$udp_port/udp" comment 'private-vpn'
    fi
    # Docker manages forwarding/NAT for its published ports. This INPUT chain
    # also covers docker-proxy and host-side listeners with restrictive INPUT.
    if ! iptables -w 5 -S PRIVATE-VPN-IN >/dev/null 2>&1; then
        iptables -w 5 -N PRIVATE-VPN-IN
    fi
    # Only our chain is rebuilt, removing obsolete project ports.
    iptables -w 5 -F PRIVATE-VPN-IN
    for port in "${tcp_ports[@]}"; do
        iptables -w 5 -A PRIVATE-VPN-IN -p tcp --dport "$port" -j ACCEPT
    done
    iptables -w 5 -A PRIVATE-VPN-IN -p udp --dport "$udp_port" -j ACCEPT
    iptables -w 5 -A PRIVATE-VPN-IN -j RETURN
    if ! iptables -w 5 -C INPUT -j PRIVATE-VPN-IN >/dev/null 2>&1; then
        iptables -w 5 -I INPUT 1 -j PRIVATE-VPN-IN
    fi
    echo "Локальный firewall настроен: TCP ${tcp_ports[*]}; UDP $udp_port."
}

vpn_firewall_install_service() {
    local root_path=$1
    [[ $root_path =~ ^/[a-zA-Z0-9_./-]+$ ]] || {
        echo 'Use a path without spaces, e.g. /opt/vpn.' >&2; return 1;
    }
    printf '[Unit]\nDescription=Restore VPN firewall allowances\nAfter=docker.service network-online.target ufw.service\nWants=docker.service network-online.target\n[Service]\nType=oneshot\nExecStart=/bin/bash %s/firewall.sh\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n' "$root_path" > /etc/systemd/system/private-vpn-firewall.service
    systemctl daemon-reload
    systemctl enable private-vpn-firewall.service
}
