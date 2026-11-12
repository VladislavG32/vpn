#!/usr/bin/env bash
# Use only features supplied by the VPS kernel; do not replace kernels/qdiscs.
vpn_tcp_cc() {
    local current
    current=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
    if [[ $current =~ ^[a-z0-9_-]+$ ]]; then printf '%s\n' "$current"; else echo cubic; fi
}

vpn_tune_network() {
    local config_file=${1:-/etc/sysctl.d/90-private-vpn.conf}
    local tuning_dir=${2:-data/tuning} key value available
    local settings=()
    install -d -m 700 "$tuning_dir"
    if [[ ! -f $tuning_dir/original.conf ]]; then
        : > "$tuning_dir/original.conf"
        for key in net.core.default_qdisc net.ipv4.tcp_congestion_control net.ipv4.tcp_mtu_probing; do
            if value=$(sysctl -n "$key" 2>/dev/null); then
                printf '%s = %s\n' "$key" "$value" >> "$tuning_dir/original.conf"
            fi
        done
        chmod 600 "$tuning_dir/original.conf"
    fi
    if command -v modprobe >/dev/null; then
        modprobe tcp_bbr 2>/dev/null || true
        modprobe sch_fq 2>/dev/null || true
        # Optional existing module. No downloads, DKMS installation or SYS_MODULE in containers.
        modprobe amneziawg 2>/dev/null || true
    fi
    available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
    if [[ " $available " == *' bbr '* ]]; then
        if sysctl -q -w net.core.default_qdisc=fq; then
            settings+=('net.core.default_qdisc = fq')
            if sysctl -q -w net.ipv4.tcp_congestion_control=bbr; then
                settings+=('net.ipv4.tcp_congestion_control = bbr')
            else
                echo 'BBR недоступен для настройки на этом VPS; текущий TCP-алгоритм сохранен.' >&2
            fi
        else
            echo 'fq недоступен; настройка BBR пропущена.' >&2
        fi
    else
        echo 'Ядро не предоставляет BBR; текущий TCP-алгоритм сохранен.' >&2
    fi
    if sysctl -q -w net.ipv4.tcp_mtu_probing=1; then
        settings+=('net.ipv4.tcp_mtu_probing = 1')
    else
        echo 'Ядро не разрешает TCP MTU probing; используется его текущая настройка.' >&2
    fi
    printf '%s\n' '# Managed by private-vpn; original values are under data/tuning.' "${settings[@]}" > "$config_file"
    chmod 644 "$config_file"
    export VPN_TCP_CC
    VPN_TCP_CC=$(vpn_tcp_cc)
    echo "TCP на VPS и в новых Xray-контейнерах: $VPN_TCP_CC."
}
