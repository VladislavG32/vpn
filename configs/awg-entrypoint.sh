#!/bin/sh
set -eu
# All rules live inside the container network namespace.
ip link del awg0 2>/dev/null || true
amneziawg-go -f awg0 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" || true' EXIT
trap 'exit 0' TERM INT
i=0
until [ -S /run/amneziawg/awg0.sock ]; do
    kill -0 "$pid"
    i=$((i + 1)); [ "$i" -lt 100 ] || exit 1
    sleep 0.1
done
awg setconf awg0 /etc/awg/server.conf
ip address add 10.77.0.1/24 dev awg0
ip link set awg0 mtu 1280 up
out=$(ip -4 route show default | awk 'NR==1 {print $5}')
[ -n "$out" ]
iptables -P FORWARD DROP
iptables -A INPUT -i awg0 -j DROP
# Redirect ordinary client DNS, including hardcoded public resolvers.
for proto in udp tcp; do
    iptables -t nat -A PREROUTING -i awg0 -p "$proto" --dport 53 -j DNAT --to-destination 172.30.77.53:53
    iptables -A FORWARD -i awg0 -d 172.30.77.53 -p "$proto" --dport 53 -j ACCEPT
done
# No inter-peer traffic, LAN access, Docker gateway or cloud metadata.
for cidr in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 192.0.0.0/24 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4; do
    iptables -A FORWARD -i awg0 -d "$cidr" -j REJECT
done
iptables -A FORWARD -i awg0 -p tcp --dport 853 -j REJECT
iptables -A FORWARD -i awg0 -p udp --dport 853 -j REJECT
iptables -A FORWARD -o awg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i awg0 -o "$out" -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.77.0.0/24 ! -o awg0 -j MASQUERADE
wait "$pid"
