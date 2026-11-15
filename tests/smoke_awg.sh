#!/usr/bin/env bash
# Actual AWG 3 handshake and encrypted traffic in isolated disposable namespaces.
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
fixture=$(mktemp -d)
suffix="${GITHUB_RUN_ID:-local}-$$"
network="vpn-smoke-$suffix"
server="vpn-smoke-server-$suffix"
client="vpn-smoke-client-$suffix"
cleanup() {
    docker rm -f "$client" "$server" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
    rm -rf -- "$fixture"
}
trap cleanup EXIT
python3 tests/smoke_fixture.py "$fixture/gen"
# These are disposable CI keys owned by the runner UID. Containers drop DAC
# override and must be able to read the individual read-only bind mounts.
chmod 644 "$fixture/gen/xray.json" "$fixture/gen/awg.conf" "$fixture/gen/client.conf"
image=private-vpn:2026-11-12
docker build -f configs/Dockerfile -t "$image" .
docker run --rm --network none --read-only --cap-drop ALL \
    -v "$fixture/gen/xray.json:/etc/xray/config.json:ro" \
    --entrypoint xray "$image" run -test -c /etc/xray/config.json
docker network create "$network" >/dev/null
docker run -d --name "$server" --network "$network" \
    --cap-drop ALL --cap-add NET_ADMIN --device /dev/net/tun \
    --read-only --tmpfs /run --tmpfs /tmp \
    -v "$fixture/gen/awg.conf:/etc/awg/server.conf:ro" \
    --entrypoint sh "$image" -ec '
        amneziawg-go -f awg0 & pid=$!
        trap "kill $pid 2>/dev/null || true" EXIT
        i=0; until [ -S /run/amneziawg/awg0.sock ]; do
            kill -0 "$pid"; i=$((i+1)); [ "$i" -lt 100 ]; sleep .1
        done
        awg setconf awg0 /etc/awg/server.conf
        ip address add 10.77.0.1/24 dev awg0
        ip link set awg0 mtu 1280 up
        touch /tmp/ready
        wait "$pid"
    ' >/dev/null
for ((i=0;i<100;i++)); do
    if docker exec "$server" test -f /tmp/ready; then break; fi
    sleep .1
done
docker exec "$server" test -f /tmp/ready
address=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$server")
sed -i "s/SERVER_IP/$address/" "$fixture/gen/client.conf"
docker run --name "$client" --network "$network" \
    --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun \
    --read-only --tmpfs /run --tmpfs /tmp \
    -v "$fixture/gen/client.conf:/etc/awg/client.conf:ro" \
    --entrypoint sh "$image" -ec '
        amneziawg-go -f awg0 & pid=$!
        trap "kill $pid 2>/dev/null || true" EXIT
        i=0; until [ -S /run/amneziawg/awg0.sock ]; do
            kill -0 "$pid"; i=$((i+1)); [ "$i" -lt 100 ]; sleep .1
        done
        awg setconf awg0 /etc/awg/client.conf
        ip address add 10.77.0.3/32 dev awg0
        ip link set awg0 mtu 1280 up
        ip route add 10.77.0.0/24 dev awg0
        ping -c 3 -W 5 10.77.0.1
        awg show awg0 latest-handshakes | awk "\$2 > 0 {found=1} END {exit !found}"
    '
echo 'AWG 3 handshake and encrypted traffic: OK'
