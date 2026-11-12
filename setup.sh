#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/configs/common.sh"
USERS=(denis vlad liza parents router svyat sveta ruslan)
SNI_DOMAINS=(www.lovelive-anime.jp gateway.icloud.com swift.com www.yahoo.com)
if [[ ! -f data/current/state.json && -z ${ENDPOINT:-} ]]; then
    # Public IP discovery is only an installation convenience; never used for migrations.
    ENDPOINT=$(curl -4fsS --max-time 10 https://api.ipify.org)
    export ENDPOINT
fi
docker info >/dev/null
compose build xray
candidate=$(python3 configs/render.py candidate "$(IFS=,; echo "${USERS[*]}")" "$(IFS=,; echo "${SNI_DOMAINS[*]}")")
apply_candidate "$candidate"
echo "Firewall VPS: TCP 443,8443; UDP $AWG_PORT. Keep SSH restricted to your administration IP."
