#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/configs/common.sh"
[[ -f data/current/state.json ]] || { echo 'Сначала выполните install.sh.' >&2; exit 1; }
USERS=(denis vlad liza parents router svyat sveta ruslan)
load_sni_candidates
vpn_tune_network
compose build xray
candidate=$(python3 configs/render.py candidate "$(IFS=,; echo "${USERS[*]}")" "$(IFS=,; echo "${SNI_DOMAINS[*]}")" optimize)
apply_candidate "$candidate"
python3 configs/render.py links
echo 'Настройки применены. Если SNI изменился, обновите подписку или повторно импортируйте профиль со своей страницы.'
echo 'Проверка работы и загрузки: bash manage.sh diagnose'
