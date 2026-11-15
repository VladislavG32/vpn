#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/configs/common.sh"
[[ -f data/current/state.json ]] || { echo 'Сначала выполните install.sh.' >&2; exit 1; }
echo 'Переход на AmneziaWG 3.1 и один профиль Happ на 443/tcp.'
echo 'После перехода заново импортируйте ключ AmneziaVPN и обновите подписку Happ у всех пользователей.'
echo 'Личные веб-ссылки, UUID, ключи пользователей и UDP-порт сохранятся. Старые поколения останутся для отката.'
load_sni_candidates
vpn_tune_network
compose build xray
candidate=$(python3 configs/render.py candidate denis,vlad,liza,parents,router,svyat,sveta,ruslan "$(IFS=,; echo "${SNI_DOMAINS[*]}")" harden)
apply_candidate "$candidate"
python3 configs/render.py links
if [[ -f data/portal/enabled ]]; then
    echo 'Откройте свои прежние страницы и импортируйте новые профили.'
elif [[ ${PORTAL_ENABLED:-1} == 1 ]]; then
    flock -u 9
    bash portal.sh enable
fi
