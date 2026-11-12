#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/configs/common.sh"
USERS=(denis vlad liza parents router svyat sveta ruslan)
[[ -f data/current/state.json ]] || { echo 'Run install.sh first' >&2; exit 1; }
case ${1:-links} in
    list) python3 configs/render.py show ;;
    links|raw)
        [[ $# -le 2 ]] || { echo 'users.sh links|raw [NAME]' >&2; exit 1; }
        python3 configs/render.py "${1:-links}" "${@:2}"
        ;;
    show)
        [[ $# == 2 ]] || { echo 'users.sh show NAME' >&2; exit 1; }
        python3 configs/render.py show "$2"
        qrencode -t ANSIUTF8 < "data/output/$2-tcp.txt"
        ;;
    rotate|enable|disable)
        [[ $# == 2 ]] || { echo 'users.sh rotate|enable|disable NAME' >&2; exit 1; }
        candidate=$(python3 configs/render.py candidate "$(IFS=,; echo "${USERS[*]}")" '' "$1" "$2")
        apply_candidate "$candidate"
        if [[ $1 != disable ]]; then python3 configs/render.py links "$2"; fi
        ;;
    *) echo 'Usage: users.sh [links [NAME]|raw [NAME]|list|show NAME|rotate NAME|enable NAME|disable NAME]' >&2; exit 1 ;;
esac
