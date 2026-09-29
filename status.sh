#!/usr/bin/env bash
#
# Show what CONTROLFORGE has running right now: service states, listeners, the HTTP
# answers (API on the configured bind, UI on port 80), and the worker egress
# firewall. Works without root; uses `sudo -n` for the firewall peek when it is
# available.
#
# Exit status: 0 when every critical check passes, 1 otherwise.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONTROLFORGE_REPO_DIR="$REPO_ROOT"
export CONTROLFORGE_REPO_DIR

# shellcheck source=scripts/lib.sh
source "$REPO_ROOT/scripts/lib.sh"

CONTROLFORGE_LOG_TAG="status"
controlforge_load_install_conf

LAN_IP="$(detect_lan_ip || true)"
fail=0

echo "CONTROLFORGE status - $(date '+%Y-%m-%d %H:%M:%S')"
echo "repository: $REPO_ROOT"
echo "database:   ${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
echo "account:    ${SERVICE_USER}   state: ${STATE_DIR}   logs: ${LOG_DIR}"
if [[ "$EXPOSE_LAN" == "yes" ]]; then
    echo "LAN address: ${LAN_IP:-not detected}"
else
    echo "exposure:   loopback only (EXPOSE_LAN=no)"
fi

echo
echo "== services =="
check_unit() {
    local unit="$1" active enabled
    if ! systemctl cat "$unit" >/dev/null 2>&1; then
        printf '  %-36s %s\n' "$unit" "not installed"
        return 1
    fi
    active="$(systemctl is-active "$unit" 2>/dev/null || true)"
    enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
    printf '  %-36s %-9s (%s)\n' "$unit" "${active:-unknown}" "${enabled:-unknown}"
    [[ "$active" == "active" ]]
}

check_unit postgresql.service || fail=1
check_unit nginx.service || fail=1
check_unit "$API_UNIT" || fail=1
check_unit "$WORKER_UNIT" || fail=1

if systemctl cat "$FW_UNIT" >/dev/null 2>&1; then
    fw_result="$(systemctl show -p Result --value "$FW_UNIT" 2>/dev/null || true)"
    fw_last="$(systemctl show -p ExecMainExitTimestamp --value "$FW_UNIT" 2>/dev/null || true)"
    printf '  %-36s %s\n' "$FW_UNIT" "oneshot (last result: ${fw_result:-unknown}${fw_last:+, $fw_last})"
fi

echo
echo "== listeners =="
show_port() {
    local port="$1" label="$2" addrs
    addrs="$(ss -ltnH "sport = :$port" 2>/dev/null | awk '{print $4}' | sort -u | tr '\n' ' ' || true)"
    printf '  %-22s %s\n' "$label" "${addrs:-not listening}"
}
show_port "$API_PORT" "API :$API_PORT"
show_port 80         "UI  :80"
show_port "$DB_PORT"  "PostgreSQL :$DB_PORT"

echo
echo "== HTTP checks =="
http_code() {
    local out
    if ! out="$(curl -sS -o /dev/null -m 5 -w '%{http_code}' "$1" 2>/dev/null)"; then
        out="no answer"
    fi
    printf '%s' "$out"
}
api_code="$(http_code "http://${API_BIND}:${API_PORT}/api/health")"
root_code="$(http_code http://127.0.0.1/)"
printf '  %-44s %s\n' "http://${API_BIND}:${API_PORT}/api/health" "$api_code"
printf '  %-44s %s\n' "http://127.0.0.1/" "$root_code"
if [[ "$EXPOSE_LAN" == "yes" && -n "$LAN_IP" ]]; then
    lan_code="$(http_code "http://${LAN_IP}/")"
    printf '  %-44s %s\n' "http://${LAN_IP}/" "$lan_code"
fi

[[ "$api_code" == "200" ]] || { echo "  -> the API is not healthy"; fail=1; }
case "$root_code" in
    no\ answer) echo "  -> port 80 is not answering (nginx down or site not loaded?)"; fail=1 ;;
    2*|3*|401|403) : ;;
    404) echo "  -> nginx answers, but the SPA build (frontend/dist) is missing" ;;
    *) : ;;
esac

echo
echo "== firewall (worker egress) =="
nft_out=""
nft_inspectable=0
if [[ ${EUID} -eq 0 ]]; then
    nft_inspectable=1
    nft_out="$(nft list table inet controlforge 2>/dev/null || true)"
elif sudo -n true >/dev/null 2>&1; then
    nft_inspectable=1
    nft_out="$(sudo -n nft list table inet controlforge 2>/dev/null || true)"
fi
if [[ $nft_inspectable -eq 0 ]]; then
    echo "  need root (or passwordless sudo) to inspect the firewall table"
elif [[ -n "$nft_out" ]]; then
    drops="$(printf '%s\n' "$nft_out" | grep -oE 'counter packets [0-9]+ bytes [0-9]+' | head -n1 || true)"
    echo "  table inet controlforge: loaded (worker egress filtered${drops:+; drop $drops})"
else
    echo "  table inet controlforge: not loaded (worker egress unfiltered)"
    echo "  refresh with: sudo systemctl start $FW_UNIT"
fi

echo
if [[ $fail -eq 0 ]]; then
    echo "status: all checks pass"
else
    echo "status: issues found (see lines above)"
fi
exit "$fail"
