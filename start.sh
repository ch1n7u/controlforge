#!/usr/bin/env bash
#
# Bring CONTROLFORGE up: PostgreSQL, the API, the worker, a firewall refresh and
# nginx. Safe to run repeatedly - already-running pieces are left alone.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONTROLFORGE_REPO_DIR="$REPO_ROOT"
export CONTROLFORGE_REPO_DIR

# shellcheck source=scripts/lib.sh
source "$REPO_ROOT/scripts/lib.sh"

CONTROLFORGE_LOG_TAG="start"
controlforge_load_install_conf

[[ ${EUID} -eq 0 ]] || exec sudo -- "$0" "$@"

controlforge_require_systemd

# --- 1. PostgreSQL -----------------------------------------------------------
if controlforge_pg_start; then
    say "PostgreSQL is up on ${DB_HOST}:${DB_PORT}"
else
    die "PostgreSQL did not become ready on ${DB_HOST}:${DB_PORT}
       Start it by hand to see why, e.g.:  systemctl status postgresql"
fi

# --- 2. API + worker ---------------------------------------------------------
if ! systemctl cat "$API_UNIT" >/dev/null 2>&1; then
    die "$API_UNIT is not installed - run ./install.sh first"
fi
systemctl start "$API_UNIT" \
    || warn "the API failed to start (see: journalctl -u $API_UNIT -n 50)"
systemctl start "$WORKER_UNIT" \
    || warn "the worker failed to start (see: journalctl -u $WORKER_UNIT -n 50)"

# --- 3. firewall refresh (oneshot; re-derived from active scopes) ------------
if systemctl cat "$FW_UNIT" >/dev/null 2>&1; then
    systemctl start "$FW_UNIT" \
        || warn "firewall sync failed (see: systemctl status $FW_UNIT)"
fi

# --- 4. nginx ----------------------------------------------------------------
if systemctl cat nginx.service >/dev/null 2>&1; then
    if ! systemctl is-active --quiet nginx; then
        say "starting nginx"
        systemctl start nginx || die "could not start nginx"
    fi
else
    warn "nginx is not installed - the API is reachable directly on ${API_BIND}:${API_PORT}, but not through the UI"
fi

# --- 5. wait for the API to answer, and for the unit to be the one answering --
# The probe is quiet until it succeeds: a refusal here is the expected state
# while the unit is still starting, not something to print at the operator.
api_ok=0
for _ in $(seq 1 30); do
    if curl -fsS -m 2 -o /dev/null "http://${API_BIND}:${API_PORT}/api/health" 2>/dev/null; then
        api_ok=1
        break
    fi
    sleep 1
done

# A stale dev server left over on the API port makes the HTTP check above pass
# while the systemd unit crash-loops on "address already in use". The unit's own
# state is the authority, so it is checked separately.
api_unit=0
systemctl is-active --quiet "$API_UNIT" && api_unit=1

# --- URLs --------------------------------------------------------------------
LAN_IP="$(detect_lan_ip || true)"
echo
echo "CONTROLFORGE is starting:"
if [[ "$EXPOSE_LAN" == "yes" && -n "$LAN_IP" ]]; then
    echo "  UI    http://127.0.0.1/            (this machine)"
    echo "  UI    http://${LAN_IP}/  (LAN)"
else
    echo "  UI    http://127.0.0.1/            (loopback only)"
fi
echo "  API   http://${API_BIND}:${API_PORT}/api/health   (direct; proxied at /api/... via nginx)"
if [[ -d "$REPO_ROOT/frontend/dist" ]]; then
    echo "  SPA   served from $REPO_ROOT/frontend/dist"
else
    warn "frontend/dist is missing - the UI will 404 until the frontend is built"
fi

if [[ $api_unit -eq 1 ]]; then
    say "the API answers on ${API_BIND}:${API_PORT} ($API_UNIT is active)"
elif [[ $api_ok -eq 1 ]]; then
    warn "port ${API_PORT} answers, but $API_UNIT is NOT active -"
    warn "something else is serving :${API_PORT}. Find it with: ss -ltnp | grep :${API_PORT}"
    exit 1
else
    warn "the API is not answering on ${API_BIND}:${API_PORT} yet"
    warn "see: journalctl -u $API_UNIT -n 50"
    exit 1
fi
