#!/usr/bin/env bash
#
# Run the CONTROLFORGE test suites:
#   * backend: pytest against the dedicated test database
#     (fixtures redirect evidence/audit to temp dirs; production data is never
#     touched)
#   * frontend: npm run build, which is `tsc -b && vite build` - the typecheck
#     and the production build in one step, skipped when the frontend does not
#     exist yet.
#
# Runs as the invoking user, not root.
#
# Do not run this at the same time as another pytest run: the suites share the
# test database and will deadlock against each other.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONTROLFORGE_REPO_DIR="$REPO_ROOT"
export CONTROLFORGE_REPO_DIR

# shellcheck source=scripts/lib.sh
source "$REPO_ROOT/scripts/lib.sh"

CONTROLFORGE_LOG_TAG="test"
controlforge_load_install_conf

fail=0
echo "== CONTROLFORGE tests =="
echo "-- database: ${DB_TEST_NAME} on ${DB_HOST}:${DB_PORT}"

# --- backend -----------------------------------------------------------------
VENV_PY="$REPO_ROOT/backend/.venv/bin/python"
if [[ -x "$VENV_PY" ]]; then
    # The backend needs <CONF_DIR>/controlforge.env, which is 0640 root:$SERVICE_GROUP.
    # A login session that began before this user was added to the group does not
    # carry it in its supplementary groups, so reading the file fails even though
    # the account is a member. The group *database* is consulted rather than
    # `id -nG` (which describes the stale session), and `sg` re-resolves the
    # group, so the tests run without a re-login.
    if [[ -r "$CONF_DIR/controlforge.env" ]]; then
        echo "-- backend: $VENV_PY -m pytest -q"
        ( cd "$REPO_ROOT/backend" && exec "$VENV_PY" -m pytest -q ) || fail=1
    elif getent group "$SERVICE_GROUP" | awk -F: '{print $4}' \
         | tr ',' '\n' | grep -qx "$(id -un)"; then
        echo "-- backend: sg $SERVICE_GROUP -c '$VENV_PY -m pytest -q'"
        ( cd "$REPO_ROOT/backend" && exec sg "$SERVICE_GROUP" -c "'$VENV_PY' -m pytest -q" ) || fail=1
    else
        echo "-- backend: cannot read $CONF_DIR/controlforge.env and $(id -un) is not in group $SERVICE_GROUP"
        echo "   run: sudo usermod -aG $SERVICE_GROUP $(id -un)   then log out and back in"
        fail=1
    fi
else
    echo "-- backend: venv missing at $REPO_ROOT/backend/.venv - pytest not run"
    fail=1
fi

# --- frontend ----------------------------------------------------------------
if [[ -f "$REPO_ROOT/frontend/package.json" ]]; then
    if [[ -d "$REPO_ROOT/frontend/node_modules" ]]; then
        echo "-- frontend: npm run build (tsc -b && vite build)"
        ( cd "$REPO_ROOT/frontend" && exec npm run --silent build ) || fail=1
    else
        echo "-- frontend: node_modules missing - run 'npm install' in frontend/ first"
        fail=1
    fi
else
    echo "-- frontend: package.json not present yet - frontend checks skipped"
fi

echo
if [[ $fail -eq 0 ]]; then
    echo "tests: OK"
else
    echo "tests: FAILURES (see above)"
fi
exit "$fail"
