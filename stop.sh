#!/usr/bin/env bash
#
# Stop the CONTROLFORGE API and worker. PostgreSQL and nginx are left alone
# (they serve other work), and the firewall rules stay loaded on purpose:
# stopping the app is not a reason to open the worker uid back up.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONTROLFORGE_REPO_DIR="$REPO_ROOT"
export CONTROLFORGE_REPO_DIR

# shellcheck source=scripts/lib.sh
source "$REPO_ROOT/scripts/lib.sh"

CONTROLFORGE_LOG_TAG="stop"
controlforge_load_install_conf

[[ ${EUID} -eq 0 ]] || exec sudo -- "$0" "$@"

for unit in "$WORKER_UNIT" "$API_UNIT"; do
    if ! systemctl cat "$unit" >/dev/null 2>&1; then
        say "$unit is not installed"
        continue
    fi
    if systemctl is-active --quiet "$unit"; then
        systemctl stop "$unit" && say "stopped $unit"
    else
        say "$unit is not running"
    fi
done

say "PostgreSQL and nginx were left running"
say "firewall rules stay loaded (fail-closed); to remove them entirely:"
say "  sudo $REPO_ROOT/scripts/sync_firewall.py --flush"
