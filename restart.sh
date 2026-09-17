#!/usr/bin/env bash
#
# Restart the Valtros stack = stop.sh followed by start.sh, so a restart
# is exactly as thorough as a fresh start (PostgreSQL included, firewall
# re-synced, URLs reprinted).
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Re-exec as root before printing anything, or the banner appears twice: once
# from the unprivileged shell and once from the one that does the work.
[[ ${EUID} -eq 0 ]] || exec sudo -- "$0" "$@"

printf 'restart: bouncing Valtros (stop + start)\n'

"$REPO_ROOT/stop.sh"
exec "$REPO_ROOT/start.sh"
