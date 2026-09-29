#!/usr/bin/env bash
#
# Stop and remove the CONTROLFORGE test lab containers. Named volumes are kept
# (no -v), so lab state survives; the network is recreated on the next up.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/lab/docker-compose.yml"

die() { printf 'lab_down: ERROR: %s\n' "$*" >&2; exit 1; }
say() { printf 'lab_down: %s\n' "$*"; }

[[ -f "$COMPOSE_FILE" ]] || die "no compose file at $COMPOSE_FILE"
/usr/bin/docker compose version >/dev/null 2>&1 || die "the docker compose v2 plugin is not available"

say "stopping the lab (docker compose down)"
# The juice profile is always included on teardown, even though starting it is
# opt-in: a compose `down` that omits an active profile treats those containers
# as orphans, so naming the profile keeps the teardown deterministic rather than
# relying on --remove-orphans to sweep up the Juice Shop target.
/usr/bin/docker compose -f "$COMPOSE_FILE" --profile juice down --remove-orphans
say "lab is down (volumes kept)"
