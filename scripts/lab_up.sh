#!/usr/bin/env bash
#
# Bring up the Valtros test lab (Docker Compose, 6 containers pinned to
# 127.0.0.1). Waits until every healthcheck passes. Idempotent.
#
# The compose file is owned by the lab workstream; this wrapper never modifies
# it, it only drives `docker compose up`.
#
# OWASP Juice Shop sits behind a compose profile so the core lab starts
# without it. Pass --with-juice (or set BUILD_LAB=yes) to include it, which is
# what the seeded `juice-shop` target expects.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/lab/docker-compose.yml"

# shellcheck source=scripts/lib.sh
source "$REPO_ROOT/scripts/lib.sh"
VALTROS_LOG_TAG="lab_up"
valtros_load_install_conf

die() { printf 'lab_up: ERROR: %s\n' "$*" >&2; exit 1; }
say() { printf 'lab_up: %s\n' "$*"; }

profiles=()
for arg in "$@"; do
    case "$arg" in
        --with-juice) profiles+=(--profile juice) ;;
        -h|--help)
            printf 'usage: %s [--with-juice]\n' "$(basename "$0")"
            printf '  --with-juice   also start the OWASP Juice Shop target (profile "juice")\n'
            exit 0 ;;
        *) die "unknown argument: $arg (try --help)" ;;
    esac
done
if [[ "${BUILD_LAB:-no}" == "yes" && ${#profiles[@]} -eq 0 ]]; then
    profiles+=(--profile juice)
fi

[[ -f "$COMPOSE_FILE" ]] || die "no compose file at $COMPOSE_FILE"
docker compose version >/dev/null 2>&1 || die "the docker compose v2 plugin is not available"

say "starting the lab (docker compose up -d --wait)"
if ! docker compose -f "$COMPOSE_FILE" "${profiles[@]}" up -d --wait --wait-timeout 180; then
    die "one or more lab containers did not become healthy - inspect with: docker compose -f $COMPOSE_FILE ps / logs"
fi

docker compose -f "$COMPOSE_FILE" "${profiles[@]}" ps

cat <<'EOF'

lab endpoints (all bound to 127.0.0.1, from lab/docker-compose.yml):
  8081  lab-headers   HTTP, response-header practice target
  8082  lab-webapp    HTTP web application
  8083  lab-api       JSON API
  8084  juice-shop    OWASP Juice Shop        (profile "juice" only)
  8443  lab-weaktls   HTTPS with a weak TLS configuration
  2222  lab-ssh       SSH
EOF
say "lab is up"
