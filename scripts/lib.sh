#!/usr/bin/env bash
#
# Valtros shared runtime configuration and host detection.
#
# Sourced by provision.sh, install.sh, start.sh, stop.sh, status.sh, test.sh
# and scripts/bootstrap_db.sh. It holds no secrets: every value here is either
# a default, a detected fact about the host, or an override read from
# <CONF_DIR>/install.conf. Passwords and keys live only in
# <CONF_DIR>/valtros.env and <CONF_DIR>/fw.env.
#
# Two rules keep this usable across distributions:
#   * nothing here may fail hard - a sourcing script on an unknown distro must
#     still be able to print its usage text and exit 2;
#   * detection never assumes a package manager, a service manager or a
#     PostgreSQL layout. Those are looked up, and the caller checks the result.

[[ -n "${VALTROS_LIB_LOADED:-}" ]] && return 0
VALTROS_LIB_LOADED=1

# ---------------------------------------------------------------------------
# Defaults. Every one of these can be overridden, in increasing priority by:
# this file -> <CONF_DIR>/install.conf -> the calling process's environment.
# ---------------------------------------------------------------------------

# Which of these settings the caller supplied before this file was sourced.
# Their values outrank the recorded ones in install.conf, so they have to be
# identified now, while a default is still distinguishable from a choice: once
# the assignments below have run, "$SERVICE_USER" is "valtros" whether the
# operator asked for it or not.
VALTROS_PRESET_VARS=""
for _v in VALTROS_REPO_DIR SERVICE_USER SERVICE_GROUP CONF_DIR STATE_DIR LOG_DIR \
          API_BIND API_PORT DB_HOST DB_PORT DB_NAME DB_TEST_NAME DB_USER FW_DB_USER \
          ADMIN_USERNAME EXPOSE_LAN BUILD_LAB SEED_CATALOG
do
    [[ -n "${!_v:-}" ]] && VALTROS_PRESET_VARS="${VALTROS_PRESET_VARS} ${_v}"
done
unset _v

VALTROS_REPO_DIR="${VALTROS_REPO_DIR:-}"
SERVICE_USER="${SERVICE_USER:-valtros}"
SERVICE_GROUP="${SERVICE_GROUP:-valtros}"
CONF_DIR="${CONF_DIR:-/etc/valtros}"
STATE_DIR="${STATE_DIR:-/var/lib/valtros}"
LOG_DIR="${LOG_DIR:-/var/log/valtros}"
API_BIND="${API_BIND:-127.0.0.1}"
API_PORT="${API_PORT:-8000}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-valtros}"
DB_TEST_NAME="${DB_TEST_NAME:-valtros_test}"
DB_USER="${DB_USER:-valtros}"
FW_DB_USER="${FW_DB_USER:-valtros_fw}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
EXPOSE_LAN="${EXPOSE_LAN:-yes}"
# BUILD_LAB is about containers (the deliberately-vulnerable Docker lab);
# SEED_CATALOG is about rows in the database (the control/test catalog the
# seeder writes). They are unrelated: an install can seed a catalog with no lab,
# or run a lab with an empty database.
BUILD_LAB="${BUILD_LAB:-no}"
SEED_CATALOG="${SEED_CATALOG:-yes}"

# The repository location defaults to the tree this file lives in (lib.sh sits
# in scripts/, so its parent is the root). A caller that forgets to set it still
# renders correct absolute paths instead of writing "@REPO_DIR@" or an empty
# prefix into a systemd unit - a failure that would only show up as a unit
# refusing to start.
if [[ -z "$VALTROS_REPO_DIR" ]]; then
    VALTROS_REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
fi

# The unit names are deliberately fixed even though the account name is not:
# the sudoers rule, the nginx site and every lifecycle script address the units
# by name, so making them configurable would mean rendering each of those too
# for no operational gain.
API_UNIT="valtros-api.service"
WORKER_UNIT="valtros-worker.service"
FW_UNIT="valtros-fw-sync.service"
FW_TIMER="valtros-fw-sync.timer"

VALTROS_LOG_TAG="${VALTROS_LOG_TAG:-valtros}"

say()  { printf '%s: %s\n' "$VALTROS_LOG_TAG" "$*"; }
warn() { printf '%s: WARNING: %s\n' "$VALTROS_LOG_TAG" "$*" >&2; }
die()  { printf '%s: ERROR: %s\n' "$VALTROS_LOG_TAG" "$*" >&2; exit 1; }
note() { printf '%s: %s\n' "$VALTROS_LOG_TAG" "$*" >&2; }

# ---------------------------------------------------------------------------
# Config file
# ---------------------------------------------------------------------------

# Reads the recorded install-time choices, if a previous install wrote them.
#
# Sourcing a file can only overwrite, so the caller's own values - the ones
# named in VALTROS_PRESET_VARS - are saved first and put back afterwards. That
# is what preserves the documented priority order: a caller that exports
# SERVICE_USER or CONF_DIR gets what it asked for, and install.conf fills in
# only what the caller stayed silent about.
#
# This matters beyond tidiness: provision.sh and install.sh both pass their
# resolved settings down to their children as environment variables, and if
# install.conf could override those, re-running an install after moving the
# repository would render the old location back into every systemd unit.
valtros_load_install_conf() {
    local conf="$CONF_DIR/install.conf"
    [[ -r "$conf" ]] || return 0

    declare -A _kept=()
    local _name
    for _name in $VALTROS_PRESET_VARS; do
        _kept["$_name"]="${!_name}"
    done

    # shellcheck disable=SC1090
    source "$conf"

    for _name in "${!_kept[@]}"; do
        printf -v "$_name" '%s' "${_kept[$_name]}"
    done
    return 0
}

# ---------------------------------------------------------------------------
# Host detection
# ---------------------------------------------------------------------------

# Sets VALTROS_DISTRO_ID / VALTROS_DISTRO_LIKE / VALTROS_DISTRO_NAME.
valtros_detect_distro() {
    VALTROS_DISTRO_ID=""
    VALTROS_DISTRO_LIKE=""
    VALTROS_DISTRO_NAME=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        VALTROS_DISTRO_ID="$(
            . /etc/os-release 2>/dev/null
            printf '%s' "${ID:-}"
        )"
        VALTROS_DISTRO_LIKE="$(
            . /etc/os-release 2>/dev/null
            printf '%s' "${ID_LIKE:-}"
        )"
        VALTROS_DISTRO_NAME="$(
            . /etc/os-release 2>/dev/null
            printf '%s' "${PRETTY_NAME:-${NAME:-}}"
        )"
    fi
    [[ -n "$VALTROS_DISTRO_ID" ]] || VALTROS_DISTRO_ID="unknown"
}

# Prints the family this distribution belongs to: one of
#   debian | rhel | suse | arch | unknown
# ID_LIKE is consulted because derivatives (Kali, Rocky, Alma, Manjaro) do not
# always carry a first-party package manager of their own.
valtros_distro_family() {
    valtros_detect_distro
    local id="$VALTROS_DISTRO_ID" like="$VALTROS_DISTRO_LIKE"
    case " $id $like " in
        *" debian "*|*" ubuntu "*|*" kali "*) printf 'debian' ;;
        *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*|*" ol "*) printf 'rhel' ;;
        *" suse "*|*" opensuse "*|*" sles "*) printf 'suse' ;;
        *" arch "*|*" archlinux "*|*" manjaro "*) printf 'arch' ;;
        *)
            # Fall back to whichever package manager is actually present, so a
            # derivative that reports an unrecognised ID still installs.
            if   valtros_has apt-get; then printf 'debian'
            elif valtros_has dnf;     then printf 'rhel'
            elif valtros_has yum;     then printf 'rhel'
            elif valtros_has pacman;  then printf 'arch'
            elif valtros_has zypper;  then printf 'suse'
            else                          printf 'unknown'
            fi ;;
    esac
}

valtros_has() { command -v "$1" >/dev/null 2>&1; }

# Prints the machine's primary global IPv4 address, or nothing.
#
# Container and virtual bridges are filtered out because they are always up and
# almost never the address an operator means: taking the first one would put
# the UI on a docker0 address that nothing outside the box can reach. `head -n1`
# after filtering keeps the choice deterministic across runs, which matters
# because the address is written into the nginx site on every install.
detect_lan_ip() {
    ip -4 -o addr show scope global 2>/dev/null \
        | awk '{print $2, $4}' \
        | grep -vE '^(docker|br-|virbr|veth|tun|tap|wg|zt)' \
        | head -n1 \
        | awk '{split($2, a, "/"); print a[1]}'
}

# The lifecycle units are systemd units, and the firewall convergence timer is
# a systemd timer. There is no non-systemd path, so say so plainly instead of
# installing something that cannot start.
valtros_require_systemd() {
    if ! valtros_has systemctl || [[ ! -d /run/systemd/system ]]; then
        die "this host is not running systemd (PID 1 is not systemd, or systemctl is absent).
       Valtros ships systemd units for the API, the worker and the firewall
       convergence timer, so it cannot be installed here. Containers built from
       a minimal base image (Alpine, OpenRC distros, WSL1) are the usual cause."
    fi
}

# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------

# valtros_pkg_install <pkg>...   - installs, refreshing the index only once
# per run. Package names are per-family and supplied by the caller, because
# the same component is called `python3-venv` on Debian and `python3` on
# Fedora; there is no reliable translation layer.
valtros_pkg_install() {
    [[ $# -gt 0 ]] || return 0
    local family
    family="$(valtros_distro_family)"
    case "$family" in
        debian)
            if [[ -z "${VALTROS_APT_UPDATED:-}" ]]; then
                DEBIAN_FRONTEND=noninteractive apt-get update -qq || warn "apt-get update failed; using the existing index"
                VALTROS_APT_UPDATED=1
            fi
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" ;;
        rhel)
            if valtros_has dnf; then dnf install -y "$@"; else yum install -y "$@"; fi ;;
        arch)
            pacman -Sy --needed --noconfirm "$@" ;;
        suse)
            zypper --non-interactive --no-gpg-checks install --no-recommends "$@" ;;
        *)
            die "no supported package manager found; install these by hand and re-run: $*" ;;
    esac
}

# Prints the distro's package name for a component, given every candidate
# spelling. The first one the package manager already knows about wins, so the
# caller does not have to know which release it is on.
valtros_pkg_resolve() {
    local family; family="$(valtros_distro_family)"
    local candidate
    for candidate in "$@"; do
        case "$family" in
            debian) valtros_has apt-cache && apt-cache show "$candidate" >/dev/null 2>&1 && { printf '%s' "$candidate"; return 0; } ;;
            rhel)   valtros_has dnf && dnf info --available "$candidate" >/dev/null 2>&1 && { printf '%s' "$candidate"; return 0; } ;;
            arch)   pacman -Si "$candidate" >/dev/null 2>&1 && { printf '%s' "$candidate"; return 0; } ;;
            suse)   zypper info "$candidate" >/dev/null 2>&1 && { printf '%s' "$candidate"; return 0; } ;;
        esac
    done
    return 1
}

# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------

# Runs psql as the database superuser. `runuser` is used in preference to
# `sudo -u` because it is part of util-linux and therefore present on every
# distribution here, whereas sudo is not guaranteed and this script already
# runs as root.
valtros_psql() {
    runuser -u postgres -- psql "$@"
}

# Starts the cluster, whichever way this distribution manages it, and waits for
# it to answer. Returns non-zero if it never becomes ready.
valtros_pg_start() {
    if pg_isready -q -h "$DB_HOST" -p "$DB_PORT"; then
        return 0
    fi
    local family; family="$(valtros_distro_family)"
    case "$family" in
        debian)
            # Debian and derivatives wrap clusters in pg_ctlcluster; the plain
            # service starts every cluster rather than the default one.
            if valtros_has pg_ctlcluster && valtros_has pg_lsclusters; then
                local ver
                ver="$(pg_lsclusters -h 2>/dev/null | awk 'NR==1{print $1}')"
                [[ -n "$ver" ]] && pg_ctlcluster "$ver" main start >/dev/null 2>&1
            fi
            systemctl start postgresql.service >/dev/null 2>&1 || true ;;
        *)
            systemctl start postgresql.service >/dev/null 2>&1 || true ;;
    esac
    local _
    for _ in $(seq 1 30); do
        pg_isready -q -h "$DB_HOST" -p "$DB_PORT" && return 0
        sleep 1
    done
    return 1
}

# Prints the data directory PostgreSQL is actually using, or nothing.
# Asking the running server is the only answer that survives every
# distribution's differing layout (Debian /var/lib/postgresql/<ver>/main,
# RHEL /var/lib/pgsql/data, Arch /var/lib/postgres/data).
valtros_pg_datadir() {
    valtros_psql -qtAX -c 'SHOW data_directory;' 2>/dev/null | head -n1
}

# Prints the server version as an integer major (18, 17, 16...).
valtros_pg_major() {
    valtros_psql -qtAX -c 'SHOW server_version_num;' 2>/dev/null \
        | head -n1 | awk '{print int($1/10000)}'
}

# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

# Escapes a value for use on the right-hand side of a sed s|..|..| expression.
_valtros_sed_escape() { printf '%s' "$1" | sed 's/[&|\\]/\\&/g'; }

# valtros_render <template> <destination> [mode]
# Substitutes the @PLACEHOLDER@ tokens. The destination is written directly
# rather than moved into place, because every caller writes either into
# /etc/systemd/system or into a temp file it validates before installing.
valtros_render() {
    local tpl="$1" dest="$2" mode="${3:-0644}"
    [[ -r "$tpl" ]] || die "template not readable: $tpl"
    # Falls back to the caller's own idea of the repo root: a rendering script
    # is always sitting inside the tree it is rendering, so that is authoritative
    # even when an install.conf from a previous location says otherwise.
    local repo_root="${VALTROS_REPO_DIR:-${REPO_ROOT:-}}"
    [[ -n "$repo_root" ]] || die "cannot determine the repository directory (VALTROS_REPO_DIR is unset)"
    local repo service_user service_group conf state log api_bind api_port python
    repo="$(_valtros_sed_escape "$repo_root")"
    service_user="$(_valtros_sed_escape "$SERVICE_USER")"
    service_group="$(_valtros_sed_escape "$SERVICE_GROUP")"
    conf="$(_valtros_sed_escape "$CONF_DIR")"
    state="$(_valtros_sed_escape "$STATE_DIR")"
    log="$(_valtros_sed_escape "$LOG_DIR")"
    api_bind="$(_valtros_sed_escape "$API_BIND")"
    api_port="$(_valtros_sed_escape "$API_PORT")"
    python="$(_valtros_sed_escape "${VALTROS_REPO_DIR}/backend/.venv/bin/python")"

    sed \
        -e "s|@REPO_DIR@|${repo}|g" \
        -e "s|@PYTHON@|${python}|g" \
        -e "s|@SERVICE_USER@|${service_user}|g" \
        -e "s|@SERVICE_GROUP@|${service_group}|g" \
        -e "s|@CONF_DIR@|${conf}|g" \
        -e "s|@STATE_DIR@|${state}|g" \
        -e "s|@LOG_DIR@|${log}|g" \
        -e "s|@API_BIND@|${api_bind}|g" \
        -e "s|@API_PORT@|${api_port}|g" \
        "$tpl" > "$dest"
    chmod "$mode" "$dest"
}
