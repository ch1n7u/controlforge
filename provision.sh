#!/usr/bin/env bash
#
# CONTROLFORGE provisioner - takes a bare Linux host to a running install.
#
# install.sh only wires a prepared tree into the host: it assumes packages,
# a service account, a virtualenv, a PostgreSQL cluster and a frontend build
# already exist. This script creates all of those, so the sequence on a new
# machine is:
#
#     ./provision.sh          # everything below
#     ./start.sh              # bring the stack up
#
# What it does, in order:
#   * installs the distribution's packages for Python, PostgreSQL and nginx
#   * initialises and starts a PostgreSQL cluster (Debian, RHEL, Arch and
#     openSUSE all initialise one differently)
#   * creates the system account and group the services run as
#   * builds the virtualenv and the frontend, as the human who ran it, not root
#   * installs the validation engines (testssl.sh, nmap) or explains the gap
#   * runs install.sh, which renders the units and the nginx site
#   * creates the database and generates the secrets (scripts/bootstrap_db.sh)
#   * applies the migrations and seeds the account and the control catalog
#   * optionally starts the stack
#
# It is idempotent: every step checks for what it is about to create, so
# re-running it on a provisioned host only re-applies and re-checks. It never
# overwrites an existing secret file.
#
# Portability notes. This targets the four common families (Debian/Ubuntu/Kali,
# RHEL/Fedora/Rocky/Alma, Arch/Manjaro, openSUSE/SLES). It requires systemd -
# there is no OpenRC/SysV path, because the units are systemd units. Package
# names differ per family and are mapped explicitly rather than guessed.
#
# Usage:  sudo ./provision.sh [options]
#         ./provision.sh --help

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONTROLFORGE_REPO_DIR="$REPO_ROOT"
export CONTROLFORGE_REPO_DIR

# The human who invoked this, captured before any escalation. The virtualenv and
# the frontend build are created by them rather than by root: a root-owned
# node_modules or .venv is the classic way a deployment becomes unmaintainable,
# because the operator can no longer rebuild it and the service account may not
# be able to read it.
ORIGINAL_USER="${SUDO_USER:-$(id -un)}"
ORIGINAL_HOME="$(getent passwd "$ORIGINAL_USER" 2>/dev/null | cut -d: -f6 || true)"
[[ -n "${ORIGINAL_HOME:-}" ]] || ORIGINAL_HOME="/tmp"

# Explicit choices from the caller's environment outrank a recorded
# install.conf; lib.sh works that out for itself (see CONTROLFORGE_PRESET_VARS) and
# is the single place that knows the precedence rules, so nothing is captured
# here. Command-line flags are applied after lib.sh and install.conf and so win
# over both, which is the order the --help text promises.

# shellcheck source=scripts/lib.sh
source "$REPO_ROOT/scripts/lib.sh"
CONTROLFORGE_LOG_TAG="provision"

# Recorded choices from a previous run fill in whatever the caller stayed silent
# about; the caller's own environment wins over them.
controlforge_load_install_conf

usage() {
    cat <<'EOF'
CONTROLFORGE provisioner - prepares a host and installs CONTROLFORGE on it.

Usage: sudo ./provision.sh [options]

Options:
  --repo-dir PATH        Repository location (default: the directory holding
                         this script). Recorded and used by every unit.
  --service-user NAME    System account the services run as (default: controlforge).
  --service-group NAME   Group for that account (default: same as the user).
  --conf-dir PATH        Configuration and secrets directory (default: /etc/controlforge).
  --state-dir PATH       Mutable state, incl. the evidence store
                         (default: /var/lib/controlforge).
  --log-dir PATH         Log directory (default: /var/log/controlforge).
  --admin-user NAME      Administrator account to create in the application
                         (default: admin).
  --no-lan               Bind the web UI to loopback only. The default also
                         binds the machine's LAN address.
  --with-lab             Start the Docker test lab after provisioning.
  --no-seed              Create the database schema and the administrator, but
                         do not seed the control and test catalog.
  --start                Start the stack when provisioning finishes.
  --skip-packages        Do not touch the package manager.
  --skip-frontend        Do not build the frontend (the UI will 404).
  -y, --non-interactive  Accept every default; never prompt.
  -h, --help             This text.

Everything above can also be given as an environment variable, e.g.
  sudo SERVICE_USER=svc EXPOSE_LAN=no ./provision.sh
or edited in <conf-dir>/install.conf and re-applied by re-running this script.
EOF
}

NON_INTERACTIVE="no"
DO_START="no"
SKIP_PACKAGES="no"
SKIP_FRONTEND="no"
SERVICE_GROUP_GIVEN="no"

# True when nothing has named a group of its own: the resolved group is the
# same word as the resolved account, which is lib.sh's parallel default rather
# than a decision. Used below so that `--service-user svc` takes the group with
# it, while a group that was named somewhere - --service-group, the environment
# or install.conf - is left exactly as it was.
GROUP_FOLLOWS_USER="no"
[[ "$SERVICE_GROUP" == "$SERVICE_USER" ]] && GROUP_FOLLOWS_USER="yes"

args=("$@")
while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo-dir)       shift; [[ $# -gt 0 ]] || die "--repo-dir needs a path";   CONTROLFORGE_REPO_DIR="$1" ;;
        --service-user)   shift; [[ $# -gt 0 ]] || die "--service-user needs a name"; SERVICE_USER="$1" ;;
        --service-group)  shift; [[ $# -gt 0 ]] || die "--service-group needs a name"; SERVICE_GROUP="$1"; SERVICE_GROUP_GIVEN="yes" ;;
        --conf-dir)       shift; [[ $# -gt 0 ]] || die "--conf-dir needs a path";   CONF_DIR="$1" ;;
        --state-dir)      shift; [[ $# -gt 0 ]] || die "--state-dir needs a path";  STATE_DIR="$1" ;;
        --log-dir)        shift; [[ $# -gt 0 ]] || die "--log-dir needs a path";    LOG_DIR="$1" ;;
        --admin-user)     shift; [[ $# -gt 0 ]] || die "--admin-user needs a name"; ADMIN_USERNAME="$1" ;;
        --no-lan)         EXPOSE_LAN="no" ;;
        --with-lab)       BUILD_LAB="yes" ;;
        --no-seed)        SEED_CATALOG="no" ;;
        --start)          DO_START="yes" ;;
        --skip-packages)  SKIP_PACKAGES="yes" ;;
        --skip-frontend)  SKIP_FRONTEND="yes" ;;
        -y|--non-interactive) NON_INTERACTIVE="yes" ;;
        -h|--help)        usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

# The group follows the account only when nothing ever named a group of its own
# - see GROUP_FOLLOWS_USER above. A group given by --service-group, by the
# environment or by install.conf is authoritative and is left alone.
if [[ "$SERVICE_GROUP_GIVEN" != "yes" && "$GROUP_FOLLOWS_USER" == "yes" ]]; then
    SERVICE_GROUP="$SERVICE_USER"
fi

if [[ "$CONTROLFORGE_REPO_DIR" != "$REPO_ROOT" ]]; then
    say "note: --repo-dir differs from this script's location; the install will point at $CONTROLFORGE_REPO_DIR"
fi

# ---------------------------------------------------------------------------
# Interactive questions, asked while still unprivileged so the operator is
# not sitting at a root prompt answering questions.
# ---------------------------------------------------------------------------

ask() {
    # ask <variable> <prompt> <default>
    [[ "$NON_INTERACTIVE" == "yes" ]] && return 0
    [[ -r /dev/tty ]] || return 0
    local var="$1" prompt="$2" default="$3" answer=""
    read -r -p "$prompt [$default]: " answer < /dev/tty || true
    [[ -n "$answer" ]] || answer="$default"
    printf -v "$var" '%s' "$answer"
}

ask_yn() {
    # ask_yn <variable> <prompt> <yes|no>
    [[ "$NON_INTERACTIVE" == "yes" ]] && return 0
    [[ -r /dev/tty ]] || return 0
    local var="$1" prompt="$2" default="$3" answer=""
    read -r -p "$prompt [$default]: " answer < /dev/tty || true
    case "${answer,,}" in
        y|yes) answer="yes" ;;
        n|no)  answer="no" ;;
        "")    answer="$default" ;;
        *)     warn "unrecognised answer '$answer'; using '$default'"; answer="$default" ;;
    esac
    printf -v "$var" '%s' "$answer"
}

# Answers come from the controlling terminal, not stdin, so that piping this
# script's output through a pager or into tee cannot swallow a prompt.
say "CONTROLFORGE provisioning"
ask        ADMIN_USERNAME "Administrator username to create" "$ADMIN_USERNAME"
ask_yn     EXPOSE_LAN     "Serve the web UI on the LAN address as well as loopback? (yes/no)" "$EXPOSE_LAN"
ask_yn     SEED_CATALOG   "Seed the control and test catalog into the database? (yes/no)" "$SEED_CATALOG"
ask_yn     BUILD_LAB      "Also start the Docker test lab (deliberately vulnerable targets)? (yes/no)" "$BUILD_LAB"
ask_yn     DO_START       "Start CONTROLFORGE when provisioning finishes? (yes/no)" "$DO_START"

# ---------------------------------------------------------------------------
# Escalate. Every resolved value is handed to the elevated pass as an
# environment variable, so that pass is deterministic and never re-derives or
# re-prompts. The flags are passed through unchanged, so the mode switches
# (--start, --skip-packages, ...) arrive by exactly the route they arrived at
# this pass, and the variables above arrive as caller-supplied settings that
# lib.sh will protect from being overwritten by install.conf.
#
# `env` is used as sudo's command rather than sudo's --preserve-env, because
# --preserve-env's syntax has changed across sudo versions and it complains
# about names that are unset. These are literal arguments to env, so they work
# regardless of the sudo version installed.
# ---------------------------------------------------------------------------

PASS_ENV=()
for _v in CONTROLFORGE_REPO_DIR SERVICE_USER SERVICE_GROUP CONF_DIR STATE_DIR LOG_DIR \
          API_BIND API_PORT DB_HOST DB_PORT DB_NAME DB_TEST_NAME DB_USER FW_DB_USER \
          ADMIN_USERNAME EXPOSE_LAN BUILD_LAB SEED_CATALOG
do
    PASS_ENV+=("$_v=${!_v}")
done
unset _v
PASS_ENV+=(
    "CONTROLFORGE_BUILD_USER=$ORIGINAL_USER"
    "CONTROLFORGE_ORIGINAL_HOME=$ORIGINAL_HOME"
)

if [[ ${EUID} -ne 0 ]]; then
    say "requesting root (sudo) to continue"
    exec sudo -- env "${PASS_ENV[@]}" "$0" "${args[@]}"
fi

# From here on: root.
BUILD_USER="${CONTROLFORGE_BUILD_USER:-root}"
BUILD_HOME="${CONTROLFORGE_ORIGINAL_HOME:-/tmp}"

controlforge_require_systemd

controlforge_detect_distro
DISTRO_FAMILY="$(controlforge_distro_family)"
DISTRO_LABEL="${CONTROLFORGE_DISTRO_NAME:-$CONTROLFORGE_DISTRO_ID}"
say "host: ${DISTRO_LABEL} (id=${CONTROLFORGE_DISTRO_ID}, family=${DISTRO_FAMILY})"
if [[ "$DISTRO_FAMILY" == "unknown" ]]; then
    warn "this distribution is not one of the supported families (debian, rhel, suse, arch)."
    warn "Package installation will be skipped; install the dependencies by hand and"
    warn "re-run with --skip-packages."
    SKIP_PACKAGES="yes"
fi

say "settings:"
say "  repository    $CONTROLFORGE_REPO_DIR"
say "  account       $SERVICE_USER:$SERVICE_GROUP"
say "  config        $CONF_DIR"
say "  state         $STATE_DIR"
say "  logs          $LOG_DIR"
say "  api           ${API_BIND}:${API_PORT}"
say "  database      ${DB_NAME} on ${DB_HOST}:${DB_PORT} (test db ${DB_TEST_NAME})"
say "  admin user    $ADMIN_USERNAME"
say "  lan exposure  $EXPOSE_LAN"
say "  seed catalog  $SEED_CATALOG"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PYTHON_BIN=""
controlforge_python() {
    if [[ -n "$PYTHON_BIN" ]]; then printf '%s' "$PYTHON_BIN"; return; fi
    if controlforge_has python3; then PYTHON_BIN="python3"
    elif controlforge_has python; then PYTHON_BIN="python"
    else die "no python3 on this host; install it and re-run"
    fi
    printf '%s' "$PYTHON_BIN"
}

# as_build_user <dir> <cmd> [args...]  - runs a build step as the invoking human.
as_build_user() {
    local dir="$1"; shift
    if [[ "$(id -un)" == "$BUILD_USER" ]]; then
        ( cd "$dir" && "$@" )
    else
        runuser -u "$BUILD_USER" -- \
            env "HOME=$BUILD_HOME" "PATH=$PATH" \
            bash -c 'cd "$1" || exit 1; shift; exec "$@"' _ "$dir" "$@"
    fi
}

# Installs a package list, falling back to one-at-a-time so that a single
# package name that does not exist on this release does not abort the whole
# transaction and leave the host without PostgreSQL. Honours --skip-packages,
# so a host that is managed by configuration management can own its packages
# while still being provisioned by this script.
pkg_install_soft() {
    [[ $# -gt 0 ]] || return 0
    if [[ "$SKIP_PACKAGES" == "yes" ]]; then
        note "not installing (--skip-packages): $*"
        return 0
    fi
    if controlforge_pkg_install "$@"; then
        return 0
    fi
    warn "installing together failed; retrying package by package"
    local p
    for p in "$@"; do
        if ! controlforge_pkg_install "$p"; then
            warn "could not install '$p' - install it by hand if a later step needs it"
        fi
    done
}

# ---------------------------------------------------------------------------
# 1. packages
# ---------------------------------------------------------------------------
provision_packages() {
    if [[ "$SKIP_PACKAGES" == "yes" ]]; then
        say "skipping package installation (--skip-packages)"
        return 0
    fi
    say "installing packages for family '$DISTRO_FAMILY'"

    local -a common=(git curl openssl)
    local -a pkgs=()
    case "$DISTRO_FAMILY" in
        debian) pkgs=(python3 python3-venv python3-pip postgresql postgresql-contrib nginx nftables iproute2 nmap nodejs npm) ;;
        rhel)   pkgs=(python3 python3-pip postgresql-server postgresql-contrib nginx nftables iproute nmap nodejs npm) ;;
        arch)   pkgs=(python python-pip postgresql nginx nftables iproute2 nmap nodejs npm) ;;
        suse)   pkgs=(python3 python3-pip postgresql-server postgresql-contrib nginx nftables iproute2 nmap nodejs npm) ;;
    esac
    pkg_install_soft "${pkgs[@]}" "${common[@]}"

    # Node is optional: without it the API and the database still work, only the
    # web UI is missing. Saying so beats failing the whole provision.
    if ! controlforge_has node; then
        warn "node/npm are still missing - the frontend cannot be built on this host."
        warn "Install Node 20.19+ or 22.12+ and re-run ./provision.sh."
    fi
}

# ---------------------------------------------------------------------------
# 2. PostgreSQL cluster
# ---------------------------------------------------------------------------
provision_postgres() {
    if controlforge_pg_start; then
        say "PostgreSQL is running (data directory: $(controlforge_pg_datadir), major: $(controlforge_pg_major))"
        return 0
    fi

    say "no running PostgreSQL; initialising a cluster"
    case "$DISTRO_FAMILY" in
        debian)
            # Debian keeps clusters under /usr/lib/postgresql/<version>/ and
            # manages them with pg_createcluster/pg_ctlcluster rather than a
            # single data directory.
            local ver=""
            ver="$(ls /usr/lib/postgresql 2>/dev/null | sort -V | tail -n1 || true)"
            if [[ -n "$ver" ]] && controlforge_has pg_createcluster; then
                say "  creating cluster $ver/main"
                pg_createcluster "$ver" main --start >/dev/null 2>&1 \
                    || warn "pg_createcluster reported a problem; continuing to see if a cluster is usable"
            fi
            ;;
        rhel)
            if controlforge_has postgresql-setup; then
                say "  initialising the data directory (postgresql-setup --initdb)"
                postgresql-setup --initdb >/dev/null 2>&1 \
                    || warn "postgresql-setup reported a problem; continuing"
            fi
            ;;
        arch)
            if [[ ! -s /var/lib/postgres/data/PG_VERSION ]]; then
                say "  initialising /var/lib/postgres/data"
                install -d -o postgres -g postgres -m 0700 /var/lib/postgres/data
                runuser -u postgres -- initdb -D /var/lib/postgres/data >/dev/null 2>&1 \
                    || warn "initdb reported a problem; continuing"
            fi
            ;;
        suse)
            # openSUSE's service initialises an empty data directory on first
            # start, so there is nothing to do before enabling it.
            ;;
    esac

    systemctl enable postgresql.service >/dev/null 2>&1 || true

    if ! controlforge_pg_start; then
        die "PostgreSQL did not start. Inspect it with:
       systemctl status postgresql.service
       journalctl -u postgresql.service -n 50
     then re-run ./provision.sh."
    fi
    say "PostgreSQL is up (data directory: $(controlforge_pg_datadir), major: $(controlforge_pg_major))"
}

# ---------------------------------------------------------------------------
# 3. service account
# ---------------------------------------------------------------------------
provision_accounts() {
    if getent group "$SERVICE_GROUP" >/dev/null; then
        say "group '$SERVICE_GROUP' already exists"
    else
        groupadd --system "$SERVICE_GROUP"
        say "created system group '$SERVICE_GROUP'"
    fi

    if getent passwd "$SERVICE_USER" >/dev/null; then
        say "account '$SERVICE_USER' already exists"
    else
        # A login shell is refused on purpose: this account only ever runs
        # systemd units, and a shell would be an interactive foothold on a host
        # whose whole purpose is to hold credentials.
        local nologin
        nologin="$(command -v nologin 2>/dev/null || printf '/usr/sbin/nologin')"
        [[ -x "$nologin" ]] || nologin="/bin/false"
        useradd --system \
                --gid "$SERVICE_GROUP" \
                --home-dir "$STATE_DIR" \
                --no-create-home \
                --shell "$nologin" \
                --comment "CONTROLFORGE service account" \
                "$SERVICE_USER"
        say "created system account '$SERVICE_USER' (shell $nologin, home $STATE_DIR)"
    fi

    # The state and config directories are created by install.sh; they are made
    # here too because bootstrap_db.sh runs before the human re-logins and needs
    # CONF_DIR to exist with the group already assigned.
    install -d -m 0750 -o root -g "$SERVICE_GROUP" "$CONF_DIR"
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$STATE_DIR"
    install -d -m 2770 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$STATE_DIR/evidence"
    install -d -m 2770 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$LOG_DIR"

    # So the operator can run ./test.sh, read the evidence store and read the log
    # directory without becoming root. Takes effect on the next login.
    if [[ "$BUILD_USER" != "root" ]] && ! id -nG "$BUILD_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$SERVICE_GROUP"; then
        usermod -aG "$SERVICE_GROUP" "$BUILD_USER"
        say "added '$BUILD_USER' to group '$SERVICE_GROUP' - log out and back in for it to take effect"
    fi
}

# ---------------------------------------------------------------------------
# 4. virtualenv
# ---------------------------------------------------------------------------
provision_venv() {
    local backend="$CONTROLFORGE_REPO_DIR/backend"
    local venv="$backend/.venv"
    local py; py="$(controlforge_python)"

    [[ -f "$backend/requirements.txt" ]] || die "missing $backend/requirements.txt"

    # The interpreter is recorded so a host that gains a newer Python later does
    # not silently rebuild the environment on a different version.
    if [[ -x "$venv/bin/python" ]]; then
        say "virtualenv already present ($("$venv/bin/python" -V 2>&1))"
    else
        say "creating virtualenv at $venv"
        as_build_user "$backend" "$py" -m venv "$venv"
    fi

    say "installing Python dependencies (wheel-only; this host has no Go/Rust toolchain)"
    # --only-binary=:all: fails loudly instead of attempting a source build. That
    # is deliberate: a dependency that ships no wheel cannot be built here, and
    # discovering that during a build is far better than discovering it at start.
    as_build_user "$backend" "$venv/bin/python" -m pip install --quiet --upgrade pip
    as_build_user "$backend" "$venv/bin/python" -m pip install --quiet --only-binary=:all: \
        -r "$backend/requirements.txt"

    local ver
    ver="$("$venv/bin/python" -c 'import fastapi, sqlalchemy, psycopg; print("fastapi", fastapi.__version__, "| sqlalchemy", sqlalchemy.__version__)')" \
        || die "the virtualenv is not importable; re-run after fixing the pip output above"
    say "virtualenv ready: $ver"
}

# ---------------------------------------------------------------------------
# 5. validation engines
# ---------------------------------------------------------------------------
provision_engines() {
    # nmap: packaged everywhere, and the only engine that needs a binary beyond
    # the Python probes.
    if controlforge_has nmap; then
        say "nmap present ($(nmap --version 2>/dev/null | head -n1))"
    else
        say "installing nmap"
        pkg_install_soft nmap || warn "nmap is still missing - the port/service tests will report INCONCLUSIVE"
    fi

    # testssl.sh: packaged on Debian/Ubuntu/Kali, not on the other families, so
    # there is a source fallback. It is a single shell script plus a data
    # directory, which is why cloning it is a legitimate install method here
    # rather than a hack.
    if controlforge_has testssl || controlforge_has testssl.sh; then
        say "testssl.sh present ($(command -v testssl || command -v testssl.sh))"
    else
        local pkg=""
        pkg="$(controlforge_pkg_resolve testssl.sh testssl 2>/dev/null || true)"
        if [[ -n "$pkg" ]]; then
            say "installing testssl.sh from the distribution ($pkg)"
            pkg_install_soft "$pkg" || warn "the '$pkg' package failed to install"
        fi
    fi
    if ! controlforge_has testssl && ! controlforge_has testssl.sh; then
        if controlforge_has git; then
            say "installing testssl.sh from source into /opt/testssl.sh"
            if [[ -d /opt/testssl.sh/.git ]]; then
                git -C /opt/testssl.sh pull --ff-only --quiet || warn "could not update /opt/testssl.sh"
            else
                git clone --depth 1 --quiet https://github.com/drwetter/testssl.sh /opt/testssl.sh \
                    || warn "cloning testssl.sh failed (no network?)"
            fi
            if [[ -x /opt/testssl.sh/testssl.sh ]]; then
                # Two names, because both spellings appear: the Debian package
                # installs `testssl`, the upstream script is `testssl.sh`.
                ln -sfn /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
                ln -sfn /opt/testssl.sh/testssl.sh /usr/local/bin/testssl
                say "testssl.sh installed at /usr/local/bin/testssl"
            fi
        else
            warn "git is unavailable, so testssl.sh could not be installed from source"
        fi
    fi

    # sslscan is the fallback the TLS engine uses when testssl.sh is absent.
    if ! controlforge_has sslscan; then
        pkg_install_soft sslscan || true
    fi

    # nuclei is not packaged by any of these distributions; it ships as a Go
    # binary, and this host has no Go toolchain. Reported rather than installed.
    if controlforge_has nuclei; then
        say "nuclei present ($(nuclei -version 2>&1 | head -n1))"
    else
        warn "nuclei is not installed. It is not packaged by these distributions;"
        warn "install it from a release binary or from Go, then re-run ./provision.sh."
        warn "The nuclei-based tests will report INCONCLUSIVE until then."
    fi
}

# ---------------------------------------------------------------------------
# 6. frontend
# ---------------------------------------------------------------------------
provision_frontend() {
    local dir="$CONTROLFORGE_REPO_DIR/frontend"

    if [[ "$SKIP_FRONTEND" == "yes" ]]; then
        say "skipping the frontend build (--skip-frontend)"
        return 0
    fi
    [[ -f "$dir/package.json" ]] || { warn "no frontend/package.json; skipping the UI build"; return 0; }

    if ! controlforge_has node || ! controlforge_has npm; then
        warn "node/npm are not installed; skipping the frontend build - the API works, the UI will 404"
        return 0
    fi

    # The build tool refuses to run on an older runtime, and its error message is
    # a stack trace, so the version is checked here where the fix can be stated.
    local major minor
    major="$(node -p 'process.versions.node.split(".")[0]')"
    minor="$(node -p 'process.versions.node.split(".")[1]')"
    local ok="no"
    if   (( major > 22 ));        then ok="yes"
    elif (( major == 22 && minor >= 12 )); then ok="yes"
    elif (( major == 20 && minor >= 19 )); then ok="yes"
    fi
    if [[ "$ok" != "yes" ]]; then
        warn "node $(node -v) is too old to build the frontend (the build tool needs"
        warn "Node 20.19+ or 22.12+). The API will run; the UI will 404 until the"
        warn "frontend is built on a suitable runtime and ./provision.sh is re-run."
        return 0
    fi

    if [[ -f "$dir/package-lock.json" ]]; then
        say "installing frontend dependencies (npm ci)"
        as_build_user "$dir" npm ci --no-audit --no-fund
    else
        say "installing frontend dependencies (npm install; no lockfile present)"
        as_build_user "$dir" npm install --no-audit --no-fund
    fi

    say "building the frontend"
    as_build_user "$dir" npm run build

    [[ -f "$dir/dist/index.html" ]] || die "the frontend build produced no frontend/dist/index.html"
    say "frontend built into $dir/dist"
}

# ---------------------------------------------------------------------------
# 7. wire the tree into the host
# ---------------------------------------------------------------------------
provision_install() {
    say "running install.sh (units, nginx site, sudoers rule, recorded settings)"
    CONTROLFORGE_REPO_DIR="$CONTROLFORGE_REPO_DIR" \
    SERVICE_USER="$SERVICE_USER" SERVICE_GROUP="$SERVICE_GROUP" \
    CONF_DIR="$CONF_DIR" STATE_DIR="$STATE_DIR" LOG_DIR="$LOG_DIR" \
    API_BIND="$API_BIND" API_PORT="$API_PORT" \
    DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_NAME="$DB_NAME" DB_TEST_NAME="$DB_TEST_NAME" \
    DB_USER="$DB_USER" FW_DB_USER="$FW_DB_USER" \
    ADMIN_USERNAME="$ADMIN_USERNAME" EXPOSE_LAN="$EXPOSE_LAN" \
    BUILD_LAB="$BUILD_LAB" SEED_CATALOG="$SEED_CATALOG" \
        "$CONTROLFORGE_REPO_DIR/install.sh"
}

# ---------------------------------------------------------------------------
# 8. database and secrets
# ---------------------------------------------------------------------------
provision_database() {
    say "bootstrapping the database and generating secrets"
    # Reuses existing secrets if the file is already there, so re-provisioning
    # never invalidates a running deployment.
    SEED_CATALOG="$SEED_CATALOG" \
        "$CONTROLFORGE_REPO_DIR/scripts/bootstrap_db.sh"
}

# ---------------------------------------------------------------------------
# 9. schema and seed data
# ---------------------------------------------------------------------------
provision_migrate() {
    local backend="$CONTROLFORGE_REPO_DIR/backend"
    local py="$backend/.venv/bin/python"

    # pydantic-settings reads the connection string and the admin password from
    # this file. Handing the path over as an environment variable keeps the
    # secrets off the command line, where they would otherwise be visible to any
    # user via `ps` for the duration of the migration.
    export CONTROLFORGE_ENV_FILE="$CONF_DIR/controlforge.env"
    [[ -r "$CONTROLFORGE_ENV_FILE" ]] || die "missing $CONTROLFORGE_ENV_FILE - bootstrap_db.sh did not write it"

    say "applying database migrations"
    ( cd "$backend" && "$backend/.venv/bin/alembic" upgrade head )

    say "seeding the administrator and (optionally) the catalog"
    # Idempotent: an existing administrator is left alone, and the catalog is
    # inserted only when the tables are empty. The password is read from the env
    # file, never printed, never passed as an argument.
    ( cd "$backend" && "$py" -m app.seed )
}

# ---------------------------------------------------------------------------
# 10. start
# ---------------------------------------------------------------------------
provision_start() {
    if [[ "$DO_START" != "yes" ]]; then
        return 0
    fi
    say "starting the stack"
    "$CONTROLFORGE_REPO_DIR/start.sh"

    if [[ "$BUILD_LAB" == "yes" ]]; then
        if controlforge_has docker; then
            say "starting the test lab"
            "$CONTROLFORGE_REPO_DIR/scripts/lab_up.sh" --with-juice || warn "the lab did not start; the platform itself is unaffected"
        else
            warn "docker is not installed, so the test lab was not started"
        fi
    fi
}

summary() {
    local lan_ip=""
    [[ "$EXPOSE_LAN" == "yes" ]] && lan_ip="$(detect_lan_ip || true)"

    printf '\n'
    say "provisioning complete"
    printf '\n'
    printf '  Web UI        http://127.0.0.1/\n'
    if [[ -n "$lan_ip" ]]; then
        printf '                http://%s/\n' "$lan_ip"
    else
        printf '                (loopback only - LAN exposure is off or no address was found)\n'
    fi
    printf '  API           http://%s:%s/api\n' "$API_BIND" "$API_PORT"
    printf '  Database      %s on %s:%s (test database: %s)\n' "$DB_NAME" "$DB_HOST" "$DB_PORT" "$DB_TEST_NAME"
    printf '  Evidence      %s/evidence\n' "$STATE_DIR"
    printf '  Settings      %s/install.conf\n' "$CONF_DIR"
    printf '\n'
    printf '  Secrets       passwords and keys are in %s/controlforge.env and %s/fw.env\n' "$CONF_DIR" "$CONF_DIR"
    printf '                (root:%s, mode 0640 and 0600 - never committed, logged or printed)\n' "$SERVICE_GROUP"
    printf '  Admin login   %s, password value stored in CONTROLFORGE_ADMIN_INITIAL_PASSWORD in that file;\n' "$ADMIN_USERNAME"
    printf '                you are asked to change it at first sign-in.\n'
    printf '\n'
    if [[ "$DO_START" == "yes" ]]; then
        printf '  Manage it     ./status.sh   ./stop.sh   ./restart.sh   ./test.sh\n'
    else
        printf '  Next          ./start.sh     then:  ./status.sh\n'
    fi
    printf '\n'
}

provision_packages
provision_postgres
provision_accounts
provision_venv
provision_engines
provision_frontend
provision_install
provision_database
provision_migrate
provision_start
summary
