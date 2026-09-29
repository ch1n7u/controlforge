#!/usr/bin/env bash
#
# CONTROLFORGE installer - wires a checked-out tree into the host. Idempotent: safe
# to run any number of times.
#
# What it does:
#   * creates the state directories and sets their ownership and modes
#   * renders the systemd units from deploy/systemd/*.in with this host's
#     paths and account name, installs them, and enables them
#   * renders and installs the nginx site for the right layout for this
#     distribution, and validates it before anything is reloaded
#   * renders the sudoers drop-in and validates it with visudo first
#   * records the resolved settings in <CONF_DIR>/install.conf
#
# What it does NOT do: install packages, create the service account, build the
# virtualenv or the frontend, or create the database. Those are provision.sh's
# job, because they are the parts that differ per distribution. Running
# install.sh on a host that has not been provisioned is a mistake, so it checks
# for the account and stops with a pointer rather than half-installing.
#
# Nothing is started here: starting the stack is ./start.sh's job, so an
# install can never surprise a running machine.
#
# Settings come from, in increasing priority:
#   scripts/lib.sh defaults  ->  <CONF_DIR>/install.conf  ->  the environment.
# e.g.  sudo SERVICE_USER=svc EXPOSE_LAN=no ./install.sh
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONTROLFORGE_REPO_DIR="$REPO_ROOT"
export CONTROLFORGE_REPO_DIR

# shellcheck source=scripts/lib.sh
source "$REPO_ROOT/scripts/lib.sh"

CONTROLFORGE_LOG_TAG="install"
controlforge_load_install_conf

# Forced after the config file is read, not before: the units must point at the
# tree that is actually running this script. If the repository has been moved,
# an install.conf written by the previous location would otherwise be rendered
# back into every unit, and the services would start from a directory that no
# longer exists.
CONTROLFORGE_REPO_DIR="$REPO_ROOT"
export CONTROLFORGE_REPO_DIR

[[ ${EUID} -eq 0 ]] || exec sudo -- "$0" "$@"

controlforge_require_systemd

# --- 0. templates present ----------------------------------------------------
templates=(
    "$REPO_ROOT/deploy/systemd/controlforge-api.service.in"
    "$REPO_ROOT/deploy/systemd/controlforge-worker.service.in"
    "$REPO_ROOT/deploy/systemd/controlforge-fw-sync.service.in"
    "$REPO_ROOT/deploy/systemd/controlforge-fw-sync.timer.in"
    "$REPO_ROOT/deploy/nginx/controlforge.conf.in"
    "$REPO_ROOT/deploy/sudoers/controlforge.in"
)
extra_required=(
    "$REPO_ROOT/scripts/sync_firewall.py"
    "$REPO_ROOT/deploy/nftables/controlforge.nft"
    "$REPO_ROOT/scripts/lab_up.sh"
    "$REPO_ROOT/scripts/lab_down.sh"
)
for required in "${templates[@]}" "${extra_required[@]}"; do
    [[ -e "$required" ]] || die "missing deployment file: $required"
done

# --- 1. the account this will run as ----------------------------------------
# Created by provision.sh. install.sh does not create it: doing so would mean
# guessing a shell, a home directory and supplementary groups, and getting that
# wrong is worse than stopping here.
if ! getent passwd "$SERVICE_USER" >/dev/null; then
    die "the service account '$SERVICE_USER' does not exist.
       Run ./provision.sh first (it creates the account, the virtualenv, the
       database and the frontend build), or create the account by hand and
       re-run this script."
fi
if ! getent group "$SERVICE_GROUP" >/dev/null; then
    die "the service group '$SERVICE_GROUP' does not exist (expected alongside '$SERVICE_USER')"
fi

# --- 2. the account must be able to reach the code and the venv -------------
# The units run with ProtectHome=read-only, which still requires every parent
# directory of the repository to be traversable by the account. This is the
# single most common install failure on a hardened host, so it is checked up
# front with the exact permission that is missing.
python_bin="$REPO_ROOT/backend/.venv/bin/python"
if [[ ! -x "$python_bin" ]]; then
    warn "no virtualenv at backend/.venv - the units will fail until it is built (provision.sh does this)"
else
    if ! runuser -u "$SERVICE_USER" -- test -x "$python_bin" 2>/dev/null; then
        die "'$SERVICE_USER' cannot execute $python_bin.
       Every directory from / to the repository must be traversable (o+x).
       Check with:  namei -l $python_bin"
    fi
fi

# --- 3. config directory ------------------------------------------------------
install -d -m 0750 -o root -g "$SERVICE_GROUP" "$CONF_DIR"
if [[ ! -s "$CONF_DIR/controlforge.env" ]]; then
    warn "no $CONF_DIR/controlforge.env - the API will not start until provision.sh (or scripts/bootstrap_db.sh) writes it"
fi

# --- 4. state directories ----------------------------------------------------
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$STATE_DIR"
# 2770 + setgid on the evidence store: every artifact written by any process in
# the group lands group-owned, and nobody outside the group can read it.
install -d -m 2770 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$STATE_DIR/evidence"
# The fw-sync unit runs as root and only reads the config, but the scripts that
# write here run as the service account.
install -d -m 2770 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$LOG_DIR"
chmod 0750 "$STATE_DIR"
say "state directories ready ($STATE_DIR, $LOG_DIR)"

# --- 5. systemd units --------------------------------------------------------
for unit in controlforge-api.service controlforge-worker.service \
            controlforge-fw-sync.service controlforge-fw-sync.timer
do
    controlforge_render "$REPO_ROOT/deploy/systemd/${unit}.in" \
                   "/etc/systemd/system/${unit}" 0644
done
systemctl daemon-reload
# The timer keeps the worker's egress allow-list converged on the active scopes;
# the service is enabled as well so the ruleset is in place at boot even before
# the timer's first tick.
systemctl enable "$API_UNIT" "$WORKER_UNIT" "$FW_UNIT" "$FW_TIMER" >/dev/null
say "units installed and enabled for user '$SERVICE_USER' (api, worker, fw-sync + timer)"

# nginx is the UI's front door; without it enabled, a reboot leaves the stack
# up but the web UI unreachable until ./start.sh runs.
systemctl enable nginx.service >/dev/null 2>&1 \
    && say "nginx enabled at boot" \
    || warn "could not enable nginx.service at boot (is nginx installed?)"

# --- 6. nginx site -----------------------------------------------------------
# nginx has no single config layout across distributions: Debian and its
# derivatives use sites-available/, everything else drops files into conf.d/.
family="$(controlforge_distro_family)"
case "$family" in
    debian)
        NGINX_AVAIL=/etc/nginx/sites-available
        NGINX_ENABLED=/etc/nginx/sites-enabled
        ;;
    *)
        NGINX_AVAIL=/etc/nginx/conf.d
        NGINX_ENABLED=""
        ;;
esac
install -d -m 0755 "$NGINX_AVAIL"
NGINX_SITE="$NGINX_AVAIL/controlforge.conf"
controlforge_render "$REPO_ROOT/deploy/nginx/controlforge.conf.in" "$NGINX_SITE" 0644

if [[ "$EXPOSE_LAN" == "yes" ]]; then
    LAN_IP="$(detect_lan_ip || true)"
    if [[ -z "$LAN_IP" ]]; then
        warn "EXPOSE_LAN=yes but no global IPv4 address was found on a physical interface;"
        warn "the site will answer on loopback only. Re-run once the interface has an address."
    else
        # Rewrite the address on every line tagged #LAN_IP, keeping the marker
        # so the next run can find the line again.
        sed -i -E \
            -e "s|^([[:space:]]*listen[[:space:]]+)[0-9]{1,3}(\.[0-9]{1,3}){3}(:80;[[:space:]]*#LAN_IP.*)|\1${LAN_IP}\3|" \
            -e "s|^([[:space:]]*server_name[[:space:]].*[[:space:]])[0-9]{1,3}(\.[0-9]{1,3}){3}(;[[:space:]]*#LAN_IP.*)|\1${LAN_IP}\3|" \
            "$NGINX_SITE"
        grep -q '#LAN_IP' "$NGINX_SITE" || warn "no #LAN_IP markers found in the site file - LAN address not refreshed"
        say "nginx site installed for 127.0.0.1:80 and ${LAN_IP}:80"
    fi
else
    # EXPOSE_LAN=no: drop the tagged lines entirely so the site binds loopback
    # only. Removing the lines rather than leaving a stale address is what makes
    # this a real access-control decision and not a cosmetic one.
    sed -i '/#LAN_IP/d' "$NGINX_SITE"
    say "nginx site installed for 127.0.0.1:80 only (EXPOSE_LAN=no)"
fi

if [[ -n "$NGINX_ENABLED" ]]; then
    ln -sfn "$NGINX_SITE" "$NGINX_ENABLED/controlforge.conf"
    if [[ -e "$NGINX_ENABLED/default" ]]; then
        rm -f "$NGINX_ENABLED/default"
        say "disabled the nginx default site (file kept in sites-available/)"
    fi
else
    # Debian's default site lives in conf.d on other families; if the package
    # shipped one, it is a catch-all server on the same port and will shadow
    # this site for any Host it lists.
    for default_site in /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.d/default.conf; do
        if [[ -e "$default_site" ]]; then
            warn "$default_site exists and is a catch-all on port 80; if the UI"
            warn "returns the distribution's welcome page, disable that file and reload."
        fi
    done
fi

nginx -t || die "nginx rejected the configuration - nothing was reloaded"
say "nginx configuration validates (nginx not reloaded)"

# --- 7. sudoers drop-in ------------------------------------------------------
SUDOERS_TMP="$(mktemp)"
trap 'rm -f "$SUDOERS_TMP"' EXIT
controlforge_render "$REPO_ROOT/deploy/sudoers/controlforge.in" "$SUDOERS_TMP" 0440
visudo -c -f "$SUDOERS_TMP" >/dev/null || die "sudoers drop-in failed visudo validation"
install -m 0440 -o root -g root "$SUDOERS_TMP" /etc/sudoers.d/controlforge
if visudo -c >/dev/null 2>&1; then
    say "sudoers drop-in installed and the full sudoers tree validates"
else
    warn "the full sudoers tree does not validate (pre-existing entries?); the drop-in itself passed"
fi

# --- 8. record the resolved settings ----------------------------------------
# Written last, after everything above succeeded, so a failed run cannot leave a
# config file claiming settings that were never applied. Values are the plain
# resolved ones - there are no secrets in any of them.
cat > "$CONF_DIR/install.conf" <<EOF
# Written by CONTROLFORGE install.sh on $(date '+%Y-%m-%d %H:%M:%S %z').
# Read by scripts/lib.sh. Contains no secrets - passwords and keys are in
# controlforge.env and fw.env in this directory.
#
# Edit a value here and re-run ./install.sh to apply it.
# (Do not edit while a lifecycle script is running.)
CONTROLFORGE_REPO_DIR="$REPO_ROOT"
SERVICE_USER="$SERVICE_USER"
SERVICE_GROUP="$SERVICE_GROUP"
CONF_DIR="$CONF_DIR"
STATE_DIR="$STATE_DIR"
LOG_DIR="$LOG_DIR"
API_BIND="$API_BIND"
API_PORT="$API_PORT"
DB_HOST="$DB_HOST"
DB_PORT="$DB_PORT"
DB_NAME="$DB_NAME"
DB_TEST_NAME="$DB_TEST_NAME"
DB_USER="$DB_USER"
FW_DB_USER="$FW_DB_USER"
ADMIN_USERNAME="$ADMIN_USERNAME"
EXPOSE_LAN="$EXPOSE_LAN"
BUILD_LAB="$BUILD_LAB"
SEED_CATALOG="$SEED_CATALOG"
EOF
chmod 0644 "$CONF_DIR/install.conf"
say "settings recorded in $CONF_DIR/install.conf"

# --- 9. summary ---------------------------------------------------------------
say "note: sudoers is read live by sudo; no reload is needed"
if [[ -d "$REPO_ROOT/frontend/dist" ]]; then
    say "frontend build found at frontend/dist"
else
    warn "frontend/dist does not exist yet - build the frontend; nginx will 404 until then"
fi
say "installed. Next: ./start.sh   (and 'systemctl reload nginx' to pick up the site now)"
