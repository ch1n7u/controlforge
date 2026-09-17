#!/usr/bin/env bash
# Valtros - database + secret bootstrap (idempotent)
#
# Creates the local PostgreSQL roles/database and generates the secret files.
# Safe to re-run: existing secrets are reused, roles are reconciled to match.
#
#   sudo ./scripts/bootstrap_db.sh            # roles + database + secrets
#   sudo ./scripts/bootstrap_db.sh grants     # (re)apply read-only grants after migrations
#
# Every name and path comes from scripts/lib.sh, which reads the recorded
# install settings from <CONF_DIR>/install.conf, so an install that used a
# different account name or database name bootstraps the same way.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VALTROS_REPO_DIR="$REPO_ROOT"
export VALTROS_REPO_DIR

# shellcheck source=scripts/lib.sh
source "$REPO_ROOT/scripts/lib.sh"

VALTROS_LOG_TAG="bootstrap_db"
valtros_load_install_conf

if [[ ${EUID} -ne 0 ]]; then
  exec sudo -- "$0" "$@"
fi

ENV_DIR="$CONF_DIR"
ENV_FILE="${ENV_DIR}/valtros.env"
FW_ENV_FILE="${ENV_DIR}/fw.env"
TEST_DB_NAME="${DB_TEST_NAME:-${DB_NAME}_test}"

log()  { printf '  %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

valtros_has openssl || fail "openssl is required to generate secrets and is not installed"
valtros_has psql    || fail "psql is not installed (install the PostgreSQL client package)"

gen_secret() { openssl rand -base64 48 | tr -d '/+=' | head -c 44; }

psql_super() { valtros_psql -v ON_ERROR_STOP=1 -q "$@"; }

# ---------------------------------------------------------------- secrets ----
generate_secrets() {
  if [[ -f "${ENV_FILE}" ]]; then
    log "secrets already present: ${ENV_FILE} (left untouched)"
    return
  fi

  log "generating secrets: ${ENV_FILE} and ${FW_ENV_FILE}"
  local db_pw secret_key fw_pw admin_pw
  db_pw=$(gen_secret)
  secret_key=$(gen_secret)
  fw_pw=$(gen_secret)
  admin_pw=$(openssl rand -base64 24 | tr -d '/+=' | head -c 20)

  install -d -o root -g "$SERVICE_GROUP" -m 0750 "${ENV_DIR}"

  umask 077
  {
    printf '# Valtros secrets - generated %s\n' "$(date -Is)"
    printf '# Keep this file out of version control, logs, screenshots and reports.\n'
    printf 'VALTROS_ENV=production\n'
    printf 'VALTROS_DB_URL=postgresql+psycopg://%s:%s@%s:%s/%s\n' "${DB_USER}" "${db_pw}" "${DB_HOST}" "${DB_PORT}" "${DB_NAME}"
    printf 'VALTROS_SECRET_KEY=%s\n' "${secret_key}"
    printf 'VALTROS_EVIDENCE_DIR=%s/evidence\n' "${STATE_DIR}"
    printf 'VALTROS_ADMIN_INITIAL_PASSWORD=%s\n' "${admin_pw}"
    # The account the seeder creates, and whether it also seeds the lab catalog.
    # Both are install-time choices rather than secrets, but they live here
    # because this is the file the seeder already reads.
    printf 'VALTROS_SEED_ADMIN_USERNAME=%s\n' "${ADMIN_USERNAME}"
    if [[ "${SEED_CATALOG:-yes}" == "yes" ]]; then
      printf 'VALTROS_AUTOSEED=true\n'
    else
      printf 'VALTROS_AUTOSEED=false\n'
    fi
  } > "${ENV_FILE}"

  printf 'VALTROS_FW_DB_URL=postgresql://%s:%s@%s:%s/%s\n' \
    "${FW_DB_USER}" "${fw_pw}" "${DB_HOST}" "${DB_PORT}" "${DB_NAME}" > "${FW_ENV_FILE}"

  chown "root:${SERVICE_GROUP}" "${ENV_FILE}"; chmod 0640 "${ENV_FILE}"
  chown root:root               "${FW_ENV_FILE}"; chmod 0600 "${FW_ENV_FILE}"
}

# The two install-time choices that are not secrets: which administrator account
# the seeder creates, and whether it also seeds the control catalog.
#
# They live in the secret file because that is the file the seeder already
# reads, but generate_secrets() deliberately leaves an existing file alone - so
# a host installed before these keys existed would never record a changed
# administrator name or a --no-seed decision. Reconciling them here keeps the
# "never overwrite a secret" rule while still letting a re-provision apply a
# non-secret choice. Values are written from the resolved settings, never read
# back out, so nothing here can print a password.
reconcile_env_options() {
  local tmp
  tmp="$(mktemp "${ENV_DIR}/.valtros.env.XXXXXX")"
  awk -v user="${ADMIN_USERNAME}" -v seed="${SEED_CATALOG:-yes}" '
    BEGIN { seen_user = 0; seen_seed = 0; autoseed = (seed == "yes") ? "true" : "false" }
    /^VALTROS_SEED_ADMIN_USERNAME=/ { print "VALTROS_SEED_ADMIN_USERNAME=" user; seen_user = 1; next }
    /^VALTROS_AUTOSEED=/             { print "VALTROS_AUTOSEED=" autoseed;        seen_seed = 1; next }
    { print }
    END {
      if (!seen_user) print "VALTROS_SEED_ADMIN_USERNAME=" user
      if (!seen_seed) print "VALTROS_AUTOSEED=" autoseed
    }
  ' "${ENV_FILE}" > "${tmp}"
  # install(1) rather than mv: the owner and mode are the point of this file,
  # and a temp file moved over it would carry mktemp's 0600 root-only mode.
  install -m 0640 -o root -g "${SERVICE_GROUP}" "${tmp}" "${ENV_FILE}"
  rm -f "${tmp}"
  log "recorded administrator username '${ADMIN_USERNAME}' and catalog seeding '${SEED_CATALOG:-yes}' in ${ENV_FILE}"
}

load_secrets() {
  [[ -f "${ENV_FILE}" ]] || fail "missing ${ENV_FILE} - run without arguments first"
  # shellcheck disable=SC1090
  set -a; source "${ENV_FILE}"; set +a
  DB_PW=$(printf '%s' "${VALTROS_DB_URL}" | sed -E 's#.*://[^:]+:([^@]+)@.*#\1#')
  [[ -n "${DB_PW}" ]] || fail "could not parse database password from VALTROS_DB_URL"
  # shellcheck disable=SC1090
  set -a; source "${FW_ENV_FILE}"; set +a
  FW_PW=$(printf '%s' "${VALTROS_FW_DB_URL}" | sed -E 's#.*://[^:]+:([^@]+)@.*#\1#')
  [[ -n "${FW_PW}" ]] || fail "could not parse read-only password from VALTROS_FW_DB_URL"
}

# ------------------------------------------------------------- collations ----
refresh_collations() {
  # A glibc upgrade between initdb and now leaves stale collation versions
  # recorded in the catalog, which makes CREATE DATABASE fail with
  # "template database has a collation version mismatch". Refreshing is a no-op
  # when everything is already in sync.
  local stale
  stale=$(psql_super -tAc "SELECT collname FROM pg_collation
                            WHERE collversion IS NOT NULL
                              AND collversion <> pg_collation_actual_version(oid);" 2>/dev/null || true)
  if [[ -n "${stale}" ]]; then
    log "refreshing stale collation versions"
    while read -r name; do
      [[ -n "${name}" ]] || continue
      printf 'ALTER COLLATION "%s" REFRESH VERSION;\n' "${name}" | psql_super -f - >/dev/null
    done <<< "${stale}"
  fi
  local db
  for db in template0 template1 postgres; do
    printf 'ALTER DATABASE %s REFRESH COLLATION VERSION;\n' "${db}" \
      | psql_super -f - >/dev/null 2>&1 || true
  done
}

# ------------------------------------------------------------------ roles ----
create_roles() {
  log "reconciling PostgreSQL roles and database"

  role_exists() { [[ "$(psql_super -tAc "SELECT 1 FROM pg_roles WHERE rolname='$1'")" == "1" ]]; }

  if role_exists "${DB_USER}"; then
    printf "ALTER ROLE %s WITH LOGIN PASSWORD '%s';\n" "${DB_USER}" "${DB_PW}" | psql_super -f - >/dev/null
  else
    printf "CREATE ROLE %s LOGIN PASSWORD '%s';\n" "${DB_USER}" "${DB_PW}" | psql_super -f - >/dev/null
  fi

  if role_exists "${FW_DB_USER}"; then
    printf "ALTER ROLE %s WITH LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE;\n" \
      "${FW_DB_USER}" "${FW_PW}" | psql_super -f - >/dev/null
  else
    printf "CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE;\n" \
      "${FW_DB_USER}" "${FW_PW}" | psql_super -f - >/dev/null
  fi

  # the read-only role must never be able to write anywhere
  psql_super -c "ALTER ROLE ${FW_DB_USER} SET default_transaction_read_only = on;" >/dev/null

  if [[ "$(psql_super -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'")" != "1" ]]; then
    log "creating database ${DB_NAME}"
    psql_super -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER} ENCODING 'UTF8' TEMPLATE template0;" >/dev/null
  else
    log "database ${DB_NAME} already exists"
  fi

  # Isolated database for the test suite; tests never touch production data.
  if [[ "$(psql_super -tAc "SELECT 1 FROM pg_database WHERE datname='${TEST_DB_NAME}'")" != "1" ]]; then
    log "creating database ${TEST_DB_NAME}"
    psql_super -c "CREATE DATABASE ${TEST_DB_NAME} OWNER ${DB_USER} ENCODING 'UTF8' TEMPLATE template0;" >/dev/null
  else
    log "database ${TEST_DB_NAME} already exists"
  fi
  psql_super -d "${TEST_DB_NAME}" -c "ALTER SCHEMA public OWNER TO ${DB_USER};" >/dev/null

  # schema ownership + revoke public schema write from everyone else
  psql_super -d "${DB_NAME}" -c "ALTER SCHEMA public OWNER TO ${DB_USER};" >/dev/null
  psql_super -d "${DB_NAME}" -c "REVOKE ALL ON SCHEMA public FROM PUBLIC;" >/dev/null
  psql_super -d "${DB_NAME}" -c "GRANT ALL ON SCHEMA public TO ${DB_USER};" >/dev/null
  psql_super -d "${DB_NAME}" -c "GRANT CONNECT ON DATABASE ${DB_NAME} TO ${FW_DB_USER};" >/dev/null
  psql_super -d "${DB_NAME}" -c "GRANT USAGE ON SCHEMA public TO ${FW_DB_USER};" >/dev/null
}

# ----------------------------------------------------------------- grants ----
apply_grants() {
  log "applying read-only grants for ${FW_DB_USER} (firewall sync role)"
  if psql_super -d "${DB_NAME}" -tAc \
      "SELECT 1 FROM pg_views WHERE schemaname='public' AND viewname='v_scope_firewall_rules'" | grep -q 1; then
    psql_super -d "${DB_NAME}" -c "GRANT SELECT ON v_scope_firewall_rules TO ${FW_DB_USER};" >/dev/null
    log "granted SELECT on v_scope_firewall_rules"
  else
    log "view v_scope_firewall_rules not present yet (run after migrations)"
  fi
}

# --------------------------------------------------------------- verify ------
verify() {
  log "verifying application connection"
  local url out
  url=$(printf '%s' "${VALTROS_DB_URL}" | sed -E 's#postgresql\+psycopg://#postgresql://#')
  out=$(psql "${url}" -tAc "SELECT 'app-role-ok';" 2>&1) || true
  if [[ "${out}" == *app-role-ok* ]]; then
    log "application role can connect"
  else
    fail "application role could not connect via TCP: ${out}"
  fi
  out=$(psql "postgresql://${FW_DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}" -tAc "SELECT 'fw-role-ok';" 2>&1) || true
  if [[ "${out}" == *fw-role-ok* ]]; then
    log "read-only role can connect"
  else
    log "read-only role cannot connect yet (expected before migrations)"
  fi
}

case "${1:-bootstrap}" in
  bootstrap) generate_secrets; reconcile_env_options; load_secrets; refresh_collations; create_roles; apply_grants; verify ;;
  grants)    load_secrets; apply_grants ;;
  *)         fail "unknown argument: $1" ;;
esac

log "bootstrap complete"
