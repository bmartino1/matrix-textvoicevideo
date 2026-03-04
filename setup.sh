#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# MATRIX-TEXTVOICEVIDEO — Setup + Bootstrap Script
#
# This single script does EVERYTHING needed before `docker compose up -d`:
#
#   1. Parse arguments, detect IPs
#   2. Create runtime directories
#   3. Generate .env (secrets, domain, IPs) — once, preserved on re-runs
#   4. Source .env so all variables are available
#   5. Write ALL config files (homeserver.yaml, nginx.conf, coturn, element-web,
#      Jitsi jvb.conf, sip-communicator, custom-config.js — all with real
#      values, NO placeholders left anywhere)
#   6. Bootstrap Synapse — 'docker run ... generate' to create signing key +
#      log.config (first-run only; skipped on re-runs)
#   7. Detect + clean stale Prosody config from previous bad runs
#   8. Generate TLS cert (Let's Encrypt best-effort, self-signed fallback)
#   9. Copy Prosody certs with correct permissions
#  10. Fix all permissions
#  11. Bootstrap Jitsi Prosody via compose (brief start to init config)
#
# DNS RECORDS NEEDED:
#   DOMAIN               → YOUR_WAN_IP
#   meet.DOMAIN          → YOUR_WAN_IP
#   turn.DOMAIN          → YOUR_WAN_IP  ← required for SNI TURN routing
#
# Usage:
#   sudo bash setup.sh --domain chat.example.com [options]
#
# Options:
#   --domain <FQDN>          Required. Your public FQDN.
#   --external-ip <IP>       Public WAN IP (auto-detected if omitted).
#   --data-dir <path>        Default: /mnt/user/appdata/matrix-textvoicevideo/data
#   --admin-email <email>    Used for Let's Encrypt. Default: admin@DOMAIN
#   --tz <timezone>          Default: America/Chicago
#   --no-tls                 HTTP-only (for LAN/testing or external proxy).
#   --behind-proxy           Nginx HTTP-only internally; upstream proxy does TLS.
#   --enable-registration    Allow public Synapse registration (default: off).
#   --reset                  DESTRUCTIVE: wipe DATA_DIR and .env, start fresh.
#   -h|--help                Show this help.
#
###############################################################################

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

msg()  { echo -e "${CYAN}$*${NC}"; }
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠ $*${NC}"; }
die()  { echo -e "${RED}ERROR: $*${NC}"; exit 1; }
banner(){ echo ""; msg "═══════════════════════════════════════════════════════════════"; msg "  $*"; msg "═══════════════════════════════════════════════════════════════"; echo ""; }

usage() {
  cat <<EOF
Usage: $0 --domain <FQDN> [options]

Required:
  --domain <FQDN>               Base domain (e.g. example.com)

Optional:
  --external-ip <IP>            Public WAN IP (auto-detect if omitted)
  --data-dir <path>             Default: /mnt/user/appdata/matrix-textvoicevideo/data
  --admin-email <email>         Default: admin@DOMAIN (Let's Encrypt)
  --tz <timezone>               Default: America/Chicago
  --no-tls                      Skip cert generation (LAN/testing)
  --behind-proxy                Same as --no-tls (external proxy terminates TLS)
  --enable-registration         Enable Synapse registration
  --reset                       DESTRUCTIVE: wipe DATA_DIR and .env and restart
  -h|--help                     Show this help
EOF
  exit 1
}

###############################################################################
# PARSE ARGS
###############################################################################
DOMAIN=""; EXTERNAL_IP=""; DATA_DIR=""; ADMIN_EMAIL=""
TIMEZONE="America/Chicago"; NO_TLS=false; BEHIND_PROXY=false
RESET=false; ENABLE_REG=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)              DOMAIN="${2:-}"; shift 2 ;;
    --external-ip)         EXTERNAL_IP="${2:-}"; shift 2 ;;
    --data-dir)            DATA_DIR="${2:-}"; shift 2 ;;
    --admin-email)         ADMIN_EMAIL="${2:-}"; shift 2 ;;
    --tz)                  TIMEZONE="${2:-}"; shift 2 ;;
    --no-tls)              NO_TLS=true; shift ;;
    --behind-proxy)        BEHIND_PROXY=true; NO_TLS=true; shift ;;
    --enable-registration) ENABLE_REG=true; shift ;;
    --reset)               RESET=true; shift ;;
    -h|--help)             usage ;;
    *) die "Unknown option: $1" ;;
  esac
done

[[ -z "$DOMAIN" ]] && { warn "Missing --domain"; usage; }

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
REF_DIR="${PROJECT_DIR}/reference"
[[ -d "$REF_DIR" ]] || die "Missing ${REF_DIR}. Your repo checkout is incomplete."

[[ -z "$DATA_DIR" ]] && DATA_DIR="/mnt/user/appdata/matrix-textvoicevideo/data"
MEET_DOMAIN="meet.${DOMAIN}"
TURN_DOMAIN="turn.${DOMAIN}"
[[ -z "$ADMIN_EMAIL" ]] && ADMIN_EMAIL="admin@${DOMAIN}"
ENV_FILE="${PROJECT_DIR}/.env"

banner "MATRIX-TEXTVOICEVIDEO — SETUP"
msg "  Project:   ${PROJECT_DIR}"
msg "  Data Dir:  ${DATA_DIR}"
msg "  Domain:    ${DOMAIN}"
msg "  Meet:      ${MEET_DOMAIN}"
msg "  Turn:      ${TURN_DOMAIN}"
msg "  TLS:       $([[ "$NO_TLS" == true ]] && echo 'disabled' || echo 'enabled')"
echo ""

###############################################################################
# HELPERS
###############################################################################
detect_external_ip() {
  curl -4 -sf --connect-timeout 5 --max-time 10 https://api.ipify.org 2>/dev/null \
    || curl -4 -sf --connect-timeout 5 --max-time 10 https://checkip.amazonaws.com 2>/dev/null \
    || curl -4 -sf --connect-timeout 5 --max-time 10 https://icanhazip.com 2>/dev/null \
    || true
}
detect_internal_ip() {
  local ip=""
  ip="$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1 || true)"
  [[ -z "$ip" ]] && ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  [[ -z "$ip" ]] && ip="127.0.0.1"
  echo "$ip"
}

# tmpl_subst <infile> <outfile>
# Replaces EVERY known __PLACEHOLDER__ with its real value.
# If you add a new placeholder to ANY reference file, add the sed line here too.
tmpl_subst() {
  local in="$1" out="$2"
  sed \
    -e "s|__SERVER_NAME__|${DOMAIN}|g" \
    -e "s|__MEET_DOMAIN__|${MEET_DOMAIN}|g" \
    -e "s|__TURN_DOMAIN__|${TURN_DOMAIN}|g" \
    -e "s|__PUBLIC_URL__|${PUBLIC_URL}|g" \
    -e "s|__MEET_PUBLIC_URL__|${MEET_PUBLIC_URL}|g" \
    -e "s|__SCHEME__|${SCHEME}|g" \
    -e "s|__EXTERNAL_IP__|${EXTERNAL_IP}|g" \
    -e "s|__INTERNAL_IP__|${INTERNAL_IP}|g" \
    -e "s|__TURN_SECRET__|${TURN_SECRET}|g" \
    -e "s|__POSTGRES_USER__|${POSTGRES_USER}|g" \
    -e "s|__POSTGRES_PASSWORD__|${POSTGRES_PASSWORD}|g" \
    -e "s|__POSTGRES_DB__|${POSTGRES_DB}|g" \
    -e "s|__SYNAPSE_REGISTRATION_SECRET__|${SYNAPSE_REGISTRATION_SECRET}|g" \
    -e "s|__SYNAPSE_MACAROON_KEY__|${SYNAPSE_MACAROON_KEY}|g" \
    -e "s|__SYNAPSE_FORM_SECRET__|${SYNAPSE_FORM_SECRET}|g" \
    -e "s|__ENABLE_REGISTRATION__|${ENABLE_REGISTRATION}|g" \
    -e "s|__ADMIN_EMAIL__|${ADMIN_EMAIL}|g" \
    "$in" > "$out"
}

gen_secret() { openssl rand -base64 48 | tr -d '/+=\n' | head -c 48; }
gen_pass()   { openssl rand -base64 32 | tr -d '/+=\n' | head -c 32; }

###############################################################################
# RESET
###############################################################################
if [[ "$RESET" == true ]]; then
  banner "RESET"
  warn "This will delete:"
  warn "  ${DATA_DIR}"
  warn "  ${ENV_FILE}"
  read -r -p "Type YES to confirm wipe: " confirm
  [[ "${confirm}" != "YES" ]] && die "Aborted."
  (cd "$PROJECT_DIR" && docker compose down -v 2>/dev/null) || true
  rm -rf "${DATA_DIR}"
  rm -f "${ENV_FILE}"
  ok "Reset complete."
fi

###############################################################################
# IP DETECTION
###############################################################################
banner "Step 1 — Detect IPs"
if [[ -z "${EXTERNAL_IP}" ]]; then
  msg "Detecting public WAN IP..."
  EXTERNAL_IP="$(detect_external_ip)"
  [[ -z "$EXTERNAL_IP" ]] && die "Could not detect public IP. Re-run with --external-ip <IP>"
fi
INTERNAL_IP="$(detect_internal_ip)"
ok "External IP: ${EXTERNAL_IP}"
ok "Internal IP: ${INTERNAL_IP}"

###############################################################################
# DIRECTORIES
###############################################################################
banner "Step 2 — Create Directories"
mkdir -p \
  "${DATA_DIR}/postgres" \
  "${DATA_DIR}/valkey" \
  "${DATA_DIR}/synapse/appdata" \
  "${DATA_DIR}/synapse/media_store" \
  "${DATA_DIR}/coturn/config" \
  "${DATA_DIR}/element-web/config" \
  "${DATA_DIR}/nginx/html/.well-known/matrix" \
  "${DATA_DIR}/nginx/html/.well-known/acme-challenge" \
  "${DATA_DIR}/nginx/certs/live/${DOMAIN}" \
  "${DATA_DIR}/jitsi/prosody" \
  "${DATA_DIR}/jitsi/prosody/prosody-plugins-custom" \
  "${DATA_DIR}/jitsi/jicofo/config" \
  "${DATA_DIR}/jitsi/jvb/config" \
  "${DATA_DIR}/jitsi/web/config"
ok "Directories ready."

###############################################################################
# .env (ONE TIME — secrets are preserved on re-runs)
###############################################################################
banner "Step 3 — .env"
SCHEME="https"; PUBLIC_URL="https://${DOMAIN}"; MEET_PUBLIC_URL="https://${MEET_DOMAIN}"
if [[ "$NO_TLS" == true ]]; then
  SCHEME="http"; PUBLIC_URL="http://${DOMAIN}"; MEET_PUBLIC_URL="http://${MEET_DOMAIN}"
fi

if [[ ! -f "$ENV_FILE" ]]; then
  POSTGRES_USER="synapse"
  POSTGRES_DB="synapse"
  POSTGRES_PASSWORD="$(gen_pass)"
  SYNAPSE_REGISTRATION_SECRET="$(gen_secret)"
  SYNAPSE_MACAROON_KEY="$(gen_secret)"
  SYNAPSE_FORM_SECRET="$(gen_secret)"
  TURN_SECRET="$(gen_secret)"
  JICOFO_AUTH_PASSWORD="$(gen_pass)"
  JVB_AUTH_PASSWORD="$(gen_pass)"
  ENABLE_REGISTRATION="$([[ "$ENABLE_REG" == true ]] && echo true || echo false)"

  cat > "$ENV_FILE" <<EOF
###############################################################################
# matrix-textvoicevideo · Auto-generated $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Domain: ${DOMAIN}
#
# KEEP THIS FILE PRIVATE — contains all secrets
# Do NOT change the IDENTITY section after first run (breaks existing data)
# Run setup.sh --reset to wipe and regenerate everything from scratch
#
# ALL values are quoted — required for bash 'source' and docker compose.
###############################################################################

############################
# IDENTITY — DO NOT CHANGE AFTER FIRST RUN
############################
SERVER_NAME="${DOMAIN}"
PUBLIC_URL="${PUBLIC_URL}"
SCHEME="${SCHEME}"

############################
# TLS MODE
############################
NO_TLS="$([[ "$NO_TLS" == true ]] && echo true || echo false)"
BEHIND_PROXY="$([[ "$BEHIND_PROXY" == true ]] && echo true || echo false)"
ADMIN_EMAIL="${ADMIN_EMAIL}"

############################
# NETWORK
############################
EXTERNAL_IP="${EXTERNAL_IP}"
INTERNAL_IP="${INTERNAL_IP}"

############################
# PATHS
############################
DATA_DIR="${DATA_DIR}"

############################
# TIMEZONE
############################
TZ="${TIMEZONE}"

############################
# POSTGRES
############################
POSTGRES_USER="${POSTGRES_USER}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD}"
POSTGRES_DB="${POSTGRES_DB}"
POSTGRES_INITDB_ARGS="--encoding=UTF8 --lc-collate=C --lc-ctype=C"

############################
# SYNAPSE SECRETS — DO NOT CHANGE AFTER FIRST RUN
############################
SYNAPSE_REGISTRATION_SECRET="${SYNAPSE_REGISTRATION_SECRET}"
SYNAPSE_MACAROON_KEY="${SYNAPSE_MACAROON_KEY}"
SYNAPSE_FORM_SECRET="${SYNAPSE_FORM_SECRET}"

############################
# TURN / COTURN
############################
TURN_SECRET="${TURN_SECRET}"

############################
# JITSI
############################
JICOFO_AUTH_PASSWORD="${JICOFO_AUTH_PASSWORD}"
JVB_AUTH_PASSWORD="${JVB_AUTH_PASSWORD}"

############################
# REGISTRATION
############################
ENABLE_REGISTRATION="${ENABLE_REGISTRATION}"
EOF
  chmod 600 "$ENV_FILE"
  ok ".env created."
else
  ok ".env exists — keeping secrets."
fi

# Source .env so all variables are available for tmpl_subst and the rest of the script
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

# Guard: if .env has a different SERVER_NAME than --domain, warn and use .env value.
# (Changing domains requires --reset to avoid data corruption.)
if [[ "${DOMAIN}" != "${SERVER_NAME}" ]]; then
  warn "CLI --domain (${DOMAIN}) differs from .env SERVER_NAME (${SERVER_NAME})."
  warn "Using ${SERVER_NAME} from .env. To change domains, re-run with --reset."
  DOMAIN="${SERVER_NAME}"
fi

# Derived values that tmpl_subst needs (always recompute — these are NOT secrets)
MEET_DOMAIN="meet.${DOMAIN}"
TURN_DOMAIN="turn.${DOMAIN}"
MEET_PUBLIC_URL="${SCHEME}://${MEET_DOMAIN}"
PUBLIC_URL="${SCHEME}://${DOMAIN}"

###############################################################################
# Generate docker-compose.yml FROM reference template
###############################################################################
banner "Step 4 — Generate docker-compose.yml (NO placeholders)"
[[ -f "${REF_DIR}/docker-compose.yml" ]] || die "Missing ${REF_DIR}/docker-compose.yml"

# The compose template uses __PLACEHOLDERS__ for values that must be baked in,
# and ${ENV_VARS} for values Docker Compose resolves at runtime from .env.
# We replace all __PLACEHOLDERS__ here.
tmp_compose="$(mktemp)"
sed \
  -e "s|__SERVER_NAME__|${SERVER_NAME}|g" \
  -e "s|__MEET_DOMAIN__|${MEET_DOMAIN}|g" \
  -e "s|__TURN_DOMAIN__|${TURN_DOMAIN}|g" \
  -e "s|__EXTERNAL_IP__|${EXTERNAL_IP}|g" \
  -e "s|__INTERNAL_IP__|${INTERNAL_IP}|g" \
  "${REF_DIR}/docker-compose.yml" > "${tmp_compose}"

# Sanity check: no double-underscore placeholders left (skip comment lines)
if grep -vE '^\s*#' "${tmp_compose}" | grep -qE '__[A-Z_]+__'; then
  warn "Remaining placeholders in compose:"
  grep -vE '^\s*#' "${tmp_compose}" | grep -nE '__[A-Z_]+__' || true
  die "compose generation failed — placeholders still present."
fi

mv "${tmp_compose}" "${PROJECT_DIR}/docker-compose.yml"
ok "docker-compose.yml written to project root."

# Structural validation — catch YAML/indentation errors immediately
msg "Validating compose file structure..."
if command -v docker &>/dev/null; then
  (cd "${PROJECT_DIR}" && docker compose -f docker-compose.yml config >/dev/null 2>&1) \
    || die "docker-compose.yml is invalid (docker compose config failed). Check YAML syntax."
  ok "docker-compose.yml passes structural validation."
else
  warn "Docker not available — skipping compose validation."
fi

###############################################################################
# Write configs from reference templates (ALL with real values)
###############################################################################
banner "Step 5 — Write Configs"

# --- Element config ---
if [[ -f "${REF_DIR}/element-config.json" ]]; then
  tmpl_subst "${REF_DIR}/element-config.json" "${DATA_DIR}/element-web/config/config.json"
else
  die "Missing reference/element-config.json"
fi
ok "Element config.json"

# --- Coturn config ---
if [[ -f "${REF_DIR}/turnserver.conf" ]]; then
  tmpl_subst "${REF_DIR}/turnserver.conf" "${DATA_DIR}/coturn/config/turnserver.conf"
else
  die "Missing reference/turnserver.conf"
fi
chmod 644 "${DATA_DIR}/coturn/config/turnserver.conf"
ok "Coturn turnserver.conf"

# --- Nginx config: choose by TLS mode ---
if [[ "${BEHIND_PROXY}" == "true" ]]; then
  tmpl_subst "${REF_DIR}/nginx-behind-proxy.conf" "${DATA_DIR}/nginx/nginx.conf"
elif [[ "${NO_TLS}" == "true" ]]; then
  tmpl_subst "${REF_DIR}/nginx-no-tls.conf" "${DATA_DIR}/nginx/nginx.conf"
else
  tmpl_subst "${REF_DIR}/nginx-https.conf" "${DATA_DIR}/nginx/nginx.conf"
fi
chmod 644 "${DATA_DIR}/nginx/nginx.conf"
ok "nginx.conf"

# --- Well-known files ---
tmpl_subst "${REF_DIR}/well-known-server.json" "${DATA_DIR}/nginx/html/.well-known/matrix/server"
tmpl_subst "${REF_DIR}/well-known-client.json" "${DATA_DIR}/nginx/html/.well-known/matrix/client"
chmod 644 "${DATA_DIR}/nginx/html/.well-known/matrix/server" "${DATA_DIR}/nginx/html/.well-known/matrix/client"
ok ".well-known files"

# --- JVB custom config (template substitution — NOT plain copy) ---
tmpl_subst "${REF_DIR}/custom-jvb.conf" "${DATA_DIR}/jitsi/jvb/custom-jvb.conf"
ok "JVB custom-jvb.conf"

# --- SIP communicator properties (template substitution — NOT plain copy) ---
tmpl_subst "${REF_DIR}/custom-sip-communicator.properties" "${DATA_DIR}/jitsi/jvb/custom-sip-communicator.properties"
ok "JVB custom-sip-communicator.properties"

# --- Jitsi Web custom-config.js (template substitution) ---
tmpl_subst "${REF_DIR}/custom-config.js" "${DATA_DIR}/jitsi/web/custom-config.js"
ok "Jitsi Web custom-config.js"

###############################################################################
# Synapse bootstrap (signing key + log config) – FIRST RUN ONLY
###############################################################################
banner "Step 6 — Synapse one-time generate (signing key)"
SIGNING_KEY="${DATA_DIR}/synapse/appdata/${SERVER_NAME}.signing.key"
if [[ ! -f "$SIGNING_KEY" ]]; then
  msg "Running synapse generate…"
  docker run --rm \
    -v "${DATA_DIR}/synapse/appdata:/data" \
    -e "SYNAPSE_SERVER_NAME=${SERVER_NAME}" \
    -e "SYNAPSE_REPORT_STATS=no" \
    matrixdotorg/synapse:latest generate

  # Overwrite the generated homeserver.yaml with our complete template
  # (the generate command creates a basic one; ours has all the right settings)
  if [[ -f "${REF_DIR}/homeserver.yaml" ]]; then
    tmpl_subst "${REF_DIR}/homeserver.yaml" "${DATA_DIR}/synapse/appdata/homeserver.yaml"
    ok "homeserver.yaml written from reference template."
  else
    die "Missing reference/homeserver.yaml — cannot configure Synapse."
  fi

  # log.config
  if [[ -f "${REF_DIR}/synapse-log.config" ]]; then
    cp -f "${REF_DIR}/synapse-log.config" "${DATA_DIR}/synapse/appdata/${SERVER_NAME}.log.config"
  fi
  ok "Synapse bootstrap complete."
else
  ok "Signing key exists — skipping generate."
  # Always refresh homeserver.yaml from template on re-runs
  # (picks up config changes without losing the signing key)
  if [[ -f "${REF_DIR}/homeserver.yaml" ]]; then
    tmpl_subst "${REF_DIR}/homeserver.yaml" "${DATA_DIR}/synapse/appdata/homeserver.yaml"
    ok "homeserver.yaml refreshed from template."
  fi
fi

###############################################################################
# Prosody stale config cleanup (prevents placeholder-poisoned boots)
###############################################################################
banner "Step 7 — Prosody stale config check"
PROSODY_CONF="${DATA_DIR}/jitsi/prosody/conf.d/jitsi-meet.cfg.lua"
PROSODY_MAIN="${DATA_DIR}/jitsi/prosody/prosody.cfg.lua"
PROSODY_DATA="${DATA_DIR}/jitsi/prosody/data"

_prosody_poisoned=false
if [[ -f "${PROSODY_CONF}" ]]; then
  if grep -qE '__MEET_DOMAIN__|__SERVER_NAME__|%5f%5f' "${PROSODY_CONF}" 2>/dev/null; then
    _prosody_poisoned=true
  fi
fi
if [[ -f "${PROSODY_MAIN}" ]]; then
  if grep -qE '__MEET_DOMAIN__|__SERVER_NAME__|%5f%5f' "${PROSODY_MAIN}" 2>/dev/null; then
    _prosody_poisoned=true
  fi
fi
# Check for URL-encoded placeholder directories (e.g. %5f%5fmeet%5fdomain%5f%5f)
if ls -d "${PROSODY_DATA}"/*%5f* 2>/dev/null | grep -q .; then
  _prosody_poisoned=true
fi

if [[ "${_prosody_poisoned}" == true ]]; then
  warn "Prosody config is contaminated with placeholder domains from a previous run."
  warn "Wiping Prosody generated config + data (your secrets in .env are safe)."
  rm -rf "${DATA_DIR}/jitsi/prosody/conf.d"
  rm -f  "${DATA_DIR}/jitsi/prosody/prosody.cfg.lua"
  rm -rf "${DATA_DIR}/jitsi/prosody/data"
  # Recreate dirs
  mkdir -p "${DATA_DIR}/jitsi/prosody/prosody-plugins-custom"
  ok "Prosody stale config wiped. It will regenerate on bootstrap."
else
  ok "Prosody config clean (no placeholder contamination)."
fi

###############################################################################
# TLS certs (optional)
###############################################################################
banner "Step 8 — TLS certs"
CERT_LIVE_DIR="${DATA_DIR}/nginx/certs/live/${SERVER_NAME}"
CERT_FULL="${CERT_LIVE_DIR}/fullchain.pem"
CERT_KEY="${CERT_LIVE_DIR}/privkey.pem"

if [[ "${NO_TLS}" == "true" ]]; then
  # Even in no-TLS mode, generate a self-signed cert so coturn volume mount
  # doesn't fail. Coturn won't actually use it for client connections in this mode.
  if [[ ! -s "${CERT_FULL}" || ! -s "${CERT_KEY}" ]]; then
    msg "Generating placeholder self-signed cert (coturn mount compatibility)..."
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
      -keyout "${CERT_KEY}" \
      -out "${CERT_FULL}" \
      -subj "/CN=${DOMAIN}/O=Matrix Self-Signed/C=US" \
      -addext "subjectAltName=DNS:${DOMAIN},DNS:${MEET_DOMAIN},DNS:auth.${MEET_DOMAIN},DNS:${TURN_DOMAIN}" \
      >/dev/null 2>&1
    ok "Placeholder self-signed cert created (TLS disabled mode)."
  fi
  ok "TLS disabled; skipping real cert generation."
else
  if [[ ! -s "${CERT_FULL}" || ! -s "${CERT_KEY}" ]]; then
    warn "No cert found; creating self-signed fallback."
    warn "Replace later with: ./scripts/certbot-init.sh"
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
      -keyout "${CERT_KEY}" \
      -out "${CERT_FULL}" \
      -subj "/CN=${DOMAIN}/O=Matrix Self-Signed/C=US" \
      -addext "subjectAltName=DNS:${DOMAIN},DNS:${MEET_DOMAIN},DNS:auth.${MEET_DOMAIN},DNS:${TURN_DOMAIN}" \
      >/dev/null 2>&1
    ok "Self-signed cert created."
  else
    ok "Cert exists."
  fi
fi

# Cert permissions: nginx + coturn + prosody all need to read these.
# Use 644 for both — the private key is readable within the container network only.
# (The host firewall / file-level access on DATA_DIR protects the key on disk.)
chmod 644 "${CERT_FULL}" "${CERT_KEY}" 2>/dev/null || true

###############################################################################
# Prosody cert/key alignment (prevents c2s "error loading private key (null)")
###############################################################################
banner "Step 9 — Prosody cert/key alignment"
PROSODY_CERT_DIR="${DATA_DIR}/jitsi/prosody/certs"
mkdir -p "${PROSODY_CERT_DIR}"

# Prosody expects cert/key filenames that match its virtual host names.
# The Jitsi prosody image runs as root inside the container, so 640 is fine.
cp -f "${CERT_FULL}" "${PROSODY_CERT_DIR}/${MEET_DOMAIN}.crt"
cp -f "${CERT_KEY}"  "${PROSODY_CERT_DIR}/${MEET_DOMAIN}.key"
cp -f "${CERT_FULL}" "${PROSODY_CERT_DIR}/auth.${MEET_DOMAIN}.crt"
cp -f "${CERT_KEY}"  "${PROSODY_CERT_DIR}/auth.${MEET_DOMAIN}.key"
chmod 644 "${PROSODY_CERT_DIR}"/*.crt 2>/dev/null || true
chmod 640 "${PROSODY_CERT_DIR}"/*.key 2>/dev/null || true
ok "Prosody certs installed for ${MEET_DOMAIN} + auth.${MEET_DOMAIN}"

###############################################################################
# Permissions (Unraid-friendly)
###############################################################################
banner "Step 10 — Permissions"
chown -R 999:999 "${DATA_DIR}/postgres" 2>/dev/null || true
chmod 700 "${DATA_DIR}/postgres" 2>/dev/null || true
chown -R 991:991 "${DATA_DIR}/synapse" 2>/dev/null || true
chmod 600 "${DATA_DIR}/synapse/appdata/homeserver.yaml" 2>/dev/null || true
chmod 600 "${ENV_FILE}" 2>/dev/null || true
# Jitsi containers need broad read/write — set 777 first, then tighten certs after
chmod -R 777 "${DATA_DIR}/jitsi" 2>/dev/null || true
# Re-apply Prosody cert perms (chmod -R 777 above just wiped them)
chmod 644 "${PROSODY_CERT_DIR}"/*.crt 2>/dev/null || true
chmod 640 "${PROSODY_CERT_DIR}"/*.key 2>/dev/null || true
ok "Permissions set."

###############################################################################
# Prosody bootstrap using docker compose (correct network/env)
###############################################################################
banner "Step 11 — Prosody bootstrap (compose network)"
msg "Starting jitsi-prosody briefly to ensure config exists…"
(
  cd "${PROJECT_DIR}"
  docker compose up -d jitsi-prosody
)

# Wait for prosody config to appear
WAIT=0
while [[ $WAIT -lt 45 ]]; do
  if [[ -f "${DATA_DIR}/jitsi/prosody/prosody.cfg.lua" || -f "${DATA_DIR}/jitsi/prosody/conf.d/jitsi-meet.cfg.lua" ]]; then
    ok "Prosody config present."
    break
  fi
  sleep 2
  WAIT=$((WAIT + 2))
done
if [[ $WAIT -ge 45 ]]; then
  warn "Prosody config did not appear within 45s — check 'docker logs jitsi-prosody'."
fi

# Stop it again so the full stack can start cleanly
(
  cd "${PROJECT_DIR}"
  docker compose stop jitsi-prosody >/dev/null 2>&1 || true
)
ok "Prosody bootstrap done."

###############################################################################
# Verify: no placeholders in any generated config
###############################################################################
banner "Step 12 — Final verification"
_found_placeholders=false
for check_file in \
  "${PROJECT_DIR}/docker-compose.yml" \
  "${DATA_DIR}/element-web/config/config.json" \
  "${DATA_DIR}/coturn/config/turnserver.conf" \
  "${DATA_DIR}/nginx/nginx.conf" \
  "${DATA_DIR}/synapse/appdata/homeserver.yaml" \
  "${DATA_DIR}/jitsi/jvb/custom-jvb.conf" \
  "${DATA_DIR}/jitsi/jvb/custom-sip-communicator.properties" \
  "${DATA_DIR}/jitsi/web/custom-config.js" \
  "${DATA_DIR}/nginx/html/.well-known/matrix/server" \
  "${DATA_DIR}/nginx/html/.well-known/matrix/client"
do
  if [[ -f "$check_file" ]] && grep -vE '^\s*#' "$check_file" 2>/dev/null | grep -qE '__[A-Z_]+__'; then
    warn "PLACEHOLDER found in: ${check_file}"
    grep -vE '^\s*#' "$check_file" | grep -nE '__[A-Z_]+__' | head -5
    _found_placeholders=true
  fi
done

if [[ "${_found_placeholders}" == true ]]; then
  die "Placeholder contamination detected. Fix the reference templates or tmpl_subst."
else
  ok "All generated configs verified — zero placeholders."
fi

###############################################################################
# DONE
###############################################################################
banner "DONE"
ok "${BOLD}Setup complete.${NC}"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Next steps:"
echo ""
echo "  1. Start the stack:"
echo "     cd ${PROJECT_DIR}"
echo "     docker compose up -d"
echo ""
echo "  2. Wait ~60s for Synapse + Postgres to initialize, then:"
echo "     ./scripts/create-user.sh admin --admin"
echo ""
echo "  3. Open in your browser:"
echo "     ${PUBLIC_URL}"
echo ""
echo "  ── Port Forwards Required ──────────────────────────────────"
echo "  WAN :80   → Host :60080   (HTTP / ACME challenge)"
echo "  WAN :443  → Host :60443   (HTTPS — Matrix + Element + Jitsi)"
echo "  WAN :3478 → Host :3478    (STUN/TURN UDP)"
echo "  WAN :5349 → Host :5349    (TURNS TLS — if not using SNI on 443)"
echo "  WAN :10000→ Host :10000   (JVB media — UDP, REQUIRED for video)"
echo "  WAN :49160-49250 → same   (Coturn relay range — UDP)"
echo ""
echo "  ── If using NPM / external proxy (--behind-proxy) ─────────"
echo "  NPM proxies ${DOMAIN}       → http://<host>:60080"
echo "  NPM proxies ${MEET_DOMAIN}  → http://<host>:60080"
echo "  JVB :10000/udp + Coturn ports still need direct NAT."
echo "═══════════════════════════════════════════════════════════════"
