#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# MATRIX-TEXTVOICEVIDEO — Setup Script (Turnkey)
#
# Purpose:
#   - Create all runtime directories with correct ownership
#   - Generate .env ONLY if missing, or if --reset is used
#   - Write/overwrite all runtime configs (homeserver.yaml, nginx.conf, etc.)
#   - Bootstrap Synapse to generate signing keys + supporting files
#   - Generate self-signed TLS cert as fallback if Let's Encrypt fails
#   - Obtain Let's Encrypt certificate (best-effort, see port note below)
#   - Never overwrite repo scripts in ./scripts
#   - --reset wipes data + .env and regenerates everything cleanly
#
# TLS / Certbot on Unraid:
#   Unraid's web GUI occupies host ports 80 and 443.  This stack's nginx
#   uses 60080 (HTTP) and 60443 (HTTPS) instead.  Your router must NAT:
#     WAN:80  → Unraid:60080
#     WAN:443 → Unraid:60443
#
#   The certbot attempt in this script runs a temporary nginx on port 80
#   (host) using the webroot method.  On Unraid this will FAIL because
#   port 80 is taken by the Unraid GUI — that is expected and safe.
#   Setup falls back to a self-signed certificate automatically so the
#   stack can still start.  Once the stack is running, obtain a real cert:
#     ./scripts/certbot-init.sh
#   That script stops nginx, binds :60080, and runs certbot standalone.
#
# Usage:
#   sudo bash setup.sh --domain chat.example.com
#   sudo bash setup.sh --domain chat.example.com --external-ip 1.2.3.4
#   sudo bash setup.sh --domain chat.example.com --no-tls
#   sudo bash setup.sh --domain chat.example.com --behind-proxy
#   sudo bash setup.sh --domain chat.example.com --reset
#   sudo bash setup.sh --domain chat.example.com --enable-registration
#
# After setup:
#   docker compose up -d
#   ./scripts/create-user.sh admin --admin
#
# Flags:
#   --domain <FQDN>          Required. Your public domain name.
#   --external-ip <IP>       Public WAN IP (auto-detected if omitted).
#   --data-dir <path>        Override data directory.
#   --admin-email <email>    Let's Encrypt registration email.
#   --tz <timezone>          Container timezone (default: America/Chicago).
#   --no-tls                 HTTP-only mode. Skip TLS entirely.
#                            Use for: LAN-only, testing, or when an EXTERNAL
#                            reverse proxy (NPM, Traefik, Caddy) handles TLS
#                            BEFORE traffic reaches this machine.
#   --behind-proxy           Configures nginx for upstream reverse-proxy mode.
#                            Nginx listens HTTP-only internally; TLS is
#                            terminated by your external proxy (NPM, Traefik,
#                            etc.) before traffic reaches this stack.
#                            See: README.md — "Using an External Reverse Proxy"
#   --reset                  DESTRUCTIVE: wipe DATA_DIR and .env then
#                            regenerate everything cleanly from scratch.
#   --enable-registration    Enable Synapse open user registration.
#                            Default is disabled — use create-user.sh instead.
###############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

msg()  { echo -e "${CYAN}$*${NC}"; }
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠ $*${NC}"; }
die()  { echo -e "${RED}ERROR: $*${NC}"; exit 1; }

usage() {
  cat <<EOF
Usage: $0 --domain <FQDN> [options]

Required:
  --domain <FQDN>               Your public domain (e.g. chat.example.com)

Optional:
  --external-ip <IP>            Public WAN IP (auto-detected if omitted)
  --data-dir <path>             Default: /mnt/user/appdata/matrix-textvoicevideo/data
  --admin-email <email>         Default: admin@DOMAIN
  --tz <timezone>               Default: America/Chicago
  --no-tls                      HTTP-only — skip all TLS/certbot.
                                Use for: LAN/testing, OR when an external
                                proxy (NPM, Traefik, Caddy) handles TLS
                                for you before traffic reaches this host.
  --behind-proxy                Configure nginx for reverse-proxy mode.
                                Nginx listens HTTP internally; your external
                                proxy (NPM/Traefik/Caddy) terminates TLS.
                                See README — "Using an External Reverse Proxy"
  --reset                       DESTRUCTIVE: wipe DATA_DIR and .env, then
                                regenerate everything from scratch.
  --enable-registration         Enable open user registration in Synapse.
  -h, --help                    Show this help

TLS mode guide:
  Default (no flags)       Nginx handles TLS. Certbot obtains Let's Encrypt cert.
                           On Unraid, initial certbot attempt will fail gracefully
                           (port 80 taken by Unraid GUI). Self-signed cert used
                           as fallback. Run ./scripts/certbot-init.sh afterwards.

  --no-tls                 Nginx HTTP-only. No certs generated at all.
                           Use when an external proxy OUTSIDE this machine
                           does TLS, or for LAN/testing use.

  --behind-proxy           Nginx HTTP-only internally. Stack expects
                           X-Forwarded-Proto: https headers from upstream proxy.
                           TLS cert is managed by the external proxy, not here.

Examples:
  sudo bash setup.sh --domain chat.example.com
  sudo bash setup.sh --domain chat.example.com --reset
  sudo bash setup.sh --domain chat.lan --no-tls
  sudo bash setup.sh --domain chat.example.com --behind-proxy
EOF
  exit 1
}

###############################################################################
# PARSE ARGUMENTS
###############################################################################
DOMAIN=""
EXTERNAL_IP=""
DATA_DIR=""
ADMIN_EMAIL=""
TIMEZONE="America/Chicago"
NO_TLS=false
BEHIND_PROXY=false
RESET=false
ENABLE_REG=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)              DOMAIN="${2:-}"; shift 2 ;;
    --external-ip)         EXTERNAL_IP="${2:-}"; shift 2 ;;
    --data-dir)            DATA_DIR="${2:-}"; shift 2 ;;
    --admin-email)         ADMIN_EMAIL="${2:-}"; shift 2 ;;
    --tz)                  TIMEZONE="${2:-}"; shift 2 ;;
    --no-tls)              NO_TLS=true; shift ;;
    --behind-proxy)        BEHIND_PROXY=true; NO_TLS=true; shift ;;
    --reset)               RESET=true; shift ;;
    --enable-registration) ENABLE_REG=true; shift ;;
    -h|--help)             usage ;;
    *) die "Unknown option: $1 — run with --help for usage." ;;
  esac
done

[[ -z "$DOMAIN" ]] && { warn "No --domain specified."; usage; }

# Basic domain validation
if ! echo "$DOMAIN" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'; then
  die "'$DOMAIN' does not look like a valid domain/hostname."
fi

# --behind-proxy implies --no-tls (nginx is HTTP internally)
# but we track them separately so .env and nginx.conf can be labelled correctly
[[ "$BEHIND_PROXY" == true ]] && NO_TLS=true

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
[[ -z "$DATA_DIR" ]] && DATA_DIR="/mnt/user/appdata/matrix-textvoicevideo/data"
MEET_DOMAIN="meet.${DOMAIN}"
[[ -z "$ADMIN_EMAIL" ]] && ADMIN_EMAIL="admin@${DOMAIN}"
ENV_FILE="${PROJECT_DIR}/.env"

echo ""
msg "═══════════════════════════════════════════════════════════════"
msg "  MATRIX-TEXTVOICEVIDEO — Setup"
msg "═══════════════════════════════════════════════════════════════"
msg "  Project:      ${PROJECT_DIR}"
msg "  Data Dir:     ${DATA_DIR}"
msg "  Domain:       ${DOMAIN}"
msg "  Meet domain:  ${MEET_DOMAIN}"
msg "  TLS mode:     $( [[ "$BEHIND_PROXY" == true ]] && echo "behind-proxy (external proxy handles TLS)" || ( [[ "$NO_TLS" == true ]] && echo "none (HTTP only)" || echo "self-managed (nginx + certbot)" ) )"
echo ""

###############################################################################
# RESET
# Wipes DATA_DIR and .env so everything regenerates on this run.
# Brings the stack down first to avoid file-in-use errors.
###############################################################################
if [[ "$RESET" == true ]]; then
  warn "DESTRUCTIVE RESET ENABLED"
  warn "This will permanently delete:"
  warn "  - ${DATA_DIR}  (all database data, media, certs, configs)"
  warn "  - ${ENV_FILE}  (all generated secrets)"
  echo ""
  read -r -p "Type YES to confirm wipe: " confirm
  if [[ "${confirm}" != "YES" ]]; then
    die "Aborted by user."
  fi

  msg "Stopping containers (if running)..."
  (cd "$PROJECT_DIR" && docker compose down -v 2>/dev/null) || \
  (cd "$PROJECT_DIR" && docker-compose down -v 2>/dev/null) || true

  rm -rf "$DATA_DIR"
  rm -f "$ENV_FILE"
  ok "Reset complete — all data wiped."
  echo ""
fi

###############################################################################
# IP DETECTION
# Tries multiple public IP detection services in order.
# Falls back to an internal IP if all fail.
# Override entirely with --external-ip if auto-detect gets the wrong address.
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
  echo "$ip"
}

if [[ -z "$EXTERNAL_IP" ]]; then
  msg "Detecting public IP..."
  EXTERNAL_IP="$(detect_external_ip)"
  [[ -z "$EXTERNAL_IP" ]] && die "Could not detect public IP. Re-run with --external-ip <IP>"
fi

INTERNAL_IP="$(detect_internal_ip)"
[[ -z "$INTERNAL_IP" ]] && INTERNAL_IP="127.0.0.1"

ok "External IP: ${EXTERNAL_IP}"
ok "Internal IP: ${INTERNAL_IP}"
echo ""

###############################################################################
# DIRECTORY STRUCTURE
# All mount paths that containers expect must exist before docker compose up.
# Docker will create missing directories as root, which breaks container
# user permissions — so we create them here with the right structure first.
###############################################################################
msg "Creating runtime directories..."

mkdir -p \
  "${DATA_DIR}/postgres" \
  "${DATA_DIR}/valkey" \
  "${DATA_DIR}/synapse/appdata" \
  "${DATA_DIR}/synapse/media_store" \
  "${DATA_DIR}/coturn/config" \
  "${DATA_DIR}/element-web/config" \
  "${DATA_DIR}/nginx/html/.well-known/matrix" \
  "${DATA_DIR}/nginx/html/.well-known/acme-challenge" \
  "${DATA_DIR}/nginx/certs" \
  "${DATA_DIR}/jitsi/prosody/config" \
  "${DATA_DIR}/jitsi/prosody/plugins" \
  "${DATA_DIR}/jitsi/jicofo" \
  "${DATA_DIR}/jitsi/jvb" \
  "${DATA_DIR}/jitsi/web"

ok "Directories created."
echo ""

###############################################################################
# PERMISSIONS
#
# Unraid runs Docker as root and uses nobody:users as the base ownership
# convention.  We apply a broad 777 base pass so all containers can always
# read/write their volumes regardless of which UID they run as internally.
# Sensitive files (secrets, keys, certs) are locked down to 600/700 below.
#
# Container UIDs that matter:
#   Synapse:   991:991   (matrixdotorg/synapse)
#   Nginx:     101:101   (nginx:alpine — www-data)
#   Postgres:  999:999   (postgres official image)
#   Coturn:    65534     (nobody — or root depending on image version)
###############################################################################
msg "Applying base permissions (Unraid-friendly: nobody:users 777)..."

chmod -R 777 "${DATA_DIR}" 2>/dev/null || true
chown -R nobody:users "${DATA_DIR}" 2>/dev/null || true

ok "Base permissions set."
echo ""

###############################################################################
# .env GENERATION
#
# .env is generated ONCE and never overwritten on re-runs (to preserve secrets).
# Use --reset to wipe and regenerate.
#
# All secrets are generated with openssl rand (cryptographically secure).
# The file is chmod 600 so only root can read it.
###############################################################################
gen_secret() { openssl rand -base64 48 | tr -d '/+=\n' | head -c 48; }
gen_pass()   { openssl rand -base64 32 | tr -d '/+=\n' | head -c 32; }

# Determine scheme and URLs based on TLS mode
SCHEME="https"
PUBLIC_URL="https://${DOMAIN}"
JITSI_PUBLIC_URL="https://${MEET_DOMAIN}"
NO_TLS_STR="false"
BEHIND_PROXY_STR="false"

if [[ "$BEHIND_PROXY" == true ]]; then
  SCHEME="https"             # Public URL is still https (proxy handles it)
  PUBLIC_URL="https://${DOMAIN}"
  JITSI_PUBLIC_URL="https://${MEET_DOMAIN}"
  NO_TLS_STR="true"
  BEHIND_PROXY_STR="true"
elif [[ "$NO_TLS" == true ]]; then
  SCHEME="http"
  PUBLIC_URL="http://${DOMAIN}"
  JITSI_PUBLIC_URL="http://${MEET_DOMAIN}"
  NO_TLS_STR="true"
fi

if [[ ! -f "$ENV_FILE" ]]; then
  msg "Generating .env (full commented template)..."

  POSTGRES_PASSWORD="$(gen_pass)"
  SYNAPSE_REGISTRATION_SECRET="$(gen_secret)"
  SYNAPSE_MACAROON_KEY="$(gen_secret)"
  SYNAPSE_FORM_SECRET="$(gen_secret)"
  TURN_SECRET="$(gen_secret)"
  JICOFO_AUTH_PASSWORD="$(gen_pass)"
  JVB_AUTH_PASSWORD="$(gen_pass)"

  cat > "$ENV_FILE" <<EOF
###############################################################################
# matrix-textvoicevideo · Auto-generated $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Domain: ${DOMAIN}
#
# IMPORTANT:
#   - This file contains secrets — keep private (chmod 600).
#   - Do NOT change the IDENTITY section after first run (breaks existing data).
#   - Re-run setup.sh --reset to wipe and regenerate everything from scratch.
#   - Re-run setup.sh (without --reset) to safely update configs only.
###############################################################################

############################
# IDENTITY — DO NOT CHANGE AFTER FIRST RUN
# These values are baked into the Synapse signing key and database.
# Changing them after first run will break federation and require a full reset.
############################
SERVER_NAME="${DOMAIN}"
PUBLIC_URL="${PUBLIC_URL}"
SCHEME="${SCHEME}"

############################
# TLS MODE
# NO_TLS=true    → nginx runs HTTP-only (no certs needed)
# BEHIND_PROXY   → nginx HTTP internally; upstream proxy handles TLS
# Both false     → nginx manages TLS directly via certbot/self-signed
############################
NO_TLS="${NO_TLS_STR}"
BEHIND_PROXY="${BEHIND_PROXY_STR}"
ADMIN_EMAIL="${ADMIN_EMAIL}"

############################
# NETWORK
############################
EXTERNAL_IP="${EXTERNAL_IP}"
INTERNAL_IP="${INTERNAL_IP}"

############################
# POSTGRES
# POSTGRES_INITDB_ARGS: C locale is REQUIRED by Synapse — do not change.
############################
POSTGRES_USER="synapse"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD}"
POSTGRES_DB="synapse"
POSTGRES_INITDB_ARGS="--encoding=UTF8 --lc-collate=C --lc-ctype=C"

############################
# SYNAPSE SECRETS
# Generated once. Changing these after first run will invalidate
# all existing user sessions and access tokens.
############################
SYNAPSE_REGISTRATION_SECRET="${SYNAPSE_REGISTRATION_SECRET}"
SYNAPSE_MACAROON_KEY="${SYNAPSE_MACAROON_KEY}"
SYNAPSE_FORM_SECRET="${SYNAPSE_FORM_SECRET}"

############################
# TURN / COTURN
# Shared secret for HMAC token auth between Synapse and Coturn.
# Must match static-auth-secret in turnserver.conf.
############################
TURN_SECRET="${TURN_SECRET}"

############################
# PATHS
############################
DATA_DIR="${DATA_DIR}"

############################
# TIMEZONE
############################
TZ="${TIMEZONE}"

###############################################################################
# JITSI — Self-Hosted Video (meet.<SERVER_NAME>)
###############################################################################
JITSI_DOMAIN="${MEET_DOMAIN}"
JITSI_PUBLIC_URL="${JITSI_PUBLIC_URL}"

JITSI_AUTH_DOMAIN="auth.${MEET_DOMAIN}"
JITSI_INTERNAL_MUC_DOMAIN="internal-muc.${MEET_DOMAIN}"
JITSI_MUC_DOMAIN="muc.${MEET_DOMAIN}"

JICOFO_AUTH_PASSWORD="${JICOFO_AUTH_PASSWORD}"
JVB_AUTH_PASSWORD="${JVB_AUTH_PASSWORD}"

# JVB_ADVERTISE_IPS: Must be your PUBLIC WAN IP so remote clients can reach JVB.
JVB_ADVERTISE_IPS="${EXTERNAL_IP}"
JVB_PORT="10000"

# Disable Jitsi's built-in Let's Encrypt (nginx handles TLS for the whole stack)
JITSI_ENABLE_LETSENCRYPT="0"
JITSI_ENABLE_HTTP_REDIRECT="0"
EOF

  chmod 600 "$ENV_FILE"
  ok ".env created at ${ENV_FILE}"
else
  warn ".env already exists — preserving existing secrets."
  warn "(Use --reset to wipe and regenerate from scratch.)"
fi

###############################################################################
# LOAD .env
# Source it so all variables are available for writing config files below.
# set -a exports all sourced variables into the environment automatically.
###############################################################################
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

# Re-derive meet domain in case .env already existed with a different value
JITSI_DOMAIN="${JITSI_DOMAIN:-meet.${SERVER_NAME}}"

echo ""

###############################################################################
# WRITE RUNTIME CONFIGS
#
# All config files below are ALWAYS written/overwritten on every run.
# This means re-running setup.sh (without --reset) safely updates configs
# while keeping your existing .env, database data, and signing keys intact.
###############################################################################

# ── 1) Element Web config.json ───────────────────────────────────────────────
# Tells Element Web where its Matrix homeserver is and sets UI preferences.
# Jitsi domain is set here so Element Web knows where to open video calls.
msg "Writing Element Web config.json..."
cat > "${DATA_DIR}/element-web/config/config.json" <<EOF
{
  "default_server_config": {
    "m.homeserver": {
      "base_url": "${PUBLIC_URL}",
      "server_name": "${SERVER_NAME}"
    }
  },
  "disable_custom_urls": true,
  "disable_guests": true,
  "brand": "Matrix Chat",
  "default_theme": "dark",
  "room_directory": { "servers": ["${SERVER_NAME}"] },
  "show_labs_settings": false,
  "default_country_code": "US",
  "jitsi": { "preferred_domain": "${JITSI_DOMAIN}" },
  "jitsi_widget": { "skip_built_in_welcome_screen": true },
  "features": {
    "feature_video_rooms": false,
    "feature_group_calls": false,
    "feature_element_call_video_rooms": false
  }
}
EOF
ok "Element Web config.json written."

# ── 2) Synapse homeserver.yaml ────────────────────────────────────────────────
# Full Synapse configuration. Secrets are read from .env so they stay
# consistent across re-runs. This file is overwritten on every run —
# manual edits here will be lost unless added to setup.sh.
msg "Writing Synapse homeserver.yaml..."

# Build homeserver.yaml into a variable so we can write it twice
# (once now, once after key generation if needed)
write_homeserver_yaml() {
cat > "${DATA_DIR}/synapse/appdata/homeserver.yaml" <<EOF
# ─── Synapse Configuration ────────────────────────────────────────────────────
# Auto-generated by setup.sh — re-run setup.sh to update (no --reset needed).
# Use ./scripts/toggle-registration.sh on|off to manage open registration.

server_name: "${SERVER_NAME}"
public_baseurl: "${PUBLIC_URL}/"
pid_file: /data/homeserver.pid
serve_server_wellknown: true

listeners:
  - port: 8008
    tls: false
    type: http
    x_forwarded: true
    bind_addresses: ['0.0.0.0']
    resources:
      - names: [client, federation]
        compress: false

database:
  name: psycopg2
  args:
    user: "${POSTGRES_USER}"
    password: "${POSTGRES_PASSWORD}"
    database: "${POSTGRES_DB}"
    host: matrix-postgres
    port: 5432

redis:
  enabled: true
  host: matrix-valkey
  port: 6379

# Secrets — do not change after first run (invalidates sessions/tokens)
registration_shared_secret: "${SYNAPSE_REGISTRATION_SECRET}"
macaroon_secret_key: "${SYNAPSE_MACAROON_KEY}"
form_secret: "${SYNAPSE_FORM_SECRET}"

# Signing key — generated by 'docker run ... generate' bootstrap step below
signing_key_path: "/data/${SERVER_NAME}.signing.key"

# Federation key servers — empty means trust ourselves only (fully self-contained)
trusted_key_servers: []
report_stats: false

# Media store
media_store_path: /data/media_store

# Log config — generated by the 'generate' bootstrap step below
log_config: "/data/${SERVER_NAME}.log.config"

# Registration — disabled by default; use create-user.sh to add users
enable_registration: $([[ "$ENABLE_REG" == true ]] && echo "true" || echo "false")
enable_registration_without_verification: false

# TURN / Coturn — provides voice relay for clients behind strict NAT
turn_uris:
  - "turn:${SERVER_NAME}:3478?transport=udp"
  - "turn:${SERVER_NAME}:3478?transport=tcp"
  - "turns:${SERVER_NAME}:5349?transport=tcp"
turn_shared_secret: "${TURN_SECRET}"
turn_user_lifetime: 1h
turn_allow_guests: false
EOF
}

write_homeserver_yaml
chown -R 991:991 "${DATA_DIR}/synapse" 2>/dev/null || \
  warn "Could not chown synapse dir to 991:991 — may need to run as root."
chmod 600 "${DATA_DIR}/synapse/appdata/homeserver.yaml"
ok "Synapse homeserver.yaml written."

# ── 3) Synapse first-run key + log config generation ─────────────────────────
# Synapse requires two files to exist before it will start:
#   <SERVER_NAME>.signing.key  — cryptographic identity for federation
#   <SERVER_NAME>.log.config   — logging configuration
#
# 'docker run ... generate' creates both. It also writes a minimal
# homeserver.yaml which we immediately overwrite with our full config.
#
# This only runs once (signing key check). Re-runs skip it safely.
SIGNING_KEY="${DATA_DIR}/synapse/appdata/${SERVER_NAME}.signing.key"
if [[ ! -f "$SIGNING_KEY" ]]; then
  msg "Bootstrapping Synapse key generation..."
  msg "(Runs 'generate' to create signing key and log config — normal first-run step.)"
  echo ""

  if docker run --rm \
    -v "${DATA_DIR}/synapse/appdata:/data" \
    -e "SYNAPSE_SERVER_NAME=${SERVER_NAME}" \
    -e "SYNAPSE_REPORT_STATS=no" \
    matrixdotorg/synapse:latest \
    generate 2>&1; then

    ok "Synapse keys generated."

    # Re-apply ownership — generate runs as root and will chown files to root
    chown -R 991:991 "${DATA_DIR}/synapse" 2>/dev/null || true
    chmod -R 700 "${DATA_DIR}/synapse/appdata" 2>/dev/null || true
    chmod 600 "${DATA_DIR}/synapse/appdata/${SERVER_NAME}.signing.key" 2>/dev/null || true

    # Overwrite the minimal homeserver.yaml that 'generate' created with ours
    msg "Re-applying full homeserver.yaml over generated template..."
    write_homeserver_yaml
    chown -R 991:991 "${DATA_DIR}/synapse" 2>/dev/null || true
    chmod 600 "${DATA_DIR}/synapse/appdata/homeserver.yaml"
    ok "homeserver.yaml re-applied."

  else
    warn "Synapse key generation failed — Docker may not be available yet."
    warn "Re-run setup.sh after Docker is ready to complete key generation."
  fi
else
  ok "Synapse signing key already exists — skipping key generation."
fi
echo ""

# ── 4) Coturn turnserver.conf ────────────────────────────────────────────────
# TURN server config. Provides media relay for voice/video clients that
# cannot connect to Jitsi JVB directly (strict NAT, corporate firewalls).
# TURN_SECRET must match the value in .env / homeserver.yaml.
msg "Writing Coturn turnserver.conf..."
cat > "${DATA_DIR}/coturn/config/turnserver.conf" <<EOF
# ─── Coturn TURN/STUN Configuration ──────────────────────────────────────────
# Auto-generated by setup.sh

# Realm = your domain
realm=${SERVER_NAME}

# HMAC shared-secret auth — compatible with Synapse token generation.
# Do NOT add 'lt-cred-mech' here — it is incompatible with use-auth-secret.
use-auth-secret
static-auth-secret=${TURN_SECRET}

# Network binding
listening-ip=${INTERNAL_IP}
relay-ip=${INTERNAL_IP}
external-ip=${EXTERNAL_IP}/${INTERNAL_IP}

# Ports
listening-port=3478
tls-listening-port=5349
min-port=49160
max-port=49250

# TLS — certs shared from nginx via docker-compose volume mount
cert=/certs/fullchain.pem
pkey=/certs/privkey.pem

# Security hardening
fingerprint
no-cli
no-tlsv1
no-tlsv1_1

# SSRF protection — block relay to private/RFC1918 ranges
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
# Re-allow our own internal relay IP
allowed-peer-ip=${INTERNAL_IP}

# Logging
log-file=stdout
verbose
EOF
chmod 600 "${DATA_DIR}/coturn/config/turnserver.conf"
ok "Coturn config written."

# ── 5) Well-known Matrix discovery files ─────────────────────────────────────
# These files tell Matrix clients and remote servers where your homeserver is.
# Served by nginx at /.well-known/matrix/server and /.well-known/matrix/client
msg "Writing .well-known Matrix discovery files..."
cat > "${DATA_DIR}/nginx/html/.well-known/matrix/server" <<EOF
{ "m.server": "${SERVER_NAME}:443" }
EOF
cat > "${DATA_DIR}/nginx/html/.well-known/matrix/client" <<EOF
{ "m.homeserver": { "base_url": "${PUBLIC_URL}" } }
EOF
ok "Well-known files written."

# ── 6) Nginx config ───────────────────────────────────────────────────────────
# Three modes are written depending on TLS flags:
#
#   HTTPS mode (default):
#     - Port 80 for ACME challenge redirect + .well-known
#     - Port 443 for all HTTPS traffic
#     - Expects certs at: /etc/nginx/certs/live/<SERVER_NAME>/
#     - On Unraid, host ports are 60080/60443 (see docker-compose.yml)
#
#   --behind-proxy mode:
#     - Nginx listens HTTP only on port 80 (internally)
#     - Trusts X-Forwarded-Proto: https from upstream proxy
#     - External proxy (NPM/Traefik/Caddy) must forward:
#         proxy_pass http://UNRAID_IP:60080
#     - Synapse X-Forwarded-Proto handling is already enabled (x_forwarded: true)
#
#   --no-tls mode:
#     - Plain HTTP, no redirects, no TLS at all
#     - Use for LAN-only or pure HTTP testing
#
msg "Writing nginx.conf..."

if [[ "${BEHIND_PROXY}" == "true" ]]; then
  # ── Behind-proxy mode ─────────────────────────────────────────────────────
  # Nginx is the INTERNAL layer. TLS is terminated upstream by NPM/Traefik/Caddy.
  # The external proxy must set: proxy_set_header X-Forwarded-Proto https
  # Upstream proxy should forward to: http://UNRAID_IP:60080
  # (The 60080 host port maps to nginx container port 80)
  cat > "${DATA_DIR}/nginx/nginx.conf" <<EOF
# ─── Nginx — Behind External Reverse Proxy (HTTP-only internal) ───────────────
# Generated by setup.sh --behind-proxy
#
# This nginx instance handles INTERNAL routing only.
# TLS is terminated upstream by your external proxy (NPM, Traefik, Caddy, etc.)
#
# Your external proxy must:
#   1. Forward traffic to http://UNRAID_IP:60080  (HTTP, no TLS to nginx)
#   2. Set header:  X-Forwarded-Proto: https
#   3. Set header:  X-Forwarded-For: \$remote_addr
#   4. Host header must match: ${SERVER_NAME} or ${JITSI_DOMAIN}
#
# See README.md — "Using an External Reverse Proxy" for full setup guide.

worker_processes auto;
worker_rlimit_nofile 8192;
error_log /var/log/nginx/error.log warn;

events { worker_connections 2048; }

http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  sendfile on;
  client_max_body_size 100M;
  proxy_read_timeout 600s;

  # Forward real client IP and protocol from upstream proxy
  proxy_set_header Host              \$host;
  proxy_set_header X-Real-IP         \$remote_addr;
  proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto \$http_x_forwarded_proto;

  upstream synapse    { server 172.42.0.3:8008; }
  upstream elementweb { server 172.42.0.4:80; }
  upstream jitsiweb   { server 172.42.0.22:80; }

  # Matrix + Element Web
  server {
    listen 80;
    server_name ${SERVER_NAME};

    location /.well-known/matrix/ {
      root /var/www/html;
      default_type application/json;
      add_header Access-Control-Allow-Origin "*" always;
    }

    location /.well-known/acme-challenge/ {
      root /var/www/certbot;
      try_files \$uri =404;
    }

    location /_matrix   { proxy_pass http://synapse; }
    location /_synapse  { proxy_pass http://synapse; }
    location /          { proxy_pass http://elementweb; }
  }

  # Jitsi Meet
  server {
    listen 80;
    server_name ${JITSI_DOMAIN};

    location / { proxy_pass http://jitsiweb; }
  }
}
EOF

elif [[ "${NO_TLS}" == "true" ]]; then
  # ── No-TLS mode ────────────────────────────────────────────────────────────
  # Plain HTTP only. No redirects, no certs.
  # Use for: LAN-only testing, development, or when EXTERNAL proxy
  # on a different machine does TLS termination.
  cat > "${DATA_DIR}/nginx/nginx.conf" <<EOF
# ─── Nginx — HTTP-only mode (--no-tls) ───────────────────────────────────────
# Generated by setup.sh --no-tls
# No TLS — all traffic is plain HTTP.

worker_processes auto;
worker_rlimit_nofile 8192;
error_log /var/log/nginx/error.log warn;

events { worker_connections 2048; }

http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  sendfile on;
  client_max_body_size 100M;
  proxy_read_timeout 600s;

  proxy_set_header Host              \$host;
  proxy_set_header X-Real-IP         \$remote_addr;
  proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto \$scheme;

  upstream synapse    { server 172.42.0.3:8008; }
  upstream elementweb { server 172.42.0.4:80; }
  upstream jitsiweb   { server 172.42.0.22:80; }

  server {
    listen 80;
    server_name ${SERVER_NAME};

    location /.well-known/matrix/ {
      root /var/www/html;
      default_type application/json;
      add_header Access-Control-Allow-Origin "*" always;
    }

    location /.well-known/acme-challenge/ {
      root /var/www/certbot;
    }

    location /_matrix   { proxy_pass http://synapse; }
    location /_synapse  { proxy_pass http://synapse; }
    location /          { proxy_pass http://elementweb; }
  }

  server {
    listen 80;
    server_name ${JITSI_DOMAIN};
    location / { proxy_pass http://jitsiweb; }
  }
}
EOF

else
  # ── HTTPS mode (default) ───────────────────────────────────────────────────
  # Nginx handles TLS directly.
  # Certs expected at: /etc/nginx/certs/live/${SERVER_NAME}/
  # On Unraid: host port 60080 → nginx:80, host port 60443 → nginx:443
  # (Router NAT: WAN:80 → Unraid:60080, WAN:443 → Unraid:60443)
  cat > "${DATA_DIR}/nginx/nginx.conf" <<EOF
# ─── Nginx — HTTPS mode ───────────────────────────────────────────────────────
# Generated by setup.sh (default TLS mode)
#
# Cert paths:
#   /etc/nginx/certs/live/${SERVER_NAME}/fullchain.pem
#   /etc/nginx/certs/live/${SERVER_NAME}/privkey.pem
#
# Unraid port mapping (set in docker-compose.yml):
#   Host :60080 → nginx :80   (HTTP / ACME challenge)
#   Host :60443 → nginx :443  (HTTPS)
#   Router NAT: WAN:80 → Unraid:60080, WAN:443 → Unraid:60443

worker_processes auto;
worker_rlimit_nofile 8192;
error_log /var/log/nginx/error.log warn;

events { worker_connections 2048; }

http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  sendfile on;
  client_max_body_size 100M;
  proxy_read_timeout 600s;

  proxy_set_header Host              \$host;
  proxy_set_header X-Real-IP         \$remote_addr;
  proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto \$scheme;

  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

  upstream synapse    { server 172.42.0.3:8008; }
  upstream elementweb { server 172.42.0.4:80; }
  upstream jitsiweb   { server 172.42.0.22:80; }

  # HTTP → HTTPS redirect + ACME challenge passthrough
  server {
    listen 80;
    server_name ${SERVER_NAME} ${JITSI_DOMAIN};

    # ACME challenge: served from webroot for certbot webroot method
    location /.well-known/acme-challenge/ {
      root /var/www/certbot;
      try_files \$uri =404;
    }
    # Matrix well-known: some clients check over plain HTTP too
    location /.well-known/matrix/ {
      root /var/www/html;
      default_type application/json;
      add_header Access-Control-Allow-Origin "*" always;
    }
    # Everything else: redirect to HTTPS
    location / {
      return 301 https://\$host\$request_uri;
    }
  }

  # Matrix + Element Web — HTTPS
  server {
    listen 443 ssl;
    http2 on;
    server_name ${SERVER_NAME};

    ssl_certificate     /etc/nginx/certs/live/${SERVER_NAME}/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/live/${SERVER_NAME}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;

    location /.well-known/matrix/ {
      root /var/www/html;
      default_type application/json;
      add_header Access-Control-Allow-Origin "*" always;
    }

    location /_matrix   { proxy_pass http://synapse; }
    location /_synapse  { proxy_pass http://synapse; }
    location /          { proxy_pass http://elementweb; }
  }

  # Jitsi Meet — HTTPS
  server {
    listen 443 ssl;
    http2 on;
    server_name ${JITSI_DOMAIN};

    ssl_certificate     /etc/nginx/certs/live/${SERVER_NAME}/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/live/${SERVER_NAME}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / { proxy_pass http://jitsiweb; }
  }
}
EOF
fi
ok "nginx.conf written."

###############################################################################
# TLS CERTIFICATES
#
# Strategy (only runs when NOT --no-tls and NOT --behind-proxy):
#   1. Attempt Let's Encrypt via webroot (best-effort)
#      - Spins up a temporary nginx container on port 80
#      - On Unraid this WILL FAIL — port 80 is taken by the Unraid GUI
#      - That failure is expected and handled gracefully
#   2. If Let's Encrypt fails: generate a self-signed certificate
#      - Self-signed allows nginx and coturn to start immediately
#      - Browser will show a security warning — this is expected
#      - Replace with a real cert by running: ./scripts/certbot-init.sh
#
# After running certbot-init.sh (standalone mode, uses port 60080):
#   - Stops nginx to free port 60080
#   - Runs certbot with -p 60080:80 (router NAT: WAN:80 → Unraid:60080)
#   - Restarts nginx with the real cert
###############################################################################
if [[ "${NO_TLS}" != "true" ]]; then
  CERT_LIVE_DIR="${DATA_DIR}/nginx/certs/live/${SERVER_NAME}"
  CERT_FULL="${CERT_LIVE_DIR}/fullchain.pem"
  CERT_KEY="${CERT_LIVE_DIR}/privkey.pem"

  mkdir -p "${CERT_LIVE_DIR}"
  chmod -R 755 "${DATA_DIR}/nginx/certs" 2>/dev/null || true

  echo ""
  msg "Attempting Let's Encrypt certificate (best-effort)..."
  warn "Requirements for success:"
  warn "  - DNS A record: ${SERVER_NAME}  → ${EXTERNAL_IP}"
  warn "  - DNS A record: ${JITSI_DOMAIN} → ${EXTERNAL_IP}"
  warn "  - Port 80 reachable from the internet (NOT available on Unraid — expected)"
  warn ""
  warn "On Unraid: this step will fail because Unraid owns port 80."
  warn "That is NORMAL. A self-signed cert will be generated as fallback."
  warn "Run ./scripts/certbot-init.sh after the stack is running to get a real cert."
  echo ""

  mkdir -p "${DATA_DIR}/nginx/html/.well-known/acme-challenge"
  chmod -R 777 "${DATA_DIR}/nginx/html" 2>/dev/null || true

  # Temporary nginx for ACME webroot challenge
  # This will fail on Unraid (port 80 taken) — that's caught below
  cat > /tmp/matrix-acme-nginx.conf <<ACMECFG
events {}
http {
  server {
    listen 80;
    server_name ${SERVER_NAME} ${JITSI_DOMAIN};
    location /.well-known/acme-challenge/ {
      root /var/www/certbot;
      try_files \$uri =404;
    }
    location / {
      return 200 'ACME bootstrap';
      add_header Content-Type text/plain;
    }
  }
}
ACMECFG

  docker rm -f matrix-acme-bootstrap >/dev/null 2>&1 || true
  BOOTSTRAP_OK=false
  if docker run -d --name matrix-acme-bootstrap \
    -v "/tmp/matrix-acme-nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "${DATA_DIR}/nginx/html:/var/www/certbot" \
    -p 80:80 \
    nginx:alpine >/dev/null 2>&1; then
    BOOTSTRAP_OK=true
    sleep 2
  else
    warn "Could not start bootstrap nginx on port 80 (expected on Unraid)."
  fi

  LE_SUCCESS=false
  if [[ "$BOOTSTRAP_OK" == "true" ]]; then
    if docker run --rm \
      -v "${DATA_DIR}/nginx/certs:/etc/letsencrypt" \
      -v "${DATA_DIR}/nginx/html:/var/www/certbot" \
      certbot/certbot certonly \
        --webroot -w /var/www/certbot \
        -d "${SERVER_NAME}" \
        -d "${JITSI_DOMAIN}" \
        --email "${ADMIN_EMAIL}" \
        --agree-tos \
        --non-interactive \
        --force-renewal 2>&1; then
      LE_SUCCESS=true
      ok "Let's Encrypt certificate obtained."
    else
      warn "Certbot failed — DNS not ready or challenge could not be completed."
    fi
  fi

  docker rm -f matrix-acme-bootstrap >/dev/null 2>&1 || true
  rm -f /tmp/matrix-acme-nginx.conf

  # ── Self-signed fallback ────────────────────────────────────────────────────
  # nginx and coturn will refuse to start without cert files present.
  # Self-signed certs allow the stack to start so you can verify everything
  # works before replacing them with a real Let's Encrypt cert.
  if [[ "$LE_SUCCESS" != "true" ]] || [[ ! -f "$CERT_FULL" ]] || [[ ! -f "$CERT_KEY" ]]; then
    warn "Generating self-signed TLS certificate as fallback..."
    warn "Browsers will show a security warning — replace with a real cert:"
    warn "  ./scripts/certbot-init.sh"

    if command -v openssl >/dev/null 2>&1; then
      openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "${CERT_KEY}" \
        -out "${CERT_FULL}" \
        -subj "/CN=${SERVER_NAME}/O=Matrix Self-Signed/C=US" \
        -addext "subjectAltName=DNS:${SERVER_NAME},DNS:${JITSI_DOMAIN}" \
        2>/dev/null
      chmod 644 "${CERT_FULL}"
      chmod 600 "${CERT_KEY}"
      ok "Self-signed cert generated at ${CERT_LIVE_DIR}"
    else
      warn "openssl not found — cannot generate self-signed cert."
      warn "Install openssl or provide certs manually at:"
      warn "  ${CERT_FULL}"
      warn "  ${CERT_KEY}"
    fi
  fi

  # Final cert permissions — readable by nginx (101) and coturn
  chmod -R 755 "${DATA_DIR}/nginx/certs" 2>/dev/null || true
  chmod 644 "${CERT_FULL}" 2>/dev/null || true
  chmod 600 "${CERT_KEY}" 2>/dev/null || true

else
  ok "TLS skipped ($( [[ "$BEHIND_PROXY" == "true" ]] && echo "--behind-proxy mode" || echo "--no-tls mode" ))."
fi

###############################################################################
# FINAL PERMISSIONS PASS
#
# After all config files are written, apply correct ownership and permissions.
# Sensitive files (keys, secrets, configs) are restricted to 600.
# Data directories that containers need to write to get appropriate access.
###############################################################################
msg "Finalizing permissions..."

# Synapse — UID 991 owns all appdata
chown -R 991:991 "${DATA_DIR}/synapse" 2>/dev/null || true
chmod 700 "${DATA_DIR}/synapse/appdata" 2>/dev/null || true
chmod 600 "${DATA_DIR}/synapse/appdata/homeserver.yaml" 2>/dev/null || true
[[ -f "${DATA_DIR}/synapse/appdata/${SERVER_NAME}.signing.key" ]] && \
  chmod 600 "${DATA_DIR}/synapse/appdata/${SERVER_NAME}.signing.key" 2>/dev/null || true

# Synapse media store — Synapse writes here at runtime
chown -R 991:991 "${DATA_DIR}/synapse/media_store" 2>/dev/null || true
chmod 755 "${DATA_DIR}/synapse/media_store" 2>/dev/null || true

# Coturn — restrict config (contains shared secret)
chmod 600 "${DATA_DIR}/coturn/config/turnserver.conf" 2>/dev/null || true

# Nginx html — world-readable (static files served by nginx)
chmod -R 755 "${DATA_DIR}/nginx/html" 2>/dev/null || true

# Postgres — UID 999 owns data dir, must be 700 (postgres enforces this)
chown -R 999:999 "${DATA_DIR}/postgres" 2>/dev/null || true
chmod 700 "${DATA_DIR}/postgres" 2>/dev/null || true

# .env — contains all secrets, readable only by root
chmod 600 "${ENV_FILE}" 2>/dev/null || true

ok "Permissions finalized."

###############################################################################
# MAKE REPO SCRIPTS EXECUTABLE
# Never overwrites content — just ensures all .sh files in scripts/ are
# executable so users can run them without 'bash' prefix.
###############################################################################
if [[ -d "${PROJECT_DIR}/scripts" ]]; then
  chmod +x "${PROJECT_DIR}/scripts/"*.sh 2>/dev/null || true
  ok "scripts/*.sh marked executable."
fi

###############################################################################
# DONE
###############################################################################
echo ""
ok "${BOLD}Setup Complete!${NC}"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Next steps:"
echo ""
echo "  1. Start the stack:"
echo "     cd ${PROJECT_DIR}"
echo "     docker compose up -d"
echo ""
echo "  2. Wait ~30s for Synapse + Postgres to initialise, then:"
echo "     ./scripts/create-user.sh admin --admin"
echo ""
echo "  3. Open in your browser:"
echo "     ${PUBLIC_URL}"
echo ""

if [[ "${BEHIND_PROXY}" == "true" ]]; then
  echo "  ── Behind-Proxy Mode ──────────────────────────────────────"
  echo "  Configure your external proxy (NPM/Traefik/Caddy) to:"
  echo "    Forward HTTPS → http://$(hostname -I | awk '{print $1}'):60080"
  echo "    Set header: X-Forwarded-Proto: https"
  echo "    Set header: X-Forwarded-For: \$remote_addr"
  echo "  See README.md — 'Using an External Reverse Proxy'"
  echo ""
elif [[ "${NO_TLS}" != "true" ]]; then
  echo "  ── TLS Status ─────────────────────────────────────────────"
  if [[ -f "${DATA_DIR}/nginx/certs/live/${SERVER_NAME}/fullchain.pem" ]]; then
    if openssl x509 -noout -issuer \
        -in "${DATA_DIR}/nginx/certs/live/${SERVER_NAME}/fullchain.pem" 2>/dev/null \
        | grep -qi "let.s encrypt"; then
      echo "  ✓ Real Let's Encrypt certificate in place."
    else
      echo "  ⚠ Self-signed certificate in place."
      echo "    Browsers will show a security warning."
      echo "    Once DNS is ready and port-forward is set, run:"
      echo "      ./scripts/certbot-init.sh"
    fi
  else
    echo "  ⚠ No certificate found."
    echo "    Run: ./scripts/certbot-init.sh"
  fi
fi
echo "═══════════════════════════════════════════════════════════════"
echo ""
