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
#   - Obtain Let's Encrypt certificate (best-effort)
#   - Never overwrite repo scripts in ./scripts
#   - --reset wipes data + .env and regenerates everything cleanly
#
# Usage:
#   sudo bash setup.sh --domain chat.example.com
#   sudo bash setup.sh --domain chat.example.com --external-ip 1.2.3.4
#   sudo bash setup.sh --domain chat.example.com --no-tls
#   sudo bash setup.sh --domain chat.example.com --reset
#   sudo bash setup.sh --domain chat.example.com --enable-registration
#
# After setup:
#   docker compose up -d
#   ./scripts/create-user.sh admin --admin
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
  --domain <FQDN>               Server domain (e.g. chat.example.com)

Optional:
  --external-ip <IP>            Public WAN IP (auto-detected if omitted)
  --data-dir <path>             Default: /mnt/user/appdata/matrix-textvoicevideo/data
  --admin-email <email>         Default: admin@DOMAIN
  --tz <timezone>               Default: America/Chicago
  --no-tls                      HTTP only (LAN/testing, skips certbot)
  --reset                       DESTRUCTIVE: wipe DATA_DIR and .env then regenerate
  --enable-registration         Enable Synapse open registration (default: disabled)
  -h, --help                    Show this help

Examples:
  sudo bash setup.sh --domain chat.example.com
  sudo bash setup.sh --domain chat.example.com --reset
  sudo bash setup.sh --domain chat.lan --no-tls
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
RESET=false
ENABLE_REG=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)             DOMAIN="${2:-}"; shift 2 ;;
    --external-ip)        EXTERNAL_IP="${2:-}"; shift 2 ;;
    --data-dir)           DATA_DIR="${2:-}"; shift 2 ;;
    --admin-email)        ADMIN_EMAIL="${2:-}"; shift 2 ;;
    --tz)                 TIMEZONE="${2:-}"; shift 2 ;;
    --no-tls)             NO_TLS=true; shift ;;
    --reset)              RESET=true; shift ;;
    --enable-registration) ENABLE_REG=true; shift ;;
    -h|--help)            usage ;;
    *) die "Unknown option: $1 — run with --help for usage." ;;
  esac
done

[[ -z "$DOMAIN" ]] && { warn "No --domain specified."; usage; }

# Basic domain validation
if ! echo "$DOMAIN" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'; then
  die "'$DOMAIN' does not look like a valid domain/hostname."
fi

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
[[ -z "$DATA_DIR" ]] && DATA_DIR="/mnt/user/appdata/matrix-textvoicevideo/data"
MEET_DOMAIN="meet.${DOMAIN}"
[[ -z "$ADMIN_EMAIL" ]] && ADMIN_EMAIL="admin@${DOMAIN}"
ENV_FILE="${PROJECT_DIR}/.env"

echo ""
msg "Project:   ${PROJECT_DIR}"
msg "Data Dir:  ${DATA_DIR}"
msg "Domain:    ${DOMAIN}"
msg "Meet:      ${MEET_DOMAIN}"
echo ""

###############################################################################
# RESET
###############################################################################
if [[ "$RESET" == true ]]; then
  warn "DESTRUCTIVE RESET ENABLED"
  warn "This will delete:"
  warn "  - ${DATA_DIR}"
  warn "  - ${ENV_FILE}"
  echo ""
  read -r -p "Type YES to confirm wipe: " confirm
  if [[ "${confirm}" != "YES" ]]; then
    die "Aborted by user."
  fi

  # Bring stack down cleanly if running
  msg "Stopping containers..."
  (cd "$PROJECT_DIR" && docker compose down -v 2>/dev/null) || true
  (cd "$PROJECT_DIR" && docker-compose down -v 2>/dev/null) || true

  rm -rf "$DATA_DIR"
  rm -f "$ENV_FILE"
  ok "Reset complete."
  echo ""
fi

###############################################################################
# IP DETECTION
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
# All paths that containers expect must exist before docker compose up
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
# Unraid: base 777 so all containers can read/write
# Then lock down sensitive files to the correct UID
#
# Container UIDs:
#   Synapse:  991:991   (matrixdotorg/synapse)
#   Nginx:    101:101   (nginx:alpine — www-data equivalent)
#   Postgres: 999:999   (postgres)
#   Coturn:   65534:65534 (nobody — can also run as root)
###############################################################################
msg "Applying base permissions (Unraid-friendly)..."

# Global 777 first so Unraid docker/compose can always access
chmod -R 777 "${DATA_DIR}" 2>/dev/null || true
# Unraid uses nobody:users ownership convention
chown -R nobody:users "${DATA_DIR}" 2>/dev/null || true

ok "Base permissions set."
echo ""

###############################################################################
# .env GENERATION
# Only generates if missing. --reset deletes it first, so this always runs
# after reset. Preserves existing .env on re-runs without --reset.
###############################################################################
gen_secret() { openssl rand -base64 48 | tr -d '/+=\n' | head -c 48; }
gen_pass()   { openssl rand -base64 32 | tr -d '/+=\n' | head -c 32; }

SCHEME="https"
PUBLIC_URL="https://${DOMAIN}"
JITSI_PUBLIC_URL="https://${MEET_DOMAIN}"
NO_TLS_STR="false"

if [[ "$NO_TLS" == true ]]; then
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
# NOTE:
#   - This file contains secrets — keep private (chmod 600).
#   - DO NOT change IDENTITY section after first run (breaks existing data).
#   - Re-run setup.sh --reset to regenerate everything from scratch.
#   - Re-run setup.sh (no --reset) to update configs without wiping data.
###############################################################################

############################
# IDENTITY — DO NOT CHANGE AFTER FIRST RUN
############################
SERVER_NAME="${DOMAIN}"
PUBLIC_URL="${PUBLIC_URL}"
SCHEME="${SCHEME}"

############################
# NETWORK
############################
EXTERNAL_IP="${EXTERNAL_IP}"
INTERNAL_IP="${INTERNAL_IP}"

############################
# POSTGRES
############################
POSTGRES_USER="synapse"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD}"
POSTGRES_DB="synapse"
POSTGRES_INITDB_ARGS="--encoding=UTF8 --lc-collate=C --lc-ctype=C"

############################
# SYNAPSE SECRETS
############################
SYNAPSE_REGISTRATION_SECRET="${SYNAPSE_REGISTRATION_SECRET}"
SYNAPSE_MACAROON_KEY="${SYNAPSE_MACAROON_KEY}"
SYNAPSE_FORM_SECRET="${SYNAPSE_FORM_SECRET}"

############################
# TURN / COTURN
############################
TURN_SECRET="${TURN_SECRET}"

############################
# TLS / CERTBOT
############################
NO_TLS="${NO_TLS_STR}"
ADMIN_EMAIL="${ADMIN_EMAIL}"

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

JVB_ADVERTISE_IPS="${EXTERNAL_IP}"
JVB_PORT="10000"

JITSI_ENABLE_LETSENCRYPT="0"
JITSI_ENABLE_HTTP_REDIRECT="0"
EOF

  chmod 600 "$ENV_FILE"
  ok ".env created."
else
  warn ".env already exists — preserving secrets. (Use --reset to regenerate.)"
fi

###############################################################################
# LOAD .env so variables are available for config writing below
###############################################################################
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

# Re-derive meet domain in case .env already existed with different value
JITSI_DOMAIN="${JITSI_DOMAIN:-meet.${SERVER_NAME}}"

echo ""

###############################################################################
# WRITE RUNTIME CONFIGS
# Always written/overwritten so re-running setup.sh updates configs
# without needing --reset
###############################################################################

# ── 1) Element Web ──────────────────────────────────────────────────────────
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
ok "Element Web config written."

# ── 2) Synapse homeserver.yaml ───────────────────────────────────────────────
msg "Writing Synapse homeserver.yaml..."
cat > "${DATA_DIR}/synapse/appdata/homeserver.yaml" <<EOF
# ─── Synapse Configuration ───────────────────────────────────────────────────
# Auto-generated by setup.sh — re-run setup.sh to update (no --reset needed)
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

# Secrets (generated by setup.sh — do not change after first run)
registration_shared_secret: "${SYNAPSE_REGISTRATION_SECRET}"
macaroon_secret_key: "${SYNAPSE_MACAROON_KEY}"
form_secret: "${SYNAPSE_FORM_SECRET}"

# Signing key path (generated by Synapse on first start)
signing_key_path: "/data/${SERVER_NAME}.signing.key"

# Trusted key servers (empty = trust ourselves only)
trusted_key_servers: []
report_stats: false

# Media store
media_store_path: /data/media_store

# Logging
log_config: ""
log_level: WARNING

# Registration (disabled by default — use create-user.sh or toggle-registration.sh)
enable_registration: $([[ "$ENABLE_REG" == true ]] && echo "true" || echo "false")
enable_registration_without_verification: false

# TURN / Coturn
turn_uris:
  - "turn:${SERVER_NAME}:3478?transport=udp"
  - "turn:${SERVER_NAME}:3478?transport=tcp"
  - "turns:${SERVER_NAME}:5349?transport=tcp"
turn_shared_secret: "${TURN_SECRET}"
turn_user_lifetime: 1h
turn_allow_guests: false
EOF
# Synapse container runs as UID 991 — must own its config + data
chown -R 991:991 "${DATA_DIR}/synapse" 2>/dev/null || \
  warn "Could not chown synapse dir to 991:991 — may need to run as root."
chmod 600 "${DATA_DIR}/synapse/appdata/homeserver.yaml"
ok "Synapse homeserver.yaml written (owned by 991:991)."

# ── 3) Synapse first-run key generation ─────────────────────────────────────
# Synapse must run once with 'generate' to create:
#   - <SERVER_NAME>.signing.key  (federation signing key)
#   - <SERVER_NAME>.log.config   (log config)
# Without this, 'docker compose up' will fail on first run.
SIGNING_KEY="${DATA_DIR}/synapse/appdata/${SERVER_NAME}.signing.key"
if [[ ! -f "$SIGNING_KEY" ]]; then
  msg "Bootstrapping Synapse key generation..."
  msg "(Running 'generate' to create signing key and log config — this is normal.)"
  echo ""

  if docker run --rm \
    --user 991:991 \
    -v "${DATA_DIR}/synapse/appdata:/data" \
    -e "SYNAPSE_SERVER_NAME=${SERVER_NAME}" \
    -e "SYNAPSE_REPORT_STATS=no" \
    matrixdotorg/synapse:latest \
    generate 2>&1; then
    ok "Synapse keys generated."
    # Re-apply ownership after key gen (docker may create files as root)
    chown -R 991:991 "${DATA_DIR}/synapse" 2>/dev/null || true
    chmod -R 700 "${DATA_DIR}/synapse/appdata" 2>/dev/null || true
    chmod 600 "${DATA_DIR}/synapse/appdata/${SERVER_NAME}.signing.key" 2>/dev/null || true
    # Overwrite the generated homeserver.yaml with our full config
    # (generate creates a minimal one; ours has all the right settings)
    msg "Re-applying homeserver.yaml over generated template..."
    cat > "${DATA_DIR}/synapse/appdata/homeserver.yaml" <<EOF2
# ─── Synapse Configuration ───────────────────────────────────────────────────
# Auto-generated by setup.sh — re-run setup.sh to update (no --reset needed)
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

# Secrets (generated by setup.sh — do not change after first run)
registration_shared_secret: "${SYNAPSE_REGISTRATION_SECRET}"
macaroon_secret_key: "${SYNAPSE_MACAROON_KEY}"
form_secret: "${SYNAPSE_FORM_SECRET}"

# Signing key path (generated by Synapse on first start)
signing_key_path: "/data/${SERVER_NAME}.signing.key"

# Trusted key servers (empty = trust ourselves only)
trusted_key_servers: []
report_stats: false

# Media store
media_store_path: /data/media_store

# Logging
log_config: ""
log_level: WARNING

# Registration (disabled by default — use create-user.sh or toggle-registration.sh)
enable_registration: $([[ "$ENABLE_REG" == true ]] && echo "true" || echo "false")
enable_registration_without_verification: false

# TURN / Coturn
turn_uris:
  - "turn:${SERVER_NAME}:3478?transport=udp"
  - "turn:${SERVER_NAME}:3478?transport=tcp"
  - "turns:${SERVER_NAME}:5349?transport=tcp"
turn_shared_secret: "${TURN_SECRET}"
turn_user_lifetime: 1h
turn_allow_guests: false
EOF2
    chown -R 991:991 "${DATA_DIR}/synapse" 2>/dev/null || true
    chmod 600 "${DATA_DIR}/synapse/appdata/homeserver.yaml"
    ok "homeserver.yaml re-applied."
  else
    warn "Synapse key generation failed — check Docker is available."
    warn "If Docker is not available yet, run setup.sh again after installing Docker."
  fi
else
  ok "Synapse signing key already exists — skipping key generation."
fi
echo ""

# ── 4) Coturn turnserver.conf ────────────────────────────────────────────────
msg "Writing Coturn turnserver.conf..."
cat > "${DATA_DIR}/coturn/config/turnserver.conf" <<EOF
# ─── Coturn TURN/STUN Configuration ─────────────────────────────────────────
# Auto-generated by setup.sh

# Realm = your domain
realm=${SERVER_NAME}

# HMAC shared-secret auth (compatible with Synapse)
# Do NOT add lt-cred-mech — it is incompatible with use-auth-secret
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

# TLS (certs shared from nginx via docker-compose volume mount)
cert=/certs/fullchain.pem
pkey=/certs/privkey.pem

# Security
fingerprint
no-cli
no-tlsv1
no-tlsv1_1

# Block SSRF to local network (RFC1918)
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
# Re-allow our own relay/internal IP
allowed-peer-ip=${INTERNAL_IP}

# Logging
log-file=stdout
verbose
EOF
chmod 600 "${DATA_DIR}/coturn/config/turnserver.conf"
ok "Coturn config written."

# ── 5) Well-known Matrix discovery files ─────────────────────────────────────
msg "Writing .well-known Matrix discovery files..."
cat > "${DATA_DIR}/nginx/html/.well-known/matrix/server" <<EOF
{ "m.server": "${SERVER_NAME}:443" }
EOF
cat > "${DATA_DIR}/nginx/html/.well-known/matrix/client" <<EOF
{ "m.homeserver": { "base_url": "${PUBLIC_URL}" } }
EOF
ok "Well-known files written."

# ── 6) Nginx config ───────────────────────────────────────────────────────────
msg "Writing nginx.conf..."
if [[ "${NO_TLS}" == "true" ]]; then
  cat > "${DATA_DIR}/nginx/nginx.conf" <<EOF
# ─── Nginx — HTTP-only mode (--no-tls) ───────────────────────────────────────
# Auto-generated by setup.sh

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

  proxy_set_header Host \$host;
  proxy_set_header X-Real-IP \$remote_addr;
  proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
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
  cat > "${DATA_DIR}/nginx/nginx.conf" <<EOF
# ─── Nginx — HTTPS mode ───────────────────────────────────────────────────────
# Auto-generated by setup.sh
# Certs expected at: /etc/nginx/certs/live/${SERVER_NAME}/fullchain.pem
#                    /etc/nginx/certs/live/${SERVER_NAME}/privkey.pem
# If using self-signed fallback certs, they are placed there by setup.sh.

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

  proxy_set_header Host \$host;
  proxy_set_header X-Real-IP \$remote_addr;
  proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto \$scheme;

  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

  upstream synapse    { server 172.42.0.3:8008; }
  upstream elementweb { server 172.42.0.4:80; }
  upstream jitsiweb   { server 172.42.0.22:80; }

  # HTTP → HTTPS redirect + ACME challenge
  server {
    listen 80;
    server_name ${SERVER_NAME} ${JITSI_DOMAIN};

    location /.well-known/acme-challenge/ {
      root /var/www/certbot;
      try_files \$uri =404;
    }
    location /.well-known/matrix/ {
      root /var/www/html;
      default_type application/json;
      add_header Access-Control-Allow-Origin "*" always;
    }
    location / {
      return 301 https://\$host\$request_uri;
    }
  }

  # Matrix / Element HTTPS
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

  # Jitsi Meet HTTPS
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
# Strategy:
#   1. Try Let's Encrypt (best-effort, requires DNS + port 80 reachable)
#   2. If LE fails, generate a self-signed cert so nginx/coturn actually start
#   3. User can run ./scripts/certbot-init.sh later once DNS is ready
###############################################################################
if [[ "${NO_TLS}" != "true" ]]; then
  CERT_LIVE_DIR="${DATA_DIR}/nginx/certs/live/${SERVER_NAME}"
  CERT_FULL="${CERT_LIVE_DIR}/fullchain.pem"
  CERT_KEY="${CERT_LIVE_DIR}/privkey.pem"

  mkdir -p "${CERT_LIVE_DIR}"
  chmod -R 755 "${DATA_DIR}/nginx/certs" 2>/dev/null || true

  echo ""
  msg "Attempting Let's Encrypt certificate (best-effort)..."
  warn "Requirements:"
  warn "  - DNS A record: ${SERVER_NAME}     → ${EXTERNAL_IP}"
  warn "  - DNS A record: ${JITSI_DOMAIN} → ${EXTERNAL_IP}"
  warn "  - Port 80 reachable from the internet to this host"
  echo ""

  mkdir -p "${DATA_DIR}/nginx/html/.well-known/acme-challenge"
  chmod -R 777 "${DATA_DIR}/nginx/html" 2>/dev/null || true

  # Spin up a temporary nginx on port 80 just for ACME challenges
  # (the main stack isn't up yet)
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
  docker run -d --name matrix-acme-bootstrap \
    -v "/tmp/matrix-acme-nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "${DATA_DIR}/nginx/html:/var/www/certbot" \
    -p 80:80 \
    nginx:alpine >/dev/null 2>&1 || warn "Could not start bootstrap nginx — port 80 may be in use."

  # Small delay for nginx to be ready
  sleep 2

  LE_SUCCESS=false
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
      --force-renewal; then
    LE_SUCCESS=true
    ok "Let's Encrypt certificate obtained."
  else
    warn "Certbot failed — DNS not ready or port 80 not reachable."
    warn "Fix DNS/port-forwarding then run:  ./scripts/certbot-init.sh"
  fi

  docker rm -f matrix-acme-bootstrap >/dev/null 2>&1 || true
  rm -f /tmp/matrix-acme-nginx.conf

  # ── Self-signed fallback ──────────────────────────────────────────────────
  # nginx and coturn will FAIL TO START without cert files.
  # If LE failed, generate self-signed so the stack can start.
  if [[ "$LE_SUCCESS" != "true" ]] || [[ ! -f "$CERT_FULL" ]] || [[ ! -f "$CERT_KEY" ]]; then
    warn "Generating self-signed TLS certificate as fallback..."
    warn "(Browsers will show a security warning — replace with real cert later.)"

    if command -v openssl >/dev/null 2>&1; then
      openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "${CERT_KEY}" \
        -out "${CERT_FULL}" \
        -subj "/CN=${SERVER_NAME}/O=Matrix Self-Signed/C=US" \
        -extensions v3_req \
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
  ok "TLS skipped (--no-tls mode)."
fi

###############################################################################
# FINAL PERMISSIONS PASS
# After all files are written, lock down sensitive files
###############################################################################
msg "Finalizing permissions..."

# Synapse owns its appdata (UID 991)
chown -R 991:991 "${DATA_DIR}/synapse" 2>/dev/null || true
chmod 700 "${DATA_DIR}/synapse/appdata" 2>/dev/null || true
chmod 600 "${DATA_DIR}/synapse/appdata/homeserver.yaml" 2>/dev/null || true
[[ -f "${DATA_DIR}/synapse/appdata/${SERVER_NAME}.signing.key" ]] && \
  chmod 600 "${DATA_DIR}/synapse/appdata/${SERVER_NAME}.signing.key" 2>/dev/null || true

# Media store — Synapse writes here
chown -R 991:991 "${DATA_DIR}/synapse/media_store" 2>/dev/null || true
chmod 755 "${DATA_DIR}/synapse/media_store" 2>/dev/null || true

# Coturn config
chmod 600 "${DATA_DIR}/coturn/config/turnserver.conf" 2>/dev/null || true

# Nginx html + certs (world-readable OK for html, certs restricted)
chmod -R 755 "${DATA_DIR}/nginx/html" 2>/dev/null || true

# Postgres data dir should be owned by postgres user (999)
chown -R 999:999 "${DATA_DIR}/postgres" 2>/dev/null || true
chmod 700 "${DATA_DIR}/postgres" 2>/dev/null || true

# .env
chmod 600 "${ENV_FILE}" 2>/dev/null || true

ok "Permissions finalized."

###############################################################################
# MAKE REPO SCRIPTS EXECUTABLE
###############################################################################
if [[ -d "${PROJECT_DIR}/scripts" ]]; then
  chmod +x "${PROJECT_DIR}/scripts/"*.sh 2>/dev/null || true
  ok "scripts/*.sh marked executable."
fi

###############################################################################
# DONE
###############################################################################
echo ""
ok "${BOLD}Setup Complete.${NC}"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Next steps:"
echo ""
echo "  1. Start the stack:"
echo "     cd ${PROJECT_DIR}"
echo "     docker compose up -d"
echo ""
echo "  2. Wait ~30s for Synapse + Postgres to initialize, then:"
echo "     ./scripts/create-user.sh admin --admin"
echo ""
echo "  3. Open:"
echo "     ${PUBLIC_URL}"
echo ""
if [[ "${NO_TLS}" != "true" ]]; then
  echo "  TLS Status:"
  if [[ -f "${DATA_DIR}/nginx/certs/live/${SERVER_NAME}/fullchain.pem" ]]; then
    if openssl x509 -noout -issuer \
        -in "${DATA_DIR}/nginx/certs/live/${SERVER_NAME}/fullchain.pem" 2>/dev/null \
        | grep -qi "let.s encrypt"; then
      echo "  ✓ Real Let's Encrypt cert in place."
    else
      echo "  ⚠ Self-signed cert in place (browser will warn)."
      echo "     Once DNS is ready: ./scripts/certbot-init.sh"
    fi
  else
    echo "  ⚠ No cert found. Run: ./scripts/certbot-init.sh"
  fi
fi
echo "═══════════════════════════════════════════════════════════════"
echo ""
