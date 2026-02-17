#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# MATRIX-TEXTVOICEVIDEO — Setup Script (Turnkey)
#
# Purpose:
#   - Create/Update runtime configs under DATA_DIR (always)
#   - Generate .env ONLY if missing, or if --reset is used
#   - Preserve the .env commented template (no minimal env)
#   - Never generate/overwrite repo scripts in ./scripts
#
# Usage:
#   sudo bash setup.sh --domain chat.example.com
#   sudo bash setup.sh --domain chat.example.com --external-ip 1.2.3.4
#   sudo bash setup.sh --domain chat.example.com --no-tls
#   sudo bash setup.sh --domain chat.example.com --reset
#   sudo bash setup.sh --domain chat.example.com --enable-registration
###############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

msg() { echo -e "${CYAN}$*${NC}"; }
ok()  { echo -e "${GREEN}$*${NC}"; }
warn(){ echo -e "${YELLOW}$*${NC}"; }
die() { echo -e "${RED}ERROR: $*${NC}"; exit 1; }

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
  --no-tls                      HTTP only (LAN/testing)
  --reset                       DESTRUCTIVE: wipe DATA_DIR and .env and regenerate
  --enable-registration         Enable Synapse registration (default: false)
  -h, --help                    Show help
EOF
  exit 1
}

###############################################################################
# ARGS
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
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --external-ip) EXTERNAL_IP="${2:-}"; shift 2 ;;
    --data-dir) DATA_DIR="${2:-}"; shift 2 ;;
    --admin-email) ADMIN_EMAIL="${2:-}"; shift 2 ;;
    --tz) TIMEZONE="${2:-}"; shift 2 ;;
    --no-tls) NO_TLS=true; shift ;;
    --reset) RESET=true; shift ;;
    --enable-registration) ENABLE_REG=true; shift ;;
    -h|--help) usage ;;
    *) die "Unknown option: $1" ;;
  esac
done

[[ -z "$DOMAIN" ]] && usage

# Simple domain validation (hostname/FQDN)
if ! echo "$DOMAIN" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'; then
  die "'$DOMAIN' does not look like a valid domain/hostname"
fi

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
[[ -z "$DATA_DIR" ]] && DATA_DIR="/mnt/user/appdata/matrix-textvoicevideo/data"
MEET_DOMAIN="meet.${DOMAIN}"
[[ -z "$ADMIN_EMAIL" ]] && ADMIN_EMAIL="admin@${DOMAIN}"

msg "Project:  ${PROJECT_DIR}"
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
  warn "  - ${PROJECT_DIR}/.env"
  echo ""
  read -r -p "Type YES to confirm wipe: " confirm
  if [[ "${confirm}" != "YES" ]]; then
    die "Aborted."
  fi

  (cd "$PROJECT_DIR" && docker compose down -v 2>/dev/null) || true
  (cd "$PROJECT_DIR" && docker-compose down -v 2>/dev/null) || true
  rm -rf "$DATA_DIR"
  rm -f "$PROJECT_DIR/.env"
  ok "Reset complete."
  echo ""
fi

###############################################################################
# IP DETECTION
###############################################################################
detect_external_ip() {
  # fast + reliable
  curl -4 -sf --connect-timeout 5 --max-time 10 https://api.ipify.org 2>/dev/null || true
}

detect_internal_ip() {
  # prefer ip route
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
# DIRS (always)
###############################################################################
msg "Creating runtime directories..."

mkdir -p \
  "$DATA_DIR/postgres" \
  "$DATA_DIR/valkey" \
  "$DATA_DIR/synapse/appdata" \
  "$DATA_DIR/synapse/media_store" \
  "$DATA_DIR/coturn/config" \
  "$DATA_DIR/element-web/config" \
  "$DATA_DIR/nginx/html/.well-known/matrix" \
  "$DATA_DIR/nginx/certs" \
  "$DATA_DIR/jitsi/prosody" \
  "$DATA_DIR/jitsi/jicofo" \
  "$DATA_DIR/jitsi/jvb" \
  "$DATA_DIR/jitsi/web"

# Unraid-friendly perms
chmod -R 777 "$DATA_DIR" 2>/dev/null || true

ok "Directories ready."
echo ""

###############################################################################
# .env (generate if missing)
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

if [[ ! -f "$PROJECT_DIR/.env" ]]; then
  msg "Generating .env (full commented template)..."

  POSTGRES_PASSWORD="$(gen_pass)"
  SYNAPSE_REGISTRATION_SECRET="$(gen_secret)"
  SYNAPSE_MACAROON_KEY="$(gen_secret)"
  SYNAPSE_FORM_SECRET="$(gen_secret)"
  TURN_SECRET="$(gen_secret)"
  JICOFO_AUTH_PASSWORD="$(gen_pass)"
  JVB_AUTH_PASSWORD="$(gen_pass)"

  cat > "$PROJECT_DIR/.env" <<EOF
###############################################################################
# matrix-textvoicevideo · Auto-generated $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Domain: ${DOMAIN}
#
# NOTE:
# - This file contains secrets. Keep it private (chmod 600).
# - Re-run setup.sh --reset to regenerate secrets + wipe runtime data.
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
# JITSI — Self-Hosted Video (meet.\${SERVER_NAME})
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

  chmod 600 "$PROJECT_DIR/.env"
  ok ".env created."
else
  warn ".env exists — preserving secrets."
fi

###############################################################################
# LOAD .env
###############################################################################
set -a
# shellcheck disable=SC1090
source "$PROJECT_DIR/.env"
set +a

###############################################################################
# WRITE/UPDATE RUNTIME CONFIGS (always)
###############################################################################

# 1) Element Web config.json (always)
msg "Writing Element Web config.json..."
cat > "$DATA_DIR/element-web/config/config.json" <<EOF
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
ok "✓ Element config written"

# 2) Synapse homeserver.yaml (always)
msg "Writing Synapse homeserver.yaml..."
cat > "$DATA_DIR/synapse/appdata/homeserver.yaml" <<EOF
server_name: "${SERVER_NAME}"
public_baseurl: "${PUBLIC_URL}/"
pid_file: /data/homeserver.pid
web_client_location: "${PUBLIC_URL}/"
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

registration_shared_secret: "${SYNAPSE_REGISTRATION_SECRET}"
macaroon_secret_key: "${SYNAPSE_MACAROON_KEY}"
form_secret: "${SYNAPSE_FORM_SECRET}"
signing_key_path: "/data/${SERVER_NAME}.signing.key"

trusted_key_servers: []
report_stats: false

enable_registration: $( [[ "$ENABLE_REG" == true ]] && echo "true" || echo "false" )
enable_registration_without_verification: false

turn_uris:
  - "turn:${SERVER_NAME}:3478?transport=udp"
  - "turn:${SERVER_NAME}:3478?transport=tcp"
  - "turns:${SERVER_NAME}:5349?transport=tcp"
turn_shared_secret: "${TURN_SECRET}"
turn_user_lifetime: 1h
turn_allow_guests: false
EOF
chmod 600 "$DATA_DIR/synapse/appdata/homeserver.yaml"
ok "✓ Synapse config written"

# 3) Coturn turnserver.conf (always)
msg "Writing Coturn turnserver.conf..."
cat > "$DATA_DIR/coturn/config/turnserver.conf" <<EOF
realm=${SERVER_NAME}

use-auth-secret
static-auth-secret=${TURN_SECRET}

listening-ip=${INTERNAL_IP}
relay-ip=${INTERNAL_IP}
external-ip=${EXTERNAL_IP}/${INTERNAL_IP}

listening-port=3478
tls-listening-port=5349

min-port=49160
max-port=49250

cert=/certs/fullchain.pem
pkey=/certs/privkey.pem

fingerprint
no-cli
no-tlsv1
no-tlsv1_1

log-file=stdout
verbose
EOF
chmod 600 "$DATA_DIR/coturn/config/turnserver.conf"
ok "✓ Coturn config written"

# 4) Well-known files (always)
msg "Writing .well-known Matrix discovery files..."
cat > "$DATA_DIR/nginx/html/.well-known/matrix/server" <<EOF
{ "m.server": "${SERVER_NAME}:443" }
EOF

cat > "$DATA_DIR/nginx/html/.well-known/matrix/client" <<EOF
{ "m.homeserver": { "base_url": "${PUBLIC_URL}" } }
EOF
ok "✓ well-known written"

# 5) Nginx config (always) — matches your static compose IPs
msg "Writing nginx.conf..."
if [[ "${NO_TLS}" == "true" ]]; then
  cat > "$DATA_DIR/nginx/nginx.conf" <<EOF
worker_processes auto;
events { worker_connections 2048; }
http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  sendfile on;

  client_max_body_size 100M;
  proxy_read_timeout 600s;

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

    location /_matrix { proxy_pass http://synapse; }
    location /_synapse { proxy_pass http://synapse; }

    location / { proxy_pass http://elementweb; }
  }

  server {
    listen 80;
    server_name ${JITSI_DOMAIN};
    location / { proxy_pass http://jitsiweb; }
  }
}
EOF
else
  cat > "$DATA_DIR/nginx/nginx.conf" <<EOF
worker_processes auto;
events { worker_connections 2048; }
http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  sendfile on;

  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

  client_max_body_size 100M;
  proxy_read_timeout 600s;

  upstream synapse    { server 172.42.0.3:8008; }
  upstream elementweb { server 172.42.0.4:80; }
  upstream jitsiweb   { server 172.42.0.22:80; }

  server {
    listen 80;
    server_name ${SERVER_NAME} ${JITSI_DOMAIN};
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://\$host\$request_uri; }
  }

  server {
    listen 443 ssl;
    server_name ${SERVER_NAME};

    ssl_certificate     /etc/nginx/certs/live/${SERVER_NAME}/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/live/${SERVER_NAME}/privkey.pem;

    location /.well-known/matrix/ {
      root /var/www/html;
      default_type application/json;
      add_header Access-Control-Allow-Origin "*" always;
    }

    location /_matrix { proxy_pass http://synapse; }
    location /_synapse { proxy_pass http://synapse; }
    location / { proxy_pass http://elementweb; }
  }

  server {
    listen 443 ssl;
    server_name ${JITSI_DOMAIN};

    ssl_certificate     /etc/nginx/certs/live/${SERVER_NAME}/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/live/${SERVER_NAME}/privkey.pem;

    location / { proxy_pass http://jitsiweb; }
  }
}
EOF
fi
ok "✓ nginx.conf written"

###############################################################################
# TLS BOOTSTRAP (optional) — still in setup per your preference
###############################################################################
if [[ "${NO_TLS}" != "true" ]]; then
  echo ""
  msg "Attempting Let's Encrypt certificate (best-effort)..."
  warn "Requirements:"
  warn "  - DNS A record for ${SERVER_NAME} -> ${EXTERNAL_IP}"
  warn "  - DNS A record for ${JITSI_DOMAIN} -> ${EXTERNAL_IP}"
  warn "  - Port 80 reachable from the internet to this host"
  echo ""

  mkdir -p "$DATA_DIR/nginx/html/.well-known/acme-challenge"
  chmod -R 777 "$DATA_DIR/nginx/html" 2>/dev/null || true

  # temporary nginx only for ACME
  cat > /tmp/nginx-bootstrap.conf <<EOF
events {}
http {
  server {
    listen 80;
    server_name ${SERVER_NAME} ${JITSI_DOMAIN};
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 200 'ACME bootstrap'; add_header Content-Type text/plain; }
  }
}
EOF

  docker rm -f matrix-certbot-bootstrap >/dev/null 2>&1 || true
  docker run -d --name matrix-certbot-bootstrap \
    -v "/tmp/nginx-bootstrap.conf:/etc/nginx/nginx.conf:ro" \
    -v "${DATA_DIR}/nginx/html:/var/www/certbot" \
    -p 80:80 nginx:alpine >/dev/null 2>&1 || true

  # certbot
  if docker run --rm \
    -v "${DATA_DIR}/nginx/certs:/etc/letsencrypt" \
    -v "${DATA_DIR}/nginx/html:/var/www/certbot" \
    certbot/certbot certonly \
      --webroot -w /var/www/certbot \
      -d "${SERVER_NAME}" \
      -d "${JITSI_DOMAIN}" \
      --email "${ADMIN_EMAIL}" \
      --agree-tos --non-interactive --force-renewal; then
    ok "✓ TLS certificate obtained."
  else
    warn "⚠ Certbot failed (DNS/port 80). You can re-run later after fixing DNS/port-forwarding."
  fi

  docker rm -f matrix-certbot-bootstrap >/dev/null 2>&1 || true
  rm -f /tmp/nginx-bootstrap.conf
  rm -f /tmp/nginx-bootstrap.conf 2>/dev/null || true
fi

###############################################################################
# MAKE REPO SCRIPTS EXECUTABLE
###############################################################################
if [[ -d "$PROJECT_DIR/scripts" ]]; then
  chmod +x "$PROJECT_DIR/scripts/"*.sh 2>/dev/null || true
fi

echo ""
ok "${BOLD}Setup Complete.${NC}"
echo ""
echo "Next:"
echo "  cd ${PROJECT_DIR}"
echo "  docker compose up -d"
echo ""
echo "Then create admin:"
echo "  ./scripts/create-user.sh admin --admin"
echo ""
echo "Open:"
echo "  ${PUBLIC_URL}"
echo ""
if [[ "${NO_TLS}" != "true" ]]; then
  warn "If TLS failed: fix DNS + port 80, then re-run setup.sh (no --reset) or run certbot script later."
fi
