#!/usr/bin/env bash
set -euo pipefail

###############################################################################
#  MATRIX-TEXTVOICEVIDEO — Setup Script
#
#  Purpose:
#    - Generate .env (if missing)
#    - Generate runtime configs in DATA_DIR
#    - Create required directories
#    - Bootstrap TLS (optional)
#    - NEVER generate repo scripts
#    - NEVER overwrite secrets unless --reset
#
#  Usage:
#    sudo bash setup.sh --domain chat.example.com
#    sudo bash setup.sh --domain chat.example.com --external-ip 1.2.3.4
#    sudo bash setup.sh --domain chat.example.com --no-tls
#    sudo bash setup.sh --domain chat.example.com --reset
###############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

usage() {
  echo "Usage: $0 --domain <FQDN> [--external-ip IP] [--no-tls] [--reset]"
  exit 1
}

###############################################################################
# ARG PARSE
###############################################################################

DOMAIN=""
EXTERNAL_IP=""
NO_TLS=false
RESET=false
ADMIN_EMAIL=""
DATA_DIR=""
TIMEZONE="America/Chicago"

while [[ $# -gt 0 ]]; do
  case $1 in
    --domain) DOMAIN="$2"; shift 2 ;;
    --external-ip) EXTERNAL_IP="$2"; shift 2 ;;
    --no-tls) NO_TLS=true; shift ;;
    --admin-email) ADMIN_EMAIL="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    --tz) TIMEZONE="$2"; shift 2 ;;
    --reset) RESET=true; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

[ -z "$DOMAIN" ] && usage

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
[ -z "$DATA_DIR" ] && DATA_DIR="/mnt/user/appdata/matrix-textvoicevideo/data"
[ -z "$ADMIN_EMAIL" ] && ADMIN_EMAIL="admin@${DOMAIN}"
MEET_DOMAIN="meet.${DOMAIN}"

echo -e "${CYAN}Project: ${PROJECT_DIR}${NC}"
echo -e "${CYAN}Data Dir: ${DATA_DIR}${NC}"

###############################################################################
# RESET (DESTRUCTIVE)
###############################################################################

if [ "$RESET" = true ]; then
  echo -e "${RED}DESTRUCTIVE RESET ENABLED${NC}"
  read -p "Type YES to confirm wipe: " confirm
  [ "$confirm" != "YES" ] && exit 1
  docker compose down -v 2>/dev/null || true
  docker-compose down -v 2>/dev/null || true
  rm -rf "$DATA_DIR"
  rm -f "$PROJECT_DIR/.env"
fi

###############################################################################
# DETECT EXTERNAL IP (if not provided)
###############################################################################

detect_external_ip() {
  curl -4 -sf https://api.ipify.org 2>/dev/null || true
}

if [ -z "$EXTERNAL_IP" ]; then
  EXTERNAL_IP="$(detect_external_ip)"
  [ -z "$EXTERNAL_IP" ] && {
    echo -e "${RED}Could not detect public IP. Use --external-ip${NC}"
    exit 1
  }
fi

INTERNAL_IP="$(hostname -I | awk '{print $1}')"
[ -z "$INTERNAL_IP" ] && INTERNAL_IP="127.0.0.1"

echo -e "${GREEN}External IP: ${EXTERNAL_IP}${NC}"
echo -e "${GREEN}Internal IP: ${INTERNAL_IP}${NC}"

###############################################################################
# CREATE DIRECTORIES
###############################################################################

mkdir -p "$DATA_DIR"/{postgres,synapse/appdata,synapse/media_store,coturn/config,nginx/html/.well-known/matrix,nginx/certs,element-web/config,valkey,jitsi}
chmod -R 777 "$DATA_DIR"

###############################################################################
# GENERATE .env (ONLY IF MISSING)
###############################################################################

if [ ! -f "$PROJECT_DIR/.env" ]; then
  echo -e "${CYAN}Generating new .env...${NC}"

  gen_secret() { openssl rand -base64 48 | tr -d '/+=\n' | head -c 48; }
  gen_pass() { openssl rand -base64 32 | tr -d '/+=\n' | head -c 32; }

  cat > "$PROJECT_DIR/.env" <<EOF
SERVER_NAME="${DOMAIN}"
PUBLIC_URL="https://${DOMAIN}"
SCHEME="$( [ "$NO_TLS" = true ] && echo http || echo https )"
EXTERNAL_IP="${EXTERNAL_IP}"
INTERNAL_IP="${INTERNAL_IP}"
POSTGRES_PASSWORD="$(gen_pass)"
SYNAPSE_REGISTRATION_SECRET="$(gen_secret)"
SYNAPSE_MACAROON_KEY="$(gen_secret)"
SYNAPSE_FORM_SECRET="$(gen_secret)"
TURN_SECRET="$(gen_secret)"
JICOFO_AUTH_PASSWORD="$(gen_pass)"
JVB_AUTH_PASSWORD="$(gen_pass)"
DATA_DIR="${DATA_DIR}"
TZ="${TIMEZONE}"
NO_TLS="${NO_TLS}"
ADMIN_EMAIL="${ADMIN_EMAIL}"
EOF

  chmod 600 "$PROJECT_DIR/.env"
else
  echo -e "${YELLOW}.env exists — preserving secrets.${NC}"
fi

###############################################################################
# LOAD .env
###############################################################################
set -a
source "$PROJECT_DIR/.env"
set +a

###############################################################################
# SYNAPSE homeserver.yaml (overwrite safe)
###############################################################################

cat > "$DATA_DIR/synapse/appdata/homeserver.yaml" <<EOF
server_name: "${SERVER_NAME}"
public_baseurl: "${PUBLIC_URL}/"

listeners:
  - port: 8008
    tls: false
    type: http
    x_forwarded: true
    bind_addresses: ['0.0.0.0']
    resources:
      - names: [client, federation]

database:
  name: psycopg2
  args:
    user: synapse
    password: "${POSTGRES_PASSWORD}"
    database: synapse
    host: matrix-postgres
    port: 5432

registration_shared_secret: "${SYNAPSE_REGISTRATION_SECRET}"
macaroon_secret_key: "${SYNAPSE_MACAROON_KEY}"
form_secret: "${SYNAPSE_FORM_SECRET}"

enable_registration: false
trusted_key_servers: []

turn_uris:
  - "turn:${SERVER_NAME}:3478?transport=udp"
  - "turn:${SERVER_NAME}:3478?transport=tcp"

turn_shared_secret: "${TURN_SECRET}"
EOF

chmod 600 "$DATA_DIR/synapse/appdata/homeserver.yaml"

###############################################################################
# COTURN CONFIG
###############################################################################

cat > "$DATA_DIR/coturn/config/turnserver.conf" <<EOF
realm=${SERVER_NAME}
use-auth-secret
static-auth-secret=${TURN_SECRET}
external-ip=${EXTERNAL_IP}/${INTERNAL_IP}
listening-port=3478
tls-listening-port=5349
EOF

chmod 600 "$DATA_DIR/coturn/config/turnserver.conf"

###############################################################################
# TLS BOOTSTRAP (OPTIONAL)
###############################################################################

if [ "$NO_TLS" = false ]; then
  echo -e "${CYAN}Attempting Let's Encrypt certificate...${NC}"

  docker run --rm \
    -v "${DATA_DIR}/nginx/certs:/etc/letsencrypt" \
    -v "${DATA_DIR}/nginx/html:/var/www/certbot" \
    certbot/certbot certonly \
      --webroot -w /var/www/certbot \
      -d "${DOMAIN}" \
      -d "${MEET_DOMAIN}" \
      --email "${ADMIN_EMAIL}" \
      --agree-tos \
      --non-interactive || true
fi

###############################################################################
# ENSURE REPO SCRIPTS ARE EXECUTABLE
###############################################################################

if [ -d "$PROJECT_DIR/scripts" ]; then
  chmod +x "$PROJECT_DIR/scripts/"*.sh 2>/dev/null || true
fi

###############################################################################
# DONE
###############################################################################

echo ""
echo -e "${GREEN}${BOLD}Setup Complete.${NC}"
echo ""
echo "Next:"
echo "  cd ${PROJECT_DIR}"
echo "  docker compose up -d"
echo ""
echo "Then create admin:"
echo "  ./scripts/create-user.sh admin --admin"
echo ""
echo "Open:"
echo "  https://${DOMAIN}"
echo ""
