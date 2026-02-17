#!/usr/bin/env bash
set -euo pipefail

###############################################################################
#  MATRIX-TEXTVOICEVIDEO — Turnkey Self-Hosted Discord Alternative
#  Text · Voice (Coturn) · Video (Jitsi) · Matrix Synapse · Element Web
#
#  Optimised for Unraid (runs as root, composeman, /mnt/user/appdata)
#  Also works on any Debian/Ubuntu/RHEL Docker host.
#
#  Usage:
#    sudo bash setup.sh --domain chat.example.com
#    sudo bash setup.sh --domain chat.example.com --external-ip 1.2.3.4
#    sudo bash setup.sh --domain chat.example.com --no-tls       # LAN only
#    sudo bash setup.sh --domain chat.example.com --reset        # wipe + rebuild
###############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
  echo -e "${CYAN}"
  echo "╔═══════════════════════════════════════════════════════════════════╗"
  echo "║   MATRIX-TEXTVOICEVIDEO  ·  Self-Hosted Discord Alternative      ║"
  echo "║   Text · Voice (Coturn) · Video (Jitsi) · Secure by Default     ║"
  echo "╚═══════════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

usage() {
  echo -e "${BOLD}Usage:${NC} $0 --domain <FQDN> [OPTIONS]"
  echo ""
  echo -e "${BOLD}Required:${NC}"
  echo "  --domain <FQDN>        Your server's fully qualified domain name"
  echo "                         (e.g. chat.example.com)"
  echo ""
  echo -e "${BOLD}Optional:${NC}"
  echo "  --external-ip <IP>     Public WAN IP (auto-detected if omitted)"
  echo "  --no-tls               Skip TLS / Let's Encrypt (LAN-only mode)"
  echo "  --admin-email <email>  Email for Let's Encrypt (default: admin@DOMAIN)"
  echo "  --data-dir <path>      Data directory (default: /mnt/user/appdata/matrix-textvoicevideo/data)"
  echo "  --tz <timezone>        Timezone (default: America/Chicago)"
  echo "  --reset                Wipe ALL data and start fresh (DESTRUCTIVE)"
  echo "  -h, --help             Show this help"
  echo ""
  echo -e "${BOLD}Examples:${NC}"
  echo "  sudo bash setup.sh --domain chat.example.com"
  echo "  sudo bash setup.sh --domain chat.example.com --external-ip 203.0.113.1"
  echo "  sudo bash setup.sh --domain myserver.local --no-tls"
  exit 1
}

###############################################################################
# PARSE ARGUMENTS
###############################################################################
DOMAIN=""
EXTERNAL_IP=""
NO_TLS=false
ADMIN_EMAIL=""
DATA_DIR=""
TIMEZONE="America/Chicago"
RESET=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --domain)       DOMAIN="$2";       shift 2 ;;
    --external-ip)  EXTERNAL_IP="$2";  shift 2 ;;
    --no-tls)       NO_TLS=true;       shift   ;;
    --admin-email)  ADMIN_EMAIL="$2";  shift 2 ;;
    --data-dir)     DATA_DIR="$2";     shift 2 ;;
    --tz)           TIMEZONE="$2";     shift 2 ;;
    --reset)        RESET=true;        shift   ;;
    -h|--help)      usage ;;
    *) echo -e "${RED}Unknown option: $1${NC}"; usage ;;
  esac
done

banner

###############################################################################
# VALIDATE
###############################################################################
if [ -z "$DOMAIN" ]; then
  echo -e "${RED}ERROR: --domain is required${NC}"
  usage
fi

# Domain must look like a valid FQDN or hostname
if ! echo "$DOMAIN" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'; then
  echo -e "${RED}ERROR: '$DOMAIN' does not look like a valid domain name${NC}"
  exit 1
fi

MEET_DOMAIN="meet.${DOMAIN}"
[ -z "$ADMIN_EMAIL" ] && ADMIN_EMAIL="admin@${DOMAIN}"

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Default data dir to Unraid appdata path
if [ -z "$DATA_DIR" ]; then
  DATA_DIR="/mnt/user/appdata/matrix-textvoicevideo/data"
fi

echo -e "${CYAN}Project directory: ${PROJECT_DIR}${NC}"
echo -e "${CYAN}Data directory:    ${DATA_DIR}${NC}"

###############################################################################
# DETECT EXTERNAL (WAN) IP
###############################################################################
detect_external_ip() {
  local ip=""
  # Try multiple services in order
  ip=$(curl -4 -sf --connect-timeout 5 --max-time 10 'https://api.ipify.org?format=json' 2>/dev/null \
       | grep -oP '"ip"\s*:\s*"\K[0-9.]+' || true)
  [ -z "$ip" ] && ip=$(curl -4 -sf --connect-timeout 5 --max-time 10 https://ifconfig.me 2>/dev/null | tr -d '[:space:]' || true)
  [ -z "$ip" ] && ip=$(curl -4 -sf --connect-timeout 5 --max-time 10 https://icanhazip.com 2>/dev/null | tr -d '[:space:]' || true)
  [ -z "$ip" ] && ip=$(curl -4 -sf --connect-timeout 5 --max-time 10 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]' || true)
  [ -z "$ip" ] && ip=$(curl -4 -sf --connect-timeout 5 --max-time 10 https://ipecho.net/plain 2>/dev/null | tr -d '[:space:]' || true)
  # Validate IPv4
  if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "$ip"
  else
    echo ""
  fi
}

###############################################################################
# DETECT INTERNAL (LAN/UNRAID) IP
# Uses `ip a` to find the primary non-loopback interface IP
###############################################################################
detect_internal_ip() {
  local ip=""
  # Try ip command first (most reliable on Unraid/Linux)
  ip=$(ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1 || true)
  # Fallback: hostname -I
  [ -z "$ip" ] && ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
  echo "$ip"
}

if [ -z "$EXTERNAL_IP" ]; then
  echo -e "${YELLOW}Detecting public IP...${NC}"
  EXTERNAL_IP=$(detect_external_ip)
  if [ -z "$EXTERNAL_IP" ]; then
    echo -e "${RED}ERROR: Could not auto-detect public IP.${NC}"
    echo -e "${YELLOW}Re-run with:  --external-ip YOUR.PUBLIC.IP${NC}"
    exit 1
  fi
  echo -e "${GREEN}Public IP detected: ${EXTERNAL_IP}${NC}"
fi

INTERNAL_IP=$(detect_internal_ip)
if [ -z "$INTERNAL_IP" ]; then
  echo -e "${YELLOW}WARNING: Could not detect internal IP. Defaulting to 127.0.0.1${NC}"
  INTERNAL_IP="127.0.0.1"
fi
echo -e "${GREEN}Internal IP:   ${INTERNAL_IP}${NC}"
echo -e "${GREEN}Domain:        ${DOMAIN}${NC}"
echo -e "${GREEN}Jitsi Domain:  ${MEET_DOMAIN}${NC}"
echo ""

###############################################################################
# RESET CHECK
###############################################################################
if [ "$RESET" = true ]; then
  echo -e "${RED}${BOLD}WARNING: This will DESTROY ALL DATA (database, media, secrets, certs).${NC}"
  echo -e "${RED}This cannot be undone.${NC}"
  read -p "Type 'YES I AM SURE' to confirm: " confirm
  if [ "$confirm" = "YES I AM SURE" ]; then
    echo -e "${YELLOW}Stopping containers...${NC}"
    docker compose -f "$PROJECT_DIR/docker-compose.yml" down -v 2>/dev/null || true
    docker-compose -f "$PROJECT_DIR/docker-compose.yml" down -v 2>/dev/null || true
    rm -rf "$DATA_DIR"
    echo -e "${GREEN}Reset complete. Rebuilding from scratch...${NC}"
  else
    echo "Aborted."; exit 1
  fi
fi

###############################################################################
# PERMISSIONS — Unraid runs everything as root; chmod 777 allows containers
# to write to mounted volumes regardless of their internal UID/GID.
###############################################################################
echo -e "${CYAN}Setting base permissions for Unraid compatibility...${NC}"
mkdir -p "$DATA_DIR"
chmod 777 "$DATA_DIR"

###############################################################################
# GENERATE SECRETS  (openssl for all sensitive values)
###############################################################################
echo -e "${CYAN}Generating cryptographic secrets...${NC}"

gen_secret()   { openssl rand -base64 48 | tr -d '/+=\n' | head -c 48; }
gen_password() { openssl rand -base64 32 | tr -d '/+=\n' | head -c 32; }
gen_hex()      { openssl rand -hex 24; }

POSTGRES_PASSWORD="$(gen_password)"
SYNAPSE_REGISTRATION_SECRET="$(gen_secret)"
SYNAPSE_MACAROON_KEY="$(gen_secret)"
SYNAPSE_FORM_SECRET="$(gen_secret)"
TURN_SECRET="$(gen_secret)"
JICOFO_AUTH_PASSWORD="$(gen_password)"
JVB_AUTH_PASSWORD="$(gen_password)"

echo -e "${GREEN}All secrets generated.${NC}"

###############################################################################
# SCHEME
###############################################################################
if [ "$NO_TLS" = true ]; then
  SCHEME="http"
else
  SCHEME="https"
fi
PUBLIC_URL="${SCHEME}://${DOMAIN}"
JITSI_PUBLIC_URL="${SCHEME}://${MEET_DOMAIN}"

###############################################################################
# CREATE DIRECTORY STRUCTURE
###############################################################################
echo -e "${CYAN}Creating directory structure...${NC}"

dirs=(
  "$DATA_DIR/postgres"
  "$DATA_DIR/synapse/appdata"
  "$DATA_DIR/synapse/media_store"
  "$DATA_DIR/coturn/config"
  "$DATA_DIR/nginx/html/.well-known/matrix"
  "$DATA_DIR/nginx/certs"
  "$DATA_DIR/element-web/config"
  "$DATA_DIR/valkey"
  "$DATA_DIR/jitsi/prosody"
  "$DATA_DIR/jitsi/jicofo"
  "$DATA_DIR/jitsi/jvb"
  "$DATA_DIR/jitsi/web"
  "$PROJECT_DIR/scripts"
  "$PROJECT_DIR/backups"
)

for d in "${dirs[@]}"; do
  mkdir -p "$d"
  chmod 777 "$d"
done

echo -e "${GREEN}Directories created.${NC}"

###############################################################################
# WRITE .env  (the single source of truth — all scripts + compose read from here)
###############################################################################
echo -e "${CYAN}Writing .env...${NC}"

cat > "$PROJECT_DIR/.env" <<ENVEOF
###############################################################################
# matrix-textvoicevideo · Auto-generated $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Domain: ${DOMAIN}
# Re-run setup.sh to regenerate — do NOT edit secrets by hand after first run
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
NO_TLS="${NO_TLS}"
ADMIN_EMAIL="${ADMIN_EMAIL}"

############################
# PATHS
############################
DATA_DIR="${DATA_DIR}"

############################
# TIMEZONE
############################
TZ="${TIMEZONE}"

############################
# JITSI — Self-Hosted Video
############################
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
ENVEOF

chmod 600 "$PROJECT_DIR/.env"
echo -e "${GREEN}.env written and locked (chmod 600).${NC}"

###############################################################################
# SYNAPSE homeserver.yaml
###############################################################################
echo -e "${CYAN}Generating Synapse homeserver.yaml...${NC}"

cat > "$DATA_DIR/synapse/appdata/homeserver.yaml" <<SYEOF
##################################################################
# Synapse Homeserver — Auto-generated by matrix-textvoicevideo
# Domain: ${DOMAIN}
##################################################################

server_name: "${DOMAIN}"
public_baseurl: "${PUBLIC_URL}/"
pid_file: /data/homeserver.pid
web_client_location: "${PUBLIC_URL}/"
serve_server_wellknown: true

##################################################################
# LISTENERS
##################################################################
listeners:
  - port: 8008
    tls: false
    type: http
    x_forwarded: true
    bind_addresses: ['0.0.0.0']
    resources:
      - names: [client, federation]
        compress: false

##################################################################
# DATABASE — PostgreSQL with C locale (required by Synapse)
##################################################################
database:
  name: psycopg2
  args:
    user: synapse
    password: "${POSTGRES_PASSWORD}"
    database: synapse
    host: matrix-postgres
    port: 5432
    cp_min: 5
    cp_max: 10

##################################################################
# REDIS / VALKEY — Required for coordination
##################################################################
redis:
  enabled: true
  host: matrix-valkey
  port: 6379

##################################################################
# LOGGING
##################################################################
log_config: "/data/${DOMAIN}.log.config"

##################################################################
# MEDIA
##################################################################
media_store_path: /data/media_store
max_upload_size: 100M
url_preview_enabled: true
url_preview_ip_range_blacklist:
  - '127.0.0.0/8'
  - '10.0.0.0/8'
  - '172.16.0.0/12'
  - '192.168.0.0/16'
  - '100.64.0.0/10'
  - '192.0.0.0/24'
  - '169.254.0.0/16'
  - '198.18.0.0/15'
  - 'fe80::/10'
  - 'fc00::/7'
  - '::1/128'

##################################################################
# SECRETS
##################################################################
registration_shared_secret: "${SYNAPSE_REGISTRATION_SECRET}"
macaroon_secret_key: "${SYNAPSE_MACAROON_KEY}"
form_secret: "${SYNAPSE_FORM_SECRET}"
signing_key_path: "/data/${DOMAIN}.signing.key"

##################################################################
# SECURITY
##################################################################
report_stats: false

# No external key servers — fully self-hosted
trusted_key_servers: []

# Registration is CLOSED — use scripts/create-user.sh to add users
enable_registration: false
enable_registration_without_verification: false

# Rate limiting
rc_message:
  per_second: 5
  burst_count: 20
rc_registration:
  per_second: 0.1
  burst_count: 3
rc_login:
  address:
    per_second: 0.5
    burst_count: 5
  account:
    per_second: 0.5
    burst_count: 5

# Session lifetime
session_lifetime: 24h
refresh_access_token_lifetime: 24h

# Password policy
password_config:
  enabled: true
  minimum_length: 10
  require_digit: true
  require_symbol: false
  require_lowercase: true
  require_uppercase: true

##################################################################
# TURN (Coturn) — Voice relay for NAT traversal
##################################################################
turn_uris:
  - "turn:${DOMAIN}:3478?transport=udp"
  - "turn:${DOMAIN}:3478?transport=tcp"
  - "turns:${DOMAIN}:5349?transport=tcp"
turn_shared_secret: "${TURN_SECRET}"
turn_user_lifetime: 1h
turn_allow_guests: false

##################################################################
# JITSI WIDGET — Video calling
##################################################################
# Element Web will use the Jitsi integration widget at meet.${DOMAIN}

##################################################################
# FEDERATION — disabled for private servers
##################################################################
allow_public_rooms_over_federation: false

##################################################################
# CACHING — tuned for 10-50 concurrent users
##################################################################
caches:
  global_factor: 1.0
  per_cache_factors:
    get_users_in_room: 2.0
SYEOF

chmod 600 "$DATA_DIR/synapse/appdata/homeserver.yaml"

###############################################################################
# SYNAPSE LOG CONFIG
###############################################################################
cat > "$DATA_DIR/synapse/appdata/${DOMAIN}.log.config" <<LOGEOF
version: 1
formatters:
  precise:
    format: '%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(request)s - %(message)s'
handlers:
  console:
    class: logging.StreamHandler
    formatter: precise
loggers:
  synapse.storage.SQL:
    level: WARNING
root:
  level: INFO
  handlers: [console]
disable_existing_loggers: false
LOGEOF

###############################################################################
# COTURN CONFIG
# Note: use-auth-secret + static-auth-secret for Matrix HMAC auth
# Do NOT use lt-cred-mech alongside use-auth-secret
###############################################################################
echo -e "${CYAN}Generating Coturn config...${NC}"

cat > "$DATA_DIR/coturn/config/turnserver.conf" <<TURNEOF
# Coturn TURN/STUN Server — Auto-generated by matrix-textvoicevideo
# Domain: ${DOMAIN}

realm=${DOMAIN}

# Matrix HMAC shared-secret auth (do NOT add lt-cred-mech)
use-auth-secret
static-auth-secret=${TURN_SECRET}

# Network
listening-ip=${INTERNAL_IP}
relay-ip=${INTERNAL_IP}
external-ip=${EXTERNAL_IP}/${INTERNAL_IP}

listening-port=3478
tls-listening-port=5349

min-port=49160
max-port=49250

# TLS certificates (shared with nginx via volume mount)
cert=/certs/fullchain.pem
pkey=/certs/privkey.pem

# Security
fingerprint
no-cli
no-tlsv1
no-tlsv1_1

# Block relay to private/loopback IPs (security critical)
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.0.0.0-192.0.0.255
denied-peer-ip=192.88.99.0-192.88.99.255
denied-peer-ip=198.18.0.0-198.19.255.255
denied-peer-ip=198.51.100.0-198.51.100.255
denied-peer-ip=203.0.113.0-203.0.113.255
denied-peer-ip=240.0.0.0-255.255.255.255
allowed-peer-ip=${INTERNAL_IP}

# Performance (supports ~50 concurrent TURN sessions)
total-quota=300
stale-nonce=600
max-bps=3000000

# Logging
log-file=stdout
verbose
TURNEOF

chmod 600 "$DATA_DIR/coturn/config/turnserver.conf"

###############################################################################
# ELEMENT WEB CONFIG
# Points to Jitsi for video calls via the jitsi widget integration
###############################################################################
echo -e "${CYAN}Generating Element Web config...${NC}"

cat > "$DATA_DIR/element-web/config/config.json" <<EWEOF
{
  "default_server_config": {
    "m.homeserver": {
      "base_url": "${PUBLIC_URL}",
      "server_name": "${DOMAIN}"
    }
  },

  "disable_custom_urls": true,
  "disable_guests": true,

  "brand": "Matrix Chat",
  "default_theme": "dark",

  "room_directory": {
    "servers": ["${DOMAIN}"]
  },

  "show_labs_settings": false,
  "default_country_code": "US",

  "jitsi": {
    "preferred_domain": "${MEET_DOMAIN}"
  },

  "jitsi_widget": {
    "skip_built_in_welcome_screen": true
  },

  "features": {
    "feature_video_rooms": false,
    "feature_group_calls": false,
    "feature_element_call_video_rooms": false
  },

  "setting_defaults": {
    "breadcrumbs": true
  },

  "map_style_url": null
}
EWEOF

###############################################################################
# WELL-KNOWN FILES (Matrix server + client discovery)
###############################################################################
echo -e "${CYAN}Generating .well-known files...${NC}"

cat > "$DATA_DIR/nginx/html/.well-known/matrix/server" <<WKSEOF
{
  "m.server": "${DOMAIN}:443"
}
WKSEOF

cat > "$DATA_DIR/nginx/html/.well-known/matrix/client" <<WKCEOF
{
  "m.homeserver": {
    "base_url": "${PUBLIC_URL}"
  }
}
WKCEOF

###############################################################################
# NGINX CONFIG
###############################################################################
echo -e "${CYAN}Generating Nginx config...${NC}"

if [ "$NO_TLS" = true ]; then
###############################################################################
# NGINX — HTTP ONLY (LAN/no-tls mode)
###############################################################################
cat > "$DATA_DIR/nginx/nginx.conf" <<NGXEOF
worker_processes auto;
worker_rlimit_nofile 8192;
error_log /var/log/nginx/error.log warn;

events {
    worker_connections 2048;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    sendfile      on;
    tcp_nopush    on;
    tcp_nodelay   on;

    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;

    client_max_body_size 100M;
    proxy_connect_timeout 60s;
    proxy_send_timeout    600s;
    proxy_read_timeout    600s;

    upstream synapse    { server 172.42.0.3:8008; }
    upstream elementweb { server 172.42.0.4:80;   }
    upstream jitsiweb   { server 172.42.0.22:80;  }

    server {
        listen 80;
        server_name ${DOMAIN};

        location /.well-known/matrix/ {
            root /var/www/html;
            default_type application/json;
            add_header Access-Control-Allow-Origin "*" always;
            add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
            add_header Access-Control-Allow-Headers "Origin, X-Requested-With, Content-Type, Accept, Authorization" always;
        }

        location /_matrix {
            proxy_pass http://synapse;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }

        location /_matrix/client/v3/sync {
            proxy_pass http://synapse;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_read_timeout 600s;
        }

        location /_synapse {
            proxy_pass http://synapse;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }

        location / {
            proxy_pass http://elementweb;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
        }
    }

    server {
        listen 80;
        server_name ${MEET_DOMAIN};

        location / {
            proxy_pass http://jitsiweb;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }
}
NGXEOF

else
###############################################################################
# NGINX — HTTPS + TLS mode
###############################################################################
cat > "$DATA_DIR/nginx/nginx.conf" <<NGXEOF
worker_processes auto;
worker_rlimit_nofile 8192;
error_log /var/log/nginx/error.log warn;

events {
    worker_connections 2048;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    sendfile      on;
    tcp_nopush    on;
    tcp_nodelay   on;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    add_header Content-Security-Policy "frame-ancestors 'self'" always;

    # TLS settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    client_max_body_size 100M;
    proxy_connect_timeout 60s;
    proxy_send_timeout    600s;
    proxy_read_timeout    600s;

    upstream synapse    { server 172.42.0.3:8008; }
    upstream elementweb { server 172.42.0.4:80;   }
    upstream jitsiweb   { server 172.42.0.22:80;  }

    ###########################################################################
    # HTTP → HTTPS redirect + ACME challenge
    ###########################################################################
    server {
        listen 80;
        server_name ${DOMAIN} ${MEET_DOMAIN};

        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }

        location / {
            return 301 https://\$host\$request_uri;
        }
    }

    ###########################################################################
    # MATRIX + ELEMENT WEB — ${DOMAIN}
    ###########################################################################
    server {
        listen 443 ssl;
        server_name ${DOMAIN};

        ssl_certificate     /etc/nginx/certs/live/${DOMAIN}/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/live/${DOMAIN}/privkey.pem;

        # .well-known for Matrix federation + client discovery
        location /.well-known/matrix/ {
            root /var/www/html;
            default_type application/json;
            add_header Access-Control-Allow-Origin "*" always;
            add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
            add_header Access-Control-Allow-Headers "Origin, X-Requested-With, Content-Type, Accept, Authorization" always;
        }

        # Matrix Client + Federation API
        location /_matrix {
            proxy_pass http://synapse;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }

        # Matrix sync (long-poll — extended timeout)
        location /_matrix/client/v3/sync {
            proxy_pass http://synapse;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_read_timeout 600s;
        }

        # Synapse Admin API
        location /_synapse {
            proxy_pass http://synapse;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }

        # Element Web (default)
        location / {
            proxy_pass http://elementweb;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
        }
    }

    ###########################################################################
    # JITSI VIDEO — ${MEET_DOMAIN}
    ###########################################################################
    server {
        listen 443 ssl;
        server_name ${MEET_DOMAIN};

        ssl_certificate     /etc/nginx/certs/live/${DOMAIN}/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/live/${DOMAIN}/privkey.pem;

        location / {
            proxy_pass http://jitsiweb;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }
}
NGXEOF
fi

###############################################################################
# TLS — Let's Encrypt Certificates
# Requests cert for both DOMAIN and meet.DOMAIN (wildcard via -d flags)
###############################################################################
if [ "$NO_TLS" = false ]; then
  echo -e "${CYAN}Bootstrapping TLS certificates via Let's Encrypt...${NC}"
  echo -e "${YELLOW}Requires ports 80/443 accessible from internet and DNS pointing to ${EXTERNAL_IP}${NC}"

  mkdir -p "$DATA_DIR/nginx/certs"
  mkdir -p "$DATA_DIR/nginx/html/.well-known/acme-challenge"
  chmod 777 "$DATA_DIR/nginx/certs"
  chmod 777 "$DATA_DIR/nginx/html"

  # Write minimal bootstrap nginx config (serves ACME challenge only)
  cat > /tmp/nginx-bootstrap.conf <<BSEOF
events {}
http {
  server {
    listen 80;
    server_name ${DOMAIN} ${MEET_DOMAIN};
    location /.well-known/acme-challenge/ {
      root /var/www/certbot;
    }
    location / {
      return 200 'Setting up TLS...';
      add_header Content-Type text/plain;
    }
  }
}
BSEOF

  # Kill anything on port 80 that might interfere
  echo -e "${YELLOW}Starting temporary HTTP server for ACME challenge...${NC}"
  docker rm -f matrix-certbot-bootstrap 2>/dev/null || true

  docker run -d --name matrix-certbot-bootstrap \
    -v "/tmp/nginx-bootstrap.conf:/etc/nginx/nginx.conf:ro" \
    -v "${DATA_DIR}/nginx/html:/var/www/certbot" \
    -p 80:80 nginx:alpine

  sleep 3

  # Request certificate for both domains
  if docker run --rm \
    -v "${DATA_DIR}/nginx/certs:/etc/letsencrypt" \
    -v "${DATA_DIR}/nginx/html:/var/www/certbot" \
    certbot/certbot certonly \
      --webroot -w /var/www/certbot \
      -d "${DOMAIN}" \
      -d "${MEET_DOMAIN}" \
      --email "${ADMIN_EMAIL}" \
      --agree-tos \
      --non-interactive \
      --force-renewal 2>&1; then
    echo -e "${GREEN}TLS certificate obtained successfully.${NC}"
  else
    echo -e "${YELLOW}WARNING: Let's Encrypt failed. Generating self-signed certificate (dev/LAN use only)...${NC}"
    mkdir -p "${DATA_DIR}/nginx/certs/live/${DOMAIN}"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout "${DATA_DIR}/nginx/certs/live/${DOMAIN}/privkey.pem" \
      -out "${DATA_DIR}/nginx/certs/live/${DOMAIN}/fullchain.pem" \
      -subj "/CN=${DOMAIN}" \
      -addext "subjectAltName=DNS:${DOMAIN},DNS:${MEET_DOMAIN}" 2>/dev/null
    echo -e "${YELLOW}Self-signed cert created. Browser will show a security warning.${NC}"
  fi

  docker rm -f matrix-certbot-bootstrap 2>/dev/null || true
  rm -f /tmp/nginx-bootstrap.conf

  # Set permissions on certs so coturn and synapse can read them
  chmod -R 755 "${DATA_DIR}/nginx/certs" 2>/dev/null || true
fi

###############################################################################
# FINAL PERMISSIONS — Unraid runs as root; set 777 so all containers can write
###############################################################################
echo -e "${CYAN}Setting final directory permissions (Unraid compatibility)...${NC}"
chmod -R 777 "$DATA_DIR"
chmod 600 "$PROJECT_DIR/.env"
chmod 600 "$DATA_DIR/synapse/appdata/homeserver.yaml"
chmod 600 "$DATA_DIR/coturn/config/turnserver.conf"

###############################################################################
# ADMIN SCRIPTS
###############################################################################
echo -e "${CYAN}Generating admin scripts...${NC}"

# ─── scripts/load-env.sh — safe .env parser, sourced by all scripts ───
cat > "$PROJECT_DIR/scripts/load-env.sh" <<'LOADEOF'
#!/usr/bin/env bash
# Safe .env loader — sources key=value pairs, handles quoted values.
# Usage: source "$(dirname "$0")/load-env.sh"

_ENV_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}") /.." && pwd)/.env"
# Handle both script-relative and direct calls
_ENV_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)/.env"
if [ ! -f "$_ENV_FILE" ]; then
  # Try locating it relative to the caller
  _ENV_FILE="$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")/.env"
fi
if [ ! -f "$_ENV_FILE" ]; then
  echo "ERROR: .env not found. Run setup.sh first." >&2
  exit 1
fi

while IFS= read -r line || [ -n "$line" ]; do
  [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
  key="${line%%=*}"
  val="${line#*=}"
  # Strip surrounding double-quotes
  val="${val#\"}"
  val="${val%\"}"
  # Strip surrounding single-quotes
  val="${val#\'}"
  val="${val%\'}"
  # Only export valid variable names
  if [[ "$key" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
    export "$key=$val"
  fi
done < "$_ENV_FILE"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOADEOF

# ─── scripts/create-user.sh ───
cat > "$PROJECT_DIR/scripts/create-user.sh" <<'USREOF'
#!/usr/bin/env bash
set -euo pipefail
# Create a Matrix user (or admin)
# Usage: ./scripts/create-user.sh <username> [--admin]
source "$(dirname "$0")/load-env.sh"

USERNAME="${1:?Usage: $0 <username> [--admin]}"
ADMIN_FLAG=""
if [ "${2:-}" = "--admin" ]; then
  ADMIN_FLAG="--admin"
  echo "Creating ADMIN user @${USERNAME}:${SERVER_NAME}"
else
  echo "Creating user @${USERNAME}:${SERVER_NAME}"
fi

read -s -p "Password: " PASSWORD
echo ""
read -s -p "Confirm:  " PASSWORD2
echo ""
if [ "$PASSWORD" != "$PASSWORD2" ]; then
  echo "ERROR: Passwords do not match."
  exit 1
fi

docker exec -i matrix-synapse register_new_matrix_user \
  -u "$USERNAME" \
  -p "$PASSWORD" \
  -c /data/homeserver.yaml \
  $ADMIN_FLAG \
  http://localhost:8008

echo ""
echo "✓ User @${USERNAME}:${SERVER_NAME} created successfully."
if [ -n "$ADMIN_FLAG" ]; then
  echo "  This user has admin privileges."
fi
USREOF

# ─── scripts/create-admin.sh — shortcut for admin creation ───
cat > "$PROJECT_DIR/scripts/create-admin.sh" <<'ADMEOF'
#!/usr/bin/env bash
set -euo pipefail
# Shortcut: create an admin user
# Usage: ./scripts/create-admin.sh <username>
source "$(dirname "$0")/load-env.sh"

USERNAME="${1:?Usage: $0 <admin-username>}"
exec "$(dirname "$0")/create-user.sh" "$USERNAME" --admin
ADMEOF

# ─── scripts/reset-password.sh ───
cat > "$PROJECT_DIR/scripts/reset-password.sh" <<'RPEOF'
#!/usr/bin/env bash
set -euo pipefail
# Reset a user's password via Synapse Admin API
# Usage: ./scripts/reset-password.sh <username> <admin-access-token>
#
# To get your admin token:
#   Log in to Element Web → Settings → Help & About → Access Token
source "$(dirname "$0")/load-env.sh"

USERNAME="${1:?Usage: $0 <username> <admin-access-token>}"
TOKEN="${2:?Usage: $0 <username> <admin-access-token>}"
USER_ID="@${USERNAME}:${SERVER_NAME}"

read -s -p "New password for ${USER_ID}: " PASSWORD
echo ""
read -s -p "Confirm: " PASSWORD2
echo ""
if [ "$PASSWORD" != "$PASSWORD2" ]; then
  echo "ERROR: Passwords do not match."
  exit 1
fi

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"new_password\": \"${PASSWORD}\", \"logout_devices\": true}" \
  "http://localhost:8008/_synapse/admin/v1/reset_password/${USER_ID}")

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ Password reset for ${USER_ID}."
  echo "  All existing sessions have been logged out."
else
  echo "✗ Failed (HTTP ${HTTP_CODE})."
  echo "  Check your admin token is valid and the user exists."
fi
RPEOF

# ─── scripts/list-users.sh ───
cat > "$PROJECT_DIR/scripts/list-users.sh" <<'LUEOF'
#!/usr/bin/env bash
set -euo pipefail
# List all registered users
# Usage: ./scripts/list-users.sh <admin-access-token>
source "$(dirname "$0")/load-env.sh"

TOKEN="${1:?Usage: $0 <admin-access-token>}"

RESPONSE=$(curl -sf \
  -H "Authorization: Bearer ${TOKEN}" \
  "http://localhost:8008/_synapse/admin/v2/users?limit=200&guests=false" 2>&1) || {
  echo "ERROR: Could not connect to Synapse. Is the stack running?"
  exit 1
}

echo "$RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
except json.JSONDecodeError as e:
    print(f'ERROR: Invalid JSON from server: {e}')
    sys.exit(1)

if 'errcode' in data:
    print(f'ERROR: {data[\"errcode\"]}: {data.get(\"error\", \"unknown\")}')
    print('Check your admin access token is valid.')
    sys.exit(1)

users = data.get('users', [])
if not users:
    print('No users found.')
    sys.exit(0)

print(f'{'Username':<40} {'Admin':<8} {'Deactivated':<12} {'Guest':<6}')
print('-' * 70)
for u in users:
    name = u.get('name', '')
    admin = 'YES' if u.get('admin') else ''
    deact = 'YES' if u.get('deactivated') else ''
    guest = 'YES' if u.get('is_guest') else ''
    print(f'{name:<40} {admin:<8} {deact:<12} {guest:<6}')
print(f'\nTotal: {len(users)} user(s)')
"
LUEOF

# ─── scripts/deactivate-user.sh ───
cat > "$PROJECT_DIR/scripts/deactivate-user.sh" <<'DUEOF'
#!/usr/bin/env bash
set -euo pipefail
# Deactivate a user account (prevents login, does NOT delete data by default)
# Usage: ./scripts/deactivate-user.sh <username> <admin-access-token>
# Add --erase to also delete user's messages and data
source "$(dirname "$0")/load-env.sh"

USERNAME="${1:?Usage: $0 <username> <admin-token> [--erase]}"
TOKEN="${2:?Usage: $0 <username> <admin-token> [--erase]}"
ERASE=false
[ "${3:-}" = "--erase" ] && ERASE=true

USER_ID="@${USERNAME}:${SERVER_NAME}"

echo "Deactivating ${USER_ID} (erase=${ERASE})..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"erase\": ${ERASE}}" \
  "http://localhost:8008/_synapse/admin/v1/deactivate/${USER_ID}")

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ ${USER_ID} deactivated."
else
  echo "✗ Failed (HTTP ${HTTP_CODE}). Check username and admin token."
fi
DUEOF

# ─── scripts/backup.sh ───
cat > "$PROJECT_DIR/scripts/backup.sh" <<'BKEOF'
#!/usr/bin/env bash
set -euo pipefail
# Full server backup: database, configs, signing keys, media
# Usage: ./scripts/backup.sh [backup-dir]
source "$(dirname "$0")/load-env.sh"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${1:-${PROJECT_DIR}/backups/${TIMESTAMP}}"
mkdir -p "$BACKUP_DIR"

echo "=== Matrix-TextVoiceVideo Backup ==="
echo "Destination: $BACKUP_DIR"
echo ""

# PostgreSQL dump
echo "[1/4] Backing up PostgreSQL database..."
docker exec matrix-postgres pg_dump \
  -U "$POSTGRES_USER" \
  --format=custom \
  --compress=9 \
  "$POSTGRES_DB" > "$BACKUP_DIR/synapse.pgdump"
echo "      ✓ Database: $(du -sh "$BACKUP_DIR/synapse.pgdump" | cut -f1)"

# Configs and secrets
echo "[2/4] Backing up configs and secrets..."
cp "$DATA_DIR/synapse/appdata/homeserver.yaml" "$BACKUP_DIR/" 2>/dev/null || true
cp "$DATA_DIR/coturn/config/turnserver.conf"  "$BACKUP_DIR/" 2>/dev/null || true
cp "$PROJECT_DIR/.env"                         "$BACKUP_DIR/dot.env" 2>/dev/null || true
chmod 600 "$BACKUP_DIR/dot.env" 2>/dev/null || true
echo "      ✓ Configs copied"

# Signing key (CRITICAL — loss means users cannot verify your server)
echo "[3/4] Backing up Synapse signing key..."
find "$DATA_DIR/synapse/appdata" -name "*.signing.key" -exec cp {} "$BACKUP_DIR/" \; 2>/dev/null || true
echo "      ✓ Signing key backed up (KEEP THIS SAFE)"

# Media store (optional — can be large)
echo "[4/4] Backing up media store (may take a while)..."
tar -czf "$BACKUP_DIR/media_store.tar.gz" \
  -C "$DATA_DIR/synapse" \
  media_store 2>/dev/null && \
  echo "      ✓ Media: $(du -sh "$BACKUP_DIR/media_store.tar.gz" | cut -f1)" || \
  echo "      ⚠ Media backup skipped (empty or error)"

echo ""
echo "✓ Backup complete: $BACKUP_DIR"
echo ""
ls -lh "$BACKUP_DIR/"
echo ""
echo "To restore:"
echo "  DB:  docker exec -i matrix-postgres pg_restore -U $POSTGRES_USER -d $POSTGRES_DB < $BACKUP_DIR/synapse.pgdump"
echo "  Configs: copy files back and run docker compose restart"
BKEOF

# ─── scripts/status.sh ───
cat > "$PROJECT_DIR/scripts/status.sh" <<'STEOF'
#!/usr/bin/env bash
# Check status of all matrix-textvoicevideo services
# Usage: ./scripts/status.sh

source "$(dirname "$0")/load-env.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}=== Container Status ===${NC}"
cd "$PROJECT_DIR" && (docker compose ps 2>/dev/null || docker-compose ps 2>/dev/null || echo "(docker compose unavailable)")

echo ""
echo -e "${CYAN}=== Internal Service Health ===${NC}"

check_internal() {
  local name="$1" url="$2"
  if curl -sf --connect-timeout 3 --max-time 5 "$url" > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} $name"
  else
    echo -e "  ${RED}✗${NC} $name  ${YELLOW}(not responding at $url)${NC}"
  fi
}

check_internal "Postgres"      "$(docker exec matrix-postgres pg_isready -U $POSTGRES_USER -d $POSTGRES_DB -q 2>/dev/null && echo OK || echo FAIL)" || true
# Use docker exec for postgres since it's not http
if docker exec matrix-postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" -q 2>/dev/null; then
  echo -e "  ${GREEN}✓${NC} PostgreSQL"
else
  echo -e "  ${RED}✗${NC} PostgreSQL (not ready)"
fi
check_internal "Synapse API"    "http://172.42.0.3:8008/_matrix/client/versions"
check_internal "Element Web"    "http://172.42.0.4:80"
check_internal "Nginx (HTTP)"   "http://172.42.0.10:80"

echo ""
echo -e "${CYAN}=== Jitsi Services ===${NC}"
check_internal "Jitsi Web"      "http://172.42.0.22:80"

echo ""
echo -e "${CYAN}=== External Endpoints ===${NC}"
check_external() {
  local name="$1" url="$2"
  if curl -sfk --connect-timeout 5 --max-time 10 "$url" > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} $name"
  else
    echo -e "  ${RED}✗${NC} $name  ${YELLOW}(check DNS + port forwarding)${NC}"
  fi
}
check_external "Matrix HTTPS"       "${PUBLIC_URL}/_matrix/client/versions"
check_external "Well-Known Client"  "${PUBLIC_URL}/.well-known/matrix/client"
check_external "Well-Known Server"  "${PUBLIC_URL}/.well-known/matrix/server"
check_external "Jitsi Video"        "${JITSI_PUBLIC_URL}"

echo ""
echo -e "${CYAN}=== Coturn TURN Server ===${NC}"
if command -v nc >/dev/null 2>&1; then
  if nc -zu "$EXTERNAL_IP" 3478 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Coturn UDP 3478 reachable"
  else
    echo -e "  ${YELLOW}⚠${NC} Coturn UDP 3478 — check port forwarding"
  fi
else
  echo "  (install netcat to test Coturn)"
fi

echo ""
echo -e "${CYAN}=== Resource Usage ===${NC}"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.Status}}" 2>/dev/null \
  | grep -E "matrix-|jitsi-" | head -20 || echo "(no containers running)"

echo ""
echo -e "${CYAN}=== Configuration ===${NC}"
echo "  Domain:       ${SERVER_NAME}"
echo "  Public URL:   ${PUBLIC_URL}"
echo "  Jitsi:        ${JITSI_PUBLIC_URL}"
echo "  External IP:  ${EXTERNAL_IP}"
echo "  Internal IP:  ${INTERNAL_IP}"
echo "  Data Dir:     ${DATA_DIR}"
STEOF

# ─── scripts/rotate-secrets.sh ───
cat > "$PROJECT_DIR/scripts/rotate-secrets.sh" <<'RSEOF'
#!/usr/bin/env bash
set -euo pipefail
# Rotate TURN secret and Jitsi passwords
# WARNING: After rotation you must restart the full stack
source "$(dirname "$0")/load-env.sh"

echo "This will rotate TURN and Jitsi secrets."
echo "All users in active voice/video calls will be disconnected."
read -p "Continue? (y/N): " confirm
[ "$confirm" != "y" ] && [ "$confirm" != "Y" ] && exit 0

NEW_TURN="$(openssl rand -base64 48 | tr -d '/+=\n' | head -c 48)"
NEW_JICOFO="$(openssl rand -base64 32 | tr -d '/+=\n' | head -c 32)"
NEW_JVB="$(openssl rand -base64 32 | tr -d '/+=\n' | head -c 32)"

sed -i "s|^TURN_SECRET=.*|TURN_SECRET=\"${NEW_TURN}\"|"               "$PROJECT_DIR/.env"
sed -i "s|^JICOFO_AUTH_PASSWORD=.*|JICOFO_AUTH_PASSWORD=\"${NEW_JICOFO}\"|" "$PROJECT_DIR/.env"
sed -i "s|^JVB_AUTH_PASSWORD=.*|JVB_AUTH_PASSWORD=\"${NEW_JVB}\"|"    "$PROJECT_DIR/.env"

# Also update coturn config
sed -i "s|^static-auth-secret=.*|static-auth-secret=${NEW_TURN}|"     "$DATA_DIR/coturn/config/turnserver.conf"
# Also update homeserver.yaml
sed -i "s|^turn_shared_secret:.*|turn_shared_secret: \"${NEW_TURN}\"|" "$DATA_DIR/synapse/appdata/homeserver.yaml"

echo "✓ Secrets rotated."
echo ""
echo "Restart the stack to apply:"
echo "  cd $PROJECT_DIR && docker compose down && docker compose up -d"
RSEOF

chmod +x "$PROJECT_DIR/scripts/"*.sh

###############################################################################
# MAKEFILE
###############################################################################
cat > "$PROJECT_DIR/Makefile" <<'MKEOF'
.PHONY: up down restart logs status ps create-user create-admin backup

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose down && docker compose up -d

logs:
	docker compose logs -f --tail=100

status:
	./scripts/status.sh

ps:
	docker compose ps

create-user:
	@read -p "Username: " user; ./scripts/create-user.sh $$user

create-admin:
	@read -p "Username: " user; ./scripts/create-admin.sh $$user

backup:
	./scripts/backup.sh

list-users:
	@read -p "Admin access token: " tok; ./scripts/list-users.sh $$tok
MKEOF

###############################################################################
# DONE
###############################################################################
echo ""
echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║                     SETUP COMPLETE                               ║${NC}"
echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Domain:${NC}       ${CYAN}${DOMAIN}${NC}"
echo -e "  ${BOLD}Jitsi:${NC}        ${CYAN}${MEET_DOMAIN}${NC}"
echo -e "  ${BOLD}Public URL:${NC}   ${CYAN}${PUBLIC_URL}${NC}"
echo -e "  ${BOLD}External IP:${NC}  ${CYAN}${EXTERNAL_IP}${NC}"
echo -e "  ${BOLD}Internal IP:${NC}  ${CYAN}${INTERNAL_IP}${NC}"
echo -e "  ${BOLD}Data Dir:${NC}     ${CYAN}${DATA_DIR}${NC}"
echo -e "  ${BOLD}TLS:${NC}          ${CYAN}$( [ "$NO_TLS" = true ] && echo 'Disabled (HTTP only)' || echo 'Enabled (Let'\''s Encrypt)' )${NC}"
echo ""
echo -e "${YELLOW}${BOLD}NEXT STEPS:${NC}"
echo ""
echo "  1. Start the stack:"
echo -e "     ${CYAN}cd ${PROJECT_DIR} && docker compose up -d${NC}"
echo ""
echo "  2. Wait ~30 seconds for all services to initialize, then:"
echo -e "     ${CYAN}./scripts/status.sh${NC}"
echo ""
echo "  3. Create your first admin user:"
echo -e "     ${CYAN}./scripts/create-admin.sh admin${NC}"
echo ""
echo "  4. Create regular users:"
echo -e "     ${CYAN}./scripts/create-user.sh alice${NC}"
echo ""
echo "  5. Open in browser:"
echo -e "     ${CYAN}${PUBLIC_URL}${NC}"
echo ""
echo -e "${YELLOW}${BOLD}PORT FORWARDING REQUIRED:${NC}"
echo "  80  → Unraid:60080   (HTTP / ACME)"
echo "  443 → Unraid:60443   (HTTPS)"
echo "  3478 UDP+TCP → Coturn (TURN/STUN voice relay)"
echo "  5349 TCP     → Coturn (TURNS over TLS)"
echo "  49160-49250 UDP → Coturn media relay"
echo "  10000 UDP   → Jitsi JVB (video)"
echo ""
echo -e "${YELLOW}${BOLD}IMPORTANT:${NC}"
echo "  • .env has all secrets — chmod 600, keep it safe"
echo "  • Synapse signing key in ${DATA_DIR}/synapse/appdata/ is IRREPLACEABLE"
echo -e "  • Run ${CYAN}./scripts/backup.sh${NC} before any updates"
echo ""
