#!/usr/bin/env bash
set -euo pipefail

###############################################################################
#  MATRIX-TEXTVOICEVIDEO — Turnkey Self-Hosted Discord Alternative
#  Generates all secrets, configs, TLS, and launches the full stack.
#  Usage:  sudo ./setup.sh --domain chat.example.com [--external-ip 1.2.3.4]
#          sudo ./setup.sh --domain chat.example.com --no-tls   (LAN-only)
###############################################################################

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

banner() {
  echo -e "${CYAN}"
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║    MATRIX-TEXTVOICEVIDEO · Self-Hosted Discord Alternative  ║"
  echo "║   Text · Voice · Video · WebRTC · Secure by Default        ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

usage() {
  echo "Usage: $0 --domain <FQDN> [OPTIONS]"
  echo ""
  echo "Required:"
  echo "  --domain <FQDN>        Your server's fully qualified domain name"
  echo ""
  echo "Optional:"
  echo "  --external-ip <IP>     Public IP (auto-detected if omitted)"
  echo "  --no-tls               Skip TLS / Let's Encrypt (LAN-only mode)"
  echo "  --admin-email <email>  Email for Let's Encrypt (default: admin@DOMAIN)"
  echo "  --data-dir <path>      Data directory (default: ./data)"
  echo "  --reset                Wipe all data and start fresh"
  echo "  -h, --help             Show this help"
  exit 1
}

###############################################################################
# PARSE ARGUMENTS
###############################################################################
DOMAIN=""
EXTERNAL_IP=""
NO_TLS=false
ADMIN_EMAIL=""
DATA_DIR="./data"
RESET=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --domain)       DOMAIN="$2"; shift 2 ;;
    --external-ip)  EXTERNAL_IP="$2"; shift 2 ;;
    --no-tls)       NO_TLS=true; shift ;;
    --admin-email)  ADMIN_EMAIL="$2"; shift 2 ;;
    --data-dir)     DATA_DIR="$2"; shift 2 ;;
    --reset)        RESET=true; shift ;;
    -h|--help)      usage ;;
    *)              echo -e "${RED}Unknown option: $1${NC}"; usage ;;
  esac
done

banner

if [ -z "$DOMAIN" ]; then
  echo -e "${RED}ERROR: --domain is required${NC}"
  usage
fi

if [ -z "$ADMIN_EMAIL" ]; then
  ADMIN_EMAIL="admin@${DOMAIN}"
fi

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$(realpath "$DATA_DIR" 2>/dev/null || echo "$PROJECT_DIR/data")"

###############################################################################
# DETECT EXTERNAL IP  (multiple fallback services, JSON-safe)
###############################################################################
detect_external_ip() {
  local ip=""

  # Try JSON API first (cleanest)
  ip=$(curl -4 -sf --connect-timeout 5 --max-time 10 'https://api.ipify.org?format=json' 2>/dev/null \
       | grep -oP '"ip"\s*:\s*"\K[0-9.]+' || true)

  # Fallback: plain-text services
  if [ -z "$ip" ]; then
    ip=$(curl -4 -sf --connect-timeout 5 --max-time 10 https://ifconfig.me 2>/dev/null || true)
  fi
  if [ -z "$ip" ]; then
    ip=$(curl -4 -sf --connect-timeout 5 --max-time 10 https://icanhazip.com 2>/dev/null | tr -d '[:space:]' || true)
  fi
  if [ -z "$ip" ]; then
    ip=$(curl -4 -sf --connect-timeout 5 --max-time 10 https://ipecho.net/plain 2>/dev/null || true)
  fi
  if [ -z "$ip" ]; then
    ip=$(curl -4 -sf --connect-timeout 5 --max-time 10 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]' || true)
  fi

  # Validate it looks like an IPv4 address
  if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "$ip"
  else
    echo ""
  fi
}

if [ -z "$EXTERNAL_IP" ]; then
  echo -e "${YELLOW}Detecting external IP...${NC}"
  EXTERNAL_IP=$(detect_external_ip)
  if [ -z "$EXTERNAL_IP" ]; then
    echo -e "${RED}ERROR: Could not auto-detect external IP.${NC}"
    echo -e "${YELLOW}Please re-run with: --external-ip YOUR.PUBLIC.IP${NC}"
    exit 1
  fi
  echo -e "${GREEN}Detected: ${EXTERNAL_IP}${NC}"
fi

INTERNAL_IP=$(hostname -I | awk '{print $1}')

###############################################################################
# RESET CHECK
###############################################################################
if [ "$RESET" = true ]; then
  echo -e "${RED}WARNING: This will destroy ALL data (database, media, keys).${NC}"
  read -p "Type 'YES' to confirm: " confirm
  if [ "$confirm" = "YES" ]; then
    docker compose -f "$PROJECT_DIR/docker-compose.yml" down -v 2>/dev/null || true
    rm -rf "$DATA_DIR"
    echo -e "${GREEN}Reset complete.${NC}"
  else
    echo "Aborted."; exit 1
  fi
fi

###############################################################################
# SECRET GENERATION
###############################################################################
gen_secret()   { openssl rand -base64 "$1" | tr -d '/+\n=' | head -c "$1"; }
gen_hex()      { openssl rand -hex "$1"; }
gen_password() { openssl rand -base64 32 | tr -d '/+=\n' | head -c 32; }

echo -e "${CYAN}Generating cryptographic secrets...${NC}"

POSTGRES_PASSWORD="$(gen_password)"
SYNAPSE_REGISTRATION_SECRET="$(gen_secret 48)"
SYNAPSE_MACAROON_KEY="$(gen_secret 48)"
SYNAPSE_FORM_SECRET="$(gen_secret 48)"
TURN_SECRET="$(gen_secret 48)"
LIVEKIT_API_KEY="API$(gen_hex 8)"
LIVEKIT_API_SECRET="$(gen_secret 48)"
JWT_SECRET="$(gen_secret 32)"

###############################################################################
# CREATE DIRECTORY STRUCTURE
###############################################################################
echo -e "${CYAN}Creating directory structure...${NC}"

mkdir -p "$DATA_DIR"/{postgres,synapse/{appdata,media_store},livekit/{config,appdata}}
mkdir -p "$DATA_DIR"/{coturn/config,nginx/{conf.d,certs,html},element-web/config,element-call/config}
mkdir -p "$DATA_DIR"/{well-known,valkey}
mkdir -p "$PROJECT_DIR"/scripts

###############################################################################
# DETERMINE SCHEME AND PORTS
###############################################################################
if [ "$NO_TLS" = true ]; then
  SCHEME="http"
  PUBLIC_URL="${SCHEME}://${DOMAIN}"
  WS_SCHEME="ws"
else
  SCHEME="https"
  PUBLIC_URL="${SCHEME}://${DOMAIN}"
  WS_SCHEME="wss"
fi

###############################################################################
# GENERATE .env FILE  — ALL VALUES QUOTED TO PREVENT BASH INTERPRETATION
###############################################################################
echo -e "${CYAN}Writing .env...${NC}"

cat > "$PROJECT_DIR/.env" <<ENVEOF
###############################################################################
# matrix-textvoicevideo · Auto-generated $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Domain: ${DOMAIN}
###############################################################################

# IDENTITY — DO NOT CHANGE AFTER FIRST RUN
SERVER_NAME="${DOMAIN}"
PUBLIC_URL="${PUBLIC_URL}"
SCHEME="${SCHEME}"

# NETWORK
EXTERNAL_IP="${EXTERNAL_IP}"
INTERNAL_IP="${INTERNAL_IP}"

# POSTGRES
POSTGRES_USER="synapse"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD}"
POSTGRES_DB="synapse"
POSTGRES_INITDB_ARGS="--encoding=UTF8 --lc-collate=C --lc-ctype=C"

# SYNAPSE SECRETS
SYNAPSE_REGISTRATION_SECRET="${SYNAPSE_REGISTRATION_SECRET}"
SYNAPSE_MACAROON_KEY="${SYNAPSE_MACAROON_KEY}"
SYNAPSE_FORM_SECRET="${SYNAPSE_FORM_SECRET}"

# TURN / COTURN
TURN_SECRET="${TURN_SECRET}"

# LIVEKIT
LIVEKIT_API_KEY="${LIVEKIT_API_KEY}"
LIVEKIT_API_SECRET="${LIVEKIT_API_SECRET}"

# JWT (for LiveKit auth)
JWT_SECRET="${JWT_SECRET}"

# TLS
NO_TLS="${NO_TLS}"
ADMIN_EMAIL="${ADMIN_EMAIL}"

# PATHS
DATA_DIR="${DATA_DIR}"
ENVEOF

chmod 600 "$PROJECT_DIR/.env"

###############################################################################
# SYNAPSE homeserver.yaml
###############################################################################
echo -e "${CYAN}Generating Synapse homeserver.yaml...${NC}"

cat > "$DATA_DIR/synapse/appdata/homeserver.yaml" <<SYEOF
##################################################################
# Synapse Homeserver — Auto-generated by matrix-textvoicevideo
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
# DATABASE — PostgreSQL with C locale
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
# REDIS / VALKEY  — Required for worker coordination
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

# Do NOT trust external key servers — fully self-hosted
trusted_key_servers: []

# Registration is CLOSED by default — use admin scripts to add users
enable_registration: false
enable_registration_without_verification: false

# Rate limiting (protects against abuse)
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

# Session / token settings
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
# TURN (Coturn)
##################################################################
turn_uris:
  - "turn:${DOMAIN}:3478?transport=udp"
  - "turn:${DOMAIN}:3478?transport=tcp"
  - "turns:${DOMAIN}:5349?transport=tcp"
turn_shared_secret: "${TURN_SECRET}"
turn_user_lifetime: 1h
turn_allow_guests: false

##################################################################
# VOIP / WEBRTC — MatrixRTC for Element Call + LiveKit
##################################################################
experimental_features:
  msc3266_enabled: true
  msc4222_enabled: true

##################################################################
# FEDERATION — disabled by default for private servers
##################################################################
# Set to true and remove whitelist to enable federation
#federation_domain_whitelist: []
allow_public_rooms_over_federation: false

##################################################################
# CACHING — tuned for 10-50 concurrent users
##################################################################
caches:
  global_factor: 1.0
  per_cache_factors:
    get_users_in_room: 2.0

# vim:ft=yaml
SYEOF

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
###############################################################################
echo -e "${CYAN}Generating Coturn config...${NC}"

cat > "$DATA_DIR/coturn/config/turnserver.conf" <<TURNEOF
# Coturn TURN Server — Auto-generated
realm=${DOMAIN}
use-auth-secret
static-auth-secret=${TURN_SECRET}

# Network
listening-port=3478
tls-listening-port=5349
min-port=49160
max-port=49250
external-ip=${EXTERNAL_IP}/${INTERNAL_IP}

# Security
fingerprint
lt-cred-mech
no-cli
no-tlsv1
no-tlsv1_1
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

# Performance — support 50 concurrent calls
total-quota=300
bps-capacity=0
stale-nonce=600
max-bps=3000000

# Logging
log-file=stdout
verbose
TURNEOF

###############################################################################
# LIVEKIT CONFIG (SFU for 10-50 user video/voice)
###############################################################################
echo -e "${CYAN}Generating LiveKit config...${NC}"

cat > "$DATA_DIR/livekit/config/livekit.yaml" <<LKEOF
# LiveKit SFU — Auto-generated
# Tuned for 10-50 concurrent video/voice participants

port: 7880
bind_addresses:
  - "0.0.0.0"

rtc:
  tcp_port: 7881
  port_range_start: 50000
  port_range_end: 50200
  use_external_ip: true
  # Advertise public IP so remote clients can reach this SFU
  node_ip: ${EXTERNAL_IP}
  enable_loopback_candidate: false

keys:
  ${LIVEKIT_API_KEY}: ${LIVEKIT_API_SECRET}

room:
  # Disable auto-create — lk-jwt-service manages room creation
  auto_create: false
  max_participants: 50
  empty_timeout: 300
  departure_timeout: 20

# Redis / Valkey for signaling coordination
redis:
  address: matrix-valkey:6379

# TURN integration — use our Coturn server as fallback
turn:
  enabled: true
  domain: ${DOMAIN}
  tls_port: 5349
  udp_port: 3478
  external_tls: true

# Logging
logging:
  level: info
  pion_level: warn
LKEOF

###############################################################################
# ELEMENT WEB CONFIG
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
  "element_call": {
    "url": "${PUBLIC_URL}/call",
    "participant_limit": 50,
    "brand": "Video Call"
  },
  "features": {
    "feature_video_rooms": true,
    "feature_group_calls": true,
    "feature_element_call_video_rooms": true
  },
  "setting_defaults": {
    "breadcrumbs": true
  },
  "map_style_url": null
}
EWEOF

###############################################################################
# ELEMENT CALL CONFIG  — points to lk-jwt-service via nginx
###############################################################################
echo -e "${CYAN}Generating Element Call config...${NC}"

cat > "$DATA_DIR/element-call/config/config.json" <<ECEOF
{
  "default_server_config": {
    "m.homeserver": {
      "base_url": "${PUBLIC_URL}",
      "server_name": "${DOMAIN}"
    }
  },
  "livekit": {
    "livekit_service_url": "${PUBLIC_URL}/livekit/jwt"
  }
}
ECEOF

###############################################################################
# .well-known for Matrix delegation + MatrixRTC SFU discovery (MSC4143)
###############################################################################
echo -e "${CYAN}Generating .well-known files...${NC}"

mkdir -p "$DATA_DIR/well-known/.well-known/matrix"

cat > "$DATA_DIR/well-known/.well-known/matrix/server" <<WKEOF
{
  "m.server": "${DOMAIN}:443"
}
WKEOF

cat > "$DATA_DIR/well-known/.well-known/matrix/client" <<WKCEOF
{
  "m.homeserver": {
    "base_url": "${PUBLIC_URL}"
  },
  "org.matrix.msc4143.rtc_foci": [
    {
      "type": "livekit",
      "livekit_service_url": "${PUBLIC_URL}/livekit/jwt"
    }
  ]
}
WKCEOF

###############################################################################
# NGINX CONFIG
###############################################################################
echo -e "${CYAN}Generating Nginx config...${NC}"

if [ "$NO_TLS" = true ]; then
# ======================== HTTP-ONLY CONFIG ========================
cat > "$DATA_DIR/nginx/nginx.conf" <<'NGXEOF'
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
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;

    # File upload size (match Synapse max_upload_size)
    client_max_body_size 100M;

    # Timeouts for WebSocket / long-poll
    proxy_connect_timeout 60s;
    proxy_send_timeout    600s;
    proxy_read_timeout    600s;

    # Upstreams — using container names on the matrix-net bridge
    upstream synapse      { server 172.42.0.3:8008; }
    upstream elementweb   { server 172.42.0.4:80;   }
    upstream elementcall  { server 172.42.0.5:8080;  }
    upstream livekit_sfu  { server 172.42.0.6:7880;  }
    upstream livekit_jwt  { server 172.42.0.8:8080;  }

    server {
        listen 80;
        server_name PLACEHOLDER_DOMAIN;

        # .well-known for federation, client discovery, and MatrixRTC
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
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Matrix Sync — long-poll needs extended timeout
        location /_matrix/client/v3/sync {
            proxy_pass http://synapse;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_read_timeout 600s;
        }

        # Synapse admin API
        location /_synapse {
            proxy_pass http://synapse;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            # Restrict admin to localhost / private networks in production:
            # allow 127.0.0.0/8;
            # allow 10.0.0.0/8;
            # allow 172.16.0.0/12;
            # allow 192.168.0.0/16;
            # deny all;
        }

        ###############################################################
        # MATRIXRTC / LIVEKIT  (voice + video)
        ###############################################################

        # LiveKit JWT auth service (lk-jwt-service)
        location ^~ /livekit/jwt/ {
            proxy_pass http://livekit_jwt/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # LiveKit SFU WebSocket + HTTP
        location ^~ /livekit/sfu/ {
            proxy_pass http://livekit_sfu/;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            proxy_buffering off;
        }

        # Legacy /sfu/get endpoint (older Element Call clients)
        location /sfu/get {
            proxy_pass http://livekit_jwt/sfu/get;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        ###############################################################
        # ELEMENT CALL
        ###############################################################
        location /call {
            proxy_pass http://elementcall;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location /call/ {
            proxy_pass http://elementcall/;
            proxy_set_header Host $host;
        }

        ###############################################################
        # ELEMENT WEB (default)
        ###############################################################
        location / {
            proxy_pass http://elementweb;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }
}
NGXEOF

# Replace placeholder
sed -i "s/PLACEHOLDER_DOMAIN/${DOMAIN}/g" "$DATA_DIR/nginx/nginx.conf"

else
# ======================== TLS CONFIG ========================
cat > "$DATA_DIR/nginx/nginx.conf" <<'NGXEOF'
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

    # TLS
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

    # Upstreams — using static IPs on the matrix-net bridge
    upstream synapse      { server 172.42.0.3:8008; }
    upstream elementweb   { server 172.42.0.4:80;   }
    upstream elementcall  { server 172.42.0.5:8080;  }
    upstream livekit_sfu  { server 172.42.0.6:7880;  }
    upstream livekit_jwt  { server 172.42.0.8:8080;  }

    # HTTP → HTTPS redirect + ACME challenge
    server {
        listen 80;
        server_name PLACEHOLDER_DOMAIN;

        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }

        location / {
            return 301 https://$host$request_uri;
        }
    }

    server {
        listen 443 ssl;
        server_name PLACEHOLDER_DOMAIN;

        ssl_certificate     /etc/nginx/certs/live/PLACEHOLDER_DOMAIN/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/live/PLACEHOLDER_DOMAIN/privkey.pem;

        # .well-known for federation, client discovery, and MatrixRTC
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
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Matrix Sync — long-poll needs extended timeout
        location /_matrix/client/v3/sync {
            proxy_pass http://synapse;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_read_timeout 600s;
        }

        # Synapse admin API
        location /_synapse {
            proxy_pass http://synapse;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        ###############################################################
        # MATRIXRTC / LIVEKIT  (voice + video)
        ###############################################################

        # LiveKit JWT auth service (lk-jwt-service)
        location ^~ /livekit/jwt/ {
            proxy_pass http://livekit_jwt/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # LiveKit SFU WebSocket + HTTP
        location ^~ /livekit/sfu/ {
            proxy_pass http://livekit_sfu/;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            proxy_buffering off;
        }

        # Legacy /sfu/get endpoint (older Element Call clients)
        location /sfu/get {
            proxy_pass http://livekit_jwt/sfu/get;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        ###############################################################
        # ELEMENT CALL
        ###############################################################
        location /call {
            proxy_pass http://elementcall;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location /call/ {
            proxy_pass http://elementcall/;
            proxy_set_header Host $host;
        }

        ###############################################################
        # ELEMENT WEB (default)
        ###############################################################
        location / {
            proxy_pass http://elementweb;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }
}
NGXEOF

sed -i "s/PLACEHOLDER_DOMAIN/${DOMAIN}/g" "$DATA_DIR/nginx/nginx.conf"
fi

###############################################################################
# LANDING PAGE
###############################################################################
cat > "$DATA_DIR/nginx/html/index.html" <<HTMLEOF
<!DOCTYPE html>
<html><head><title>${DOMAIN} — Matrix Chat</title></head>
<body style="font-family:sans-serif;text-align:center;margin-top:50px;">
<h1>Welcome to ${DOMAIN}</h1>
<p>Use <a href="/"><b>Element Web</b></a> to chat.</p>
</body></html>
HTMLEOF

# Copy well-known into nginx html root
cp -r "$DATA_DIR/well-known/.well-known" "$DATA_DIR/nginx/html/"

###############################################################################
# DOCKER COMPOSE — Static IPs, Unraid labels, Valkey, lk-jwt-service
###############################################################################
echo -e "${CYAN}Generating docker-compose.yml...${NC}"

cat > "$PROJECT_DIR/docker-compose.yml" <<'DCEOF'
###############################################################################
# MATRIX-TEXTVOICEVIDEO — Docker Compose Stack
# Self-Hosted Discord Alternative
# Text · Voice · Video · WebRTC · 10-50 concurrent users
#
# Service IPs (matrix-net 172.42.0.0/24):
#   postgres     172.42.0.2
#   synapse      172.42.0.3
#   element-web  172.42.0.4
#   element-call 172.42.0.5
#   livekit      172.42.0.6
#   valkey       172.42.0.7
#   lk-jwt-svc   172.42.0.8
#   nginx        172.42.0.10
###############################################################################

networks:
  matrix-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.42.0.0/24

services:

  ###########################################################################
  # VALKEY (Redis replacement) — Synapse + LiveKit coordination
  ###########################################################################
  valkey:
    image: valkey/valkey:latest
    container_name: matrix-valkey
    command: ["valkey-server", "--appendonly", "yes"]
    volumes:
      - ${DATA_DIR}/valkey:/data
    networks:
      matrix-net:
        ipv4_address: 172.42.0.7
    # ports:
    #   - "6379:6379"          # Uncomment for debug only
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "valkey-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    labels:
      net.unraid.docker.icon: "https://raw.githubusercontent.com/SnuK87/unraid-templates/refs/heads/main/icons/valkey-logo.png"
      net.unraid.docker.managed: "composeman"

  ###########################################################################
  # POSTGRES — Database (C locale for Synapse)
  ###########################################################################
  postgres:
    image: postgres:16-alpine
    container_name: matrix-postgres
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_INITDB_ARGS: ${POSTGRES_INITDB_ARGS}
    volumes:
      - ${DATA_DIR}/postgres:/var/lib/postgresql/data
    networks:
      matrix-net:
        ipv4_address: 172.42.0.2
    # ports:
    #   - "5432:5432"          # Uncomment for debug only
    restart: unless-stopped
    shm_size: 256mb
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5
    labels:
      net.unraid.docker.icon: "https://cdn.jsdelivr.net/gh/selfhst/icons/png/postgresql.png"
      net.unraid.docker.managed: "composeman"

  ###########################################################################
  # SYNAPSE — Matrix Homeserver
  ###########################################################################
  synapse:
    image: matrixdotorg/synapse:latest
    container_name: matrix-synapse
    depends_on:
      postgres:
        condition: service_healthy
      valkey:
        condition: service_healthy
    environment:
      SYNAPSE_SERVER_NAME: ${SERVER_NAME}
      SYNAPSE_REPORT_STATS: "no"
    volumes:
      - ${DATA_DIR}/synapse/appdata:/data
      - ${DATA_DIR}/synapse/media_store:/data/media_store
    networks:
      matrix-net:
        ipv4_address: 172.42.0.3
    # ports:
    #   - "8008:8008"          # Uncomment for debug only
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-fSs", "http://localhost:8008/health"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 30s
    labels:
      net.unraid.docker.icon: "https://cdn.jsdelivr.net/gh/selfhst/icons/png/matrix.png"
      net.unraid.docker.webui: "http://[IP]:8008/_matrix/client/versions"
      net.unraid.docker.managed: "composeman"

  ###########################################################################
  # LIVEKIT — WebRTC SFU (Voice/Video)
  ###########################################################################
  livekit:
    image: livekit/livekit-server:latest
    container_name: matrix-livekit
    command: ["--config", "/etc/livekit.yaml", "--node-ip", "${EXTERNAL_IP}"]
    depends_on:
      valkey:
        condition: service_healthy
    volumes:
      - ${DATA_DIR}/livekit/config/livekit.yaml:/etc/livekit.yaml:ro
    networks:
      matrix-net:
        ipv4_address: 172.42.0.6
    ports:
      # These MUST be exposed — WebRTC media traffic
      - "7881:7881/tcp"
      - "50000-50200:50000-50200/udp"
      # - "7880:7880/tcp"     # Uncomment for debug only (SFU HTTP/WS)
    restart: unless-stopped
    labels:
      net.unraid.docker.icon: "https://pbs.twimg.com/profile_images/1791157444829380609/M6p5M6-A_400x400.png"
      net.unraid.docker.managed: "composeman"

  ###########################################################################
  # LK-JWT-SERVICE — MatrixRTC Authorization (LiveKit JWT tokens)
  ###########################################################################
  lk-jwt-service:
    image: ghcr.io/element-hq/lk-jwt-service:latest
    container_name: matrix-lk-jwt
    depends_on:
      - livekit
      - synapse
    environment:
      LIVEKIT_JWT_PORT: "8080"
      LIVEKIT_URL: "${SCHEME}://${SERVER_NAME}/livekit/sfu"
      LIVEKIT_KEY: "${LIVEKIT_API_KEY}"
      LIVEKIT_SECRET: "${LIVEKIT_API_SECRET}"
      LIVEKIT_FULL_ACCESS_HOMESERVERS: "${SERVER_NAME}"
    networks:
      matrix-net:
        ipv4_address: 172.42.0.8
    # ports:
    #   - "8090:8080"          # Uncomment for debug only
    restart: unless-stopped
    labels:
      net.unraid.docker.icon: "https://cdn.jsdelivr.net/gh/selfhst/icons/png/element.png"
      net.unraid.docker.managed: "composeman"

  ###########################################################################
  # ELEMENT WEB — Chat UI (like Discord)
  ###########################################################################
  element-web:
    image: vectorim/element-web:latest
    container_name: matrix-element-web
    volumes:
      - ${DATA_DIR}/element-web/config/config.json:/app/config.json:ro
    networks:
      matrix-net:
        ipv4_address: 172.42.0.4
    # ports:
    #   - "8080:80"            # Uncomment for debug only
    restart: unless-stopped
    labels:
      net.unraid.docker.icon: "https://cdn.jsdelivr.net/gh/selfhst/icons/png/element.png"
      net.unraid.docker.managed: "composeman"

  ###########################################################################
  # ELEMENT CALL — Video/Voice Call UI
  ###########################################################################
  element-call:
    image: ghcr.io/element-hq/element-call:latest
    container_name: matrix-element-call
    volumes:
      - ${DATA_DIR}/element-call/config/config.json:/app/config.json:ro
    networks:
      matrix-net:
        ipv4_address: 172.42.0.5
    # ports:
    #   - "8082:8080"          # Uncomment for debug only
    restart: unless-stopped
    labels:
      net.unraid.docker.icon: "https://cdn.jsdelivr.net/gh/selfhst/icons/png/element.png"
      net.unraid.docker.managed: "composeman"

  ###########################################################################
  # COTURN — TURN/STUN relay for NAT traversal (host networking required)
  ###########################################################################
  coturn:
    image: coturn/coturn:latest
    container_name: matrix-coturn
    network_mode: host
    volumes:
      - ${DATA_DIR}/coturn/config/turnserver.conf:/etc/coturn/turnserver.conf:ro
    restart: unless-stopped
    labels:
      net.unraid.docker.icon: "https://raw.githubusercontent.com/xthursdayx/docker-templates/master/xthursdayx/images/webrtc-icon.png"
      net.unraid.docker.managed: "composeman"

  ###########################################################################
  # NGINX — Reverse Proxy + TLS Termination
  ###########################################################################
  nginx:
    image: nginx:alpine
    container_name: matrix-nginx
    volumes:
      - ${DATA_DIR}/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ${DATA_DIR}/nginx/html:/var/www/html:ro
      - ${DATA_DIR}/nginx/certs:/etc/nginx/certs:ro
    networks:
      matrix-net:
        ipv4_address: 172.42.0.10
    ports:
      - "60080:80"
      - "60443:443"
    depends_on:
      - synapse
      - element-web
      - element-call
      - livekit
      - lk-jwt-service
    restart: unless-stopped
    labels:
      net.unraid.docker.icon: "https://nginxproxymanager.com/icon.png"
      net.unraid.docker.webui: "http://[IP]:60080"
      net.unraid.docker.managed: "composeman"

  ###########################################################################
  # CERTBOT — Auto TLS cert renewal (optional, activate with tls profile)
  ###########################################################################
  certbot:
    image: certbot/certbot:latest
    container_name: matrix-certbot
    profiles: ["tls"]
    volumes:
      - ${DATA_DIR}/nginx/certs:/etc/letsencrypt
      - ${DATA_DIR}/nginx/html:/var/www/certbot
    entrypoint: /bin/sh -c 'trap exit TERM; while :; do certbot renew --webroot -w /var/www/certbot --quiet; sleep 12h & wait $${!}; done'
    restart: unless-stopped
    labels:
      net.unraid.docker.icon: "https://cdn.jsdelivr.net/gh/selfhst/icons/png/lets-encrypt.png"
      net.unraid.docker.managed: "composeman"
DCEOF

###############################################################################
# TLS BOOTSTRAPPING
###############################################################################
if [ "$NO_TLS" = false ]; then
  echo -e "${CYAN}Bootstrapping TLS certificates with Let's Encrypt...${NC}"
  echo -e "${YELLOW}(Requires ports 80/443 open and DNS pointing to this server)${NC}"

  mkdir -p "$DATA_DIR/nginx/certs"

  # Write temp bootstrap nginx config
  cat > "$DATA_DIR/nginx/nginx-bootstrap.conf" <<BSEOF
events {}
http {
  server {
    listen 80;
    server_name ${DOMAIN};
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 200 'Waiting for TLS setup...'; add_header Content-Type text/plain; }
  }
}
BSEOF

  # Start temp nginx
  docker run -d --name matrix-certbot-bootstrap \
    -v "$DATA_DIR/nginx/nginx-bootstrap.conf:/etc/nginx/nginx.conf:ro" \
    -v "$DATA_DIR/nginx/html:/var/www/certbot" \
    -p 80:80 nginx:alpine 2>/dev/null || true

  sleep 2

  # Get certificate
  docker run --rm \
    -v "$DATA_DIR/nginx/certs:/etc/letsencrypt" \
    -v "$DATA_DIR/nginx/html:/var/www/certbot" \
    certbot/certbot certonly --webroot -w /var/www/certbot \
    -d "$DOMAIN" --email "$ADMIN_EMAIL" --agree-tos --non-interactive \
    --force-renewal 2>&1 || {
      echo -e "${YELLOW}TLS certificate request failed. Falling back to self-signed...${NC}"
      mkdir -p "$DATA_DIR/nginx/certs/live/${DOMAIN}"
      openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$DATA_DIR/nginx/certs/live/${DOMAIN}/privkey.pem" \
        -out "$DATA_DIR/nginx/certs/live/${DOMAIN}/fullchain.pem" \
        -subj "/CN=${DOMAIN}" 2>/dev/null
    }

  docker rm -f matrix-certbot-bootstrap 2>/dev/null || true
  rm -f "$DATA_DIR/nginx/nginx-bootstrap.conf"
fi

###############################################################################
# SET FILE PERMISSIONS
###############################################################################
echo -e "${CYAN}Setting secure file permissions...${NC}"

chmod 600 "$PROJECT_DIR/.env"
chmod 600 "$DATA_DIR/synapse/appdata/homeserver.yaml"
chmod 600 "$DATA_DIR/coturn/config/turnserver.conf"
chmod 600 "$DATA_DIR/livekit/config/livekit.yaml"

# Synapse needs write access to its data dir
chown -R 991:991 "$DATA_DIR/synapse" 2>/dev/null || true

###############################################################################
# GENERATE ADMIN SCRIPTS
###############################################################################
echo -e "${CYAN}Generating admin scripts...${NC}"

# ─── Helper: safe .env loader (sourced by all admin scripts) ───
cat > "$PROJECT_DIR/scripts/load-env.sh" <<'LOADEOF'
#!/usr/bin/env bash
# Safe .env loader — reads key=value pairs even if values contain spaces.
# Usage:  source "$(dirname "$0")/load-env.sh"

_ENV_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.env"
if [ ! -f "$_ENV_FILE" ]; then
  echo "ERROR: .env not found at $_ENV_FILE" >&2
  echo "       Run setup.sh first to generate it." >&2
  exit 1
fi

# Read each non-comment, non-empty line and export it safely
while IFS= read -r line || [ -n "$line" ]; do
  # Skip blanks and comments
  [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
  # Strip surrounding quotes from the value
  key="${line%%=*}"
  val="${line#*=}"
  # Remove leading/trailing double-quotes if present
  val="${val#\"}"
  val="${val%\"}"
  # Remove leading/trailing single-quotes if present
  val="${val#\'}"
  val="${val%\'}"
  export "$key=$val"
done < "$_ENV_FILE"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOADEOF

# ─── create-user.sh ───
cat > "$PROJECT_DIR/scripts/create-user.sh" <<'USREOF'
#!/usr/bin/env bash
set -euo pipefail
# Usage: ./scripts/create-user.sh <username> [--admin]
source "$(dirname "$0")/load-env.sh"

USERNAME="${1:?Usage: $0 <username> [--admin]}"
ADMIN_FLAG=""
if [ "${2:-}" = "--admin" ]; then ADMIN_FLAG="--admin"; fi

read -s -p "Password for @${USERNAME}:${SERVER_NAME}: " PASSWORD
echo ""
read -s -p "Confirm password: " PASSWORD2
echo ""
if [ "$PASSWORD" != "$PASSWORD2" ]; then echo "Passwords don't match!"; exit 1; fi

docker exec -it matrix-synapse register_new_matrix_user \
  -u "$USERNAME" \
  -p "$PASSWORD" \
  -c /data/homeserver.yaml \
  $ADMIN_FLAG \
  http://localhost:8008

echo ""
echo "✓ User @${USERNAME}:${SERVER_NAME} created."
USREOF

# ─── reset-password.sh ───
cat > "$PROJECT_DIR/scripts/reset-password.sh" <<'RPEOF'
#!/usr/bin/env bash
set -euo pipefail
# Usage: ./scripts/reset-password.sh <username> <admin-token>
source "$(dirname "$0")/load-env.sh"

USERNAME="${1:?Usage: $0 <username> <admin-token>}"
TOKEN="${2:?Usage: $0 <username> <admin-token>}"
USER_ID="@${USERNAME}:${SERVER_NAME}"

read -s -p "New password for ${USER_ID}: " PASSWORD
echo ""
read -s -p "Confirm: " PASSWORD2
echo ""
if [ "$PASSWORD" != "$PASSWORD2" ]; then echo "Passwords don't match!"; exit 1; fi

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"new_password\": \"${PASSWORD}\", \"logout_devices\": true}" \
  "http://localhost:8008/_synapse/admin/v1/reset_password/${USER_ID}")

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ Password reset for ${USER_ID}."
else
  echo "✗ Failed (HTTP ${HTTP_CODE}). Verify your admin token is valid."
  echo ""
  echo "To get an admin token, log into Element Web as an admin user,"
  echo "then go to Settings → Help & About → Access Token."
fi
RPEOF

# ─── list-users.sh ───
cat > "$PROJECT_DIR/scripts/list-users.sh" <<'LUEOF'
#!/usr/bin/env bash
set -euo pipefail
# Lists all registered users (requires admin token)
# Usage: ./scripts/list-users.sh <admin-token>
source "$(dirname "$0")/load-env.sh"

TOKEN="${1:?Usage: $0 <admin-access-token>}"

curl -s -H "Authorization: Bearer ${TOKEN}" \
  "http://localhost:8008/_synapse/admin/v2/users?limit=100" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
users = data.get('users', [])
if not users:
    print('  No users found (or invalid token).')
else:
    for u in users:
        admin = '(admin)' if u.get('admin') else ''
        print(f\"  {u['name']} {admin}\")
    print(f\"\n  Total: {len(users)} users\")
"
LUEOF

# ─── deactivate-user.sh ───
cat > "$PROJECT_DIR/scripts/deactivate-user.sh" <<'DUEOF'
#!/usr/bin/env bash
set -euo pipefail
# Usage: ./scripts/deactivate-user.sh <username> <admin-token>
source "$(dirname "$0")/load-env.sh"

USERNAME="${1:?Usage: $0 <username> <admin-token>}"
TOKEN="${2:?Usage: $0 <username> <admin-token>}"
USER_ID="@${USERNAME}:${SERVER_NAME}"

echo "Deactivating ${USER_ID}..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"erase": false}' \
  "http://localhost:8008/_synapse/admin/v1/deactivate/${USER_ID}")

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ User ${USER_ID} deactivated."
else
  echo "✗ Failed (HTTP ${HTTP_CODE}). Verify your admin token and username."
fi
DUEOF

# ─── rotate-secrets.sh ───
cat > "$PROJECT_DIR/scripts/rotate-secrets.sh" <<'RSEOF'
#!/usr/bin/env bash
set -euo pipefail
# Rotates TURN and LiveKit secrets (requires restart)
echo "This will rotate TURN and LiveKit secrets and restart services."
read -p "Continue? (y/N): " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then exit 0; fi

source "$(dirname "$0")/load-env.sh"

NEW_TURN="$(openssl rand -base64 48 | tr -d '/+=\n' | head -c 48)"
NEW_LK_SECRET="$(openssl rand -base64 48 | tr -d '/+=\n' | head -c 48)"

# Update .env (handles quoted values)
sed -i "s|^TURN_SECRET=.*|TURN_SECRET=\"${NEW_TURN}\"|" "$PROJECT_DIR/.env"
sed -i "s|^LIVEKIT_API_SECRET=.*|LIVEKIT_API_SECRET=\"${NEW_LK_SECRET}\"|" "$PROJECT_DIR/.env"

echo "✓ Secrets rotated in .env."
echo ""
echo "IMPORTANT: You must regenerate configs and restart:"
echo "  1. Re-run:  sudo ./setup.sh --domain ${SERVER_NAME}"
echo "  2. Then:    docker compose down && docker compose up -d"
RSEOF

# ─── backup.sh ───
cat > "$PROJECT_DIR/scripts/backup.sh" <<'BKEOF'
#!/usr/bin/env bash
set -euo pipefail
# Creates a full backup of the Matrix server
source "$(dirname "$0")/load-env.sh"

BACKUP_DIR="${1:-${PROJECT_DIR}/backups/$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$BACKUP_DIR"

echo "Backing up PostgreSQL..."
docker exec matrix-postgres pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > "$BACKUP_DIR/synapse.sql"

echo "Backing up configs..."
cp "$DATA_DIR/synapse/appdata/homeserver.yaml" "$BACKUP_DIR/"
cp "$DATA_DIR/synapse/appdata/"*.signing.key "$BACKUP_DIR/" 2>/dev/null || true
cp "$PROJECT_DIR/.env" "$BACKUP_DIR/"

echo "Backing up media..."
tar -czf "$BACKUP_DIR/media_store.tar.gz" -C "$DATA_DIR/synapse" media_store 2>/dev/null || true

echo "✓ Backup complete: $BACKUP_DIR"
ls -lh "$BACKUP_DIR/"
BKEOF

# ─── status.sh ───
cat > "$PROJECT_DIR/scripts/status.sh" <<'STEOF'
#!/usr/bin/env bash
set -euo pipefail
# Shows the status of all services

echo "=== Container Status ==="
docker compose ps 2>/dev/null || docker-compose ps 2>/dev/null || echo "(docker compose not available)"

echo ""
echo "=== Service Health ==="
source "$(dirname "$0")/load-env.sh"

check() {
  local name="$1" url="$2"
  if curl -sf --connect-timeout 3 "$url" > /dev/null 2>&1; then
    echo "  ✓ $name"
  else
    echo "  ✗ $name (unreachable)"
  fi
}

check "Synapse API"       "http://172.42.0.3:8008/_matrix/client/versions"
check "Element Web"       "http://172.42.0.4:80"
check "Element Call"      "http://172.42.0.5:8080"
check "LiveKit SFU"       "http://172.42.0.6:7880"
check "LK-JWT-Service"    "http://172.42.0.8:8080/healthz"
check "Nginx (HTTP)"      "http://172.42.0.10:80"

echo ""
echo "=== External Endpoints ==="
check "Public HTTPS"      "${PUBLIC_URL}/_matrix/client/versions"
check "Well-Known Client" "${PUBLIC_URL}/.well-known/matrix/client"
check "LiveKit JWT Health" "${PUBLIC_URL}/livekit/jwt/healthz"

echo ""
echo "=== Resource Usage ==="
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>/dev/null | head -20
STEOF

chmod +x "$PROJECT_DIR"/scripts/*.sh

###############################################################################
# GENERATE MAKEFILE
###############################################################################
cat > "$PROJECT_DIR/Makefile" <<'MKEOF'
.PHONY: up down restart logs status create-user backup ps

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

create-user:
	@read -p "Username: " user; ./scripts/create-user.sh $$user

create-admin:
	@read -p "Username: " user; ./scripts/create-user.sh $$user --admin

backup:
	./scripts/backup.sh

ps:
	docker compose ps
MKEOF

###############################################################################
# GENERATE README
###############################################################################
cat > "$PROJECT_DIR/README.md" <<'READMEEOF'
# Matrix-TextVoiceVideo — Self-Hosted Discord Alternative

A turnkey, Docker-based Matrix server stack providing Discord-like text, voice,
and video chat. Supports 10-50 concurrent users in voice/video rooms.

## Stack

| Service            | Purpose                          | Image                                | IP           |
|--------------------|----------------------------------|--------------------------------------|--------------|
| **Synapse**        | Matrix homeserver                | `matrixdotorg/synapse`               | 172.42.0.3   |
| **PostgreSQL**     | Database (C locale)              | `postgres:16-alpine`                 | 172.42.0.2   |
| **Element Web**    | Chat UI (like Discord)           | `vectorim/element-web`               | 172.42.0.4   |
| **Element Call**   | Video/Voice UI                   | `ghcr.io/element-hq/element-call`    | 172.42.0.5   |
| **LiveKit**        | WebRTC SFU (group video/voice)   | `livekit/livekit-server`             | 172.42.0.6   |
| **Valkey**         | Redis-compatible cache/queue     | `valkey/valkey`                      | 172.42.0.7   |
| **LK-JWT-Service** | MatrixRTC authorization          | `ghcr.io/element-hq/lk-jwt-service` | 172.42.0.8   |
| **Coturn**         | TURN/STUN relay (NAT traversal)  | `coturn/coturn`                      | host network |
| **Nginx**          | Reverse proxy + TLS              | `nginx:alpine`                       | 172.42.0.10  |
| **Certbot**        | Auto TLS renewal                 | `certbot/certbot`                    | —            |

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/bmartino1/matrix-textvoicevideo.git
cd matrix-textvoicevideo

# 2. Run setup
chmod +x setup.sh
sudo ./setup.sh --domain chat.yourdomain.com

# 3. Start the stack
docker compose up -d

# 4. Create your first admin user
./scripts/create-user.sh admin --admin

# 5. Create regular users
./scripts/create-user.sh alice
./scripts/create-user.sh bob
```

## LAN-Only (No TLS)

```bash
sudo ./setup.sh --domain myserver.local --no-tls
```

## Specify External IP Manually

If auto-detection fails (e.g. behind a proxy):

```bash
sudo ./setup.sh --domain chat.example.com --external-ip 203.0.113.42
```

## Admin Scripts

| Script                         | Purpose                    |
|--------------------------------|----------------------------|
| `scripts/create-user.sh`      | Register new user          |
| `scripts/reset-password.sh`   | Reset user password        |
| `scripts/list-users.sh`       | List all users             |
| `scripts/deactivate-user.sh`  | Disable a user account     |
| `scripts/rotate-secrets.sh`   | Rotate TURN/LiveKit keys   |
| `scripts/backup.sh`           | Full server backup         |
| `scripts/status.sh`           | Check service health       |

All admin scripts use `scripts/load-env.sh` to safely parse the `.env` file
(handles spaces, quotes, and special characters in values).

## Architecture

```
Internet → Nginx (60443/60080) → Element Web (chat UI)
                                → Synapse (/_matrix, /_synapse)
                                → Element Call (/call)
                                → LK-JWT-Service (/livekit/jwt) → LiveKit JWT auth
                                → LiveKit SFU (/livekit/sfu)    → WebRTC signaling
         → Coturn (3478 UDP/TCP, 5349 TLS)                     → TURN relay
         → LiveKit (7881 TCP, 50000-50200 UDP)                  → WebRTC media
```

### Voice/Video Call Flow

1. User clicks "Call" in Element Web → requests OpenID token from Synapse
2. Element Call sends token to LK-JWT-Service via `/livekit/jwt/`
3. LK-JWT-Service validates against Synapse, returns LiveKit JWT
4. Client connects to LiveKit SFU with the JWT
5. LiveKit routes audio/video between participants
6. Coturn provides TURN relay for users behind strict NATs

## Security Defaults

- Registration is **disabled** — use admin scripts to create users
- PostgreSQL initialized with **C locale** (required by Synapse)
- All secrets **auto-generated** with cryptographic randomness
- `.env` values are **quoted** to prevent shell injection
- Trusted key servers **empty** — fully self-hosted, no matrix.org dependency
- TURN server denies relay to **all private IP ranges**
- Rate limiting on registration, login, and messaging
- Password policy: 10+ chars, upper + lower + digit required
- Internal service ports **commented out** by default (uncomment for debug)
- No ports exposed except Nginx, Coturn, and LiveKit UDP

## Firewall Requirements

| Port          | Protocol | Service    | Purpose               |
|---------------|----------|------------|-----------------------|
| 60080         | TCP      | Nginx      | HTTP / ACME           |
| 60443         | TCP      | Nginx      | HTTPS                 |
| 3478          | UDP+TCP  | Coturn     | TURN/STUN             |
| 5349          | TCP      | Coturn     | TURNS (TLS)           |
| 49160-49250   | UDP      | Coturn     | TURN media relay      |
| 7881          | TCP      | LiveKit    | WebRTC TCP fallback   |
| 50000-50200   | UDP      | LiveKit    | WebRTC media          |

## Unraid Notes

This stack uses `composeman` labels for Unraid Docker management. Each container
has a custom icon and the Nginx container has a WebUI link configured. Deploy
via the Unraid Compose Manager or manually with `docker compose up -d`.

## Troubleshooting

### Voice/Video calls connect but no audio/video
- Verify `EXTERNAL_IP` in `.env` is your actual public IP
- Ensure ports 7881/tcp and 50000-50200/udp are forwarded
- Check LiveKit JWT service: `curl https://yourdomain.com/livekit/jwt/healthz`
- Check Coturn ports 3478 and 5349 are reachable

### "Failed to load service worker" warning
- This is a known Element Web warning about authenticated media
- It does not affect core functionality (text, voice, video all work)

### Admin scripts show "command not found"
- Ensure you're running scripts from the project root
- The `.env` file must be generated by `setup.sh` (values are quoted)

## Scaling Notes

- LiveKit SFU handles up to **50 participants** per room by default
- Valkey enables Synapse worker support for higher throughput
- For 100+ users, add Synapse workers (stream_writers, federation_sender)
- Coturn `total-quota=300` supports ~50 concurrent TURN relays
READMEEOF

###############################################################################
# GENERATE .gitignore
###############################################################################
cat > "$PROJECT_DIR/.gitignore" <<'GIEOF'
# Secrets
.env

# Data
data/
backups/

# OS
.DS_Store
*.swp
*.swo
*~

# IDE
.vscode/
.idea/
GIEOF

###############################################################################
# DONE
###############################################################################
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    SETUP COMPLETE                           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Domain:      ${CYAN}${DOMAIN}${NC}"
echo -e "  URL:         ${CYAN}${PUBLIC_URL}${NC}"
echo -e "  Data Dir:    ${CYAN}${DATA_DIR}${NC}"
echo -e "  External IP: ${CYAN}${EXTERNAL_IP}${NC}"
echo -e "  Internal IP: ${CYAN}${INTERNAL_IP}${NC}"
echo ""
echo -e "${YELLOW}NEXT STEPS:${NC}"
echo "  1. Start the stack:"
echo -e "     ${CYAN}docker compose up -d${NC}"
echo ""
echo "  2. Create your first admin user:"
echo -e "     ${CYAN}./scripts/create-user.sh admin --admin${NC}"
echo ""
echo "  3. Create regular users:"
echo -e "     ${CYAN}./scripts/create-user.sh alice${NC}"
echo ""
echo "  4. Open in browser:"
echo -e "     ${CYAN}${PUBLIC_URL}${NC}"
echo ""
echo -e "${YELLOW}SERVICE IPS (172.42.0.0/24):${NC}"
echo "  postgres     172.42.0.2"
echo "  synapse      172.42.0.3"
echo "  element-web  172.42.0.4"
echo "  element-call 172.42.0.5"
echo "  livekit      172.42.0.6"
echo "  valkey       172.42.0.7"
echo "  lk-jwt-svc   172.42.0.8"
echo "  nginx        172.42.0.10"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC}"
echo "  • .env contains all secrets — keep it safe! (chmod 600)"
echo "  • Signing keys in data/synapse/ are IRREPLACEABLE — back them up!"
echo -e "  • Run ${CYAN}./scripts/backup.sh${NC} regularly"
echo -e "  • Run ${CYAN}./scripts/status.sh${NC} to check service health"
echo ""
