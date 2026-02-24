#!/usr/bin/env bash
# =============================================================================
#  certbot-init.sh — Initial TLS certificate issuance for Unraid
#
#  Unraid hosts its own web GUI on ports 80 and 443.
#  Nginx in this stack uses host ports 60080 (HTTP) and 60443 (HTTPS).
#  Your router should NAT:
#    WAN :80  → Unraid IP :60080
#    WAN :443 → Unraid IP :60443
#
#  Certbot's HTTP-01 challenge: Let's Encrypt hits YOUR_DOMAIN:80 from the
#  internet → router forwards to :60080 on Unraid → certbot container bound
#  to that port.  We achieve this with -p 60080:80 on the certbot container.
# =============================================================================
set -euo pipefail

echo "=============================================="
echo "  Let's Encrypt — Initial Certificate Issuance"
echo "  (Unraid 60080/60443 topology)"
echo "=============================================="
echo ""

# ── Prompt for config ────────────────────────────────────────────────────────
read -rp "Primary domain (e.g. example.com): " DOMAIN
read -rp "Additional domain/subdomain (optional, press Enter to skip): " DOMAIN2
read -rp "Admin email for Let's Encrypt notices: " EMAIL

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${DATA_DIR:-$(dirname "$SCRIPT_DIR")/data}"
CERTS="${DATA_DIR}/nginx/certs"
WEBROOT="${DATA_DIR}/nginx/html"

mkdir -p "$CERTS" "$WEBROOT"

# ── Build -d flags ────────────────────────────────────────────────────────────
DOMAIN_FLAGS="-d ${DOMAIN}"
if [ -n "$DOMAIN2" ]; then
    DOMAIN_FLAGS="${DOMAIN_FLAGS} -d ${DOMAIN2}"
fi

echo ""
echo ">>> Checking that port 60080 is free..."
if ss -tlnp 2>/dev/null | grep -q ':60080 ' || \
   lsof -i:60080 >/dev/null 2>&1; then
    echo "ERROR: Port 60080 is already in use."
    echo "       Stop the nginx container first, then re-run this script."
    exit 1
fi

# ── Stop nginx so certbot can bind 60080 ────────────────────────────────────
echo ""
echo ">>> Stopping nginx container (if running)..."
NGINX_CONTAINER=$(docker ps --format '{{.Names}}' | grep -i 'nginx' | head -n1 || true)
if [ -n "$NGINX_CONTAINER" ]; then
    docker stop "$NGINX_CONTAINER"
    echo "    Stopped: $NGINX_CONTAINER"
else
    echo "    nginx not running — OK."
fi

# ── Issue certificate (standalone, bound to host :60080) ────────────────────
echo ""
echo ">>> Requesting certificate from Let's Encrypt..."
echo "    Domain(s): ${DOMAIN_FLAGS}"
echo "    Email    : ${EMAIL}"
echo ""

# shellcheck disable=SC2086
docker run --rm \
    -p 60080:80 \
    -v "${CERTS}:/etc/letsencrypt" \
    -v "${WEBROOT}:/var/www/certbot" \
    certbot/certbot certonly \
        --standalone \
        --http-01-port 80 \
        --preferred-challenges http \
        ${DOMAIN_FLAGS} \
        --email "${EMAIL}" \
        --agree-tos \
        --no-eff-email \
        --rsa-key-size 4096

# ── Restart nginx ─────────────────────────────────────────────────────────────
echo ""
echo ">>> Restarting nginx..."
if [ -n "$NGINX_CONTAINER" ]; then
    docker start "$NGINX_CONTAINER"
    echo "    Started: $NGINX_CONTAINER"
else
    # Try to find it even if it was stopped before we ran
    NGINX_CONTAINER=$(docker ps -a --format '{{.Names}}' | grep -i 'nginx' | head -n1 || true)
    if [ -n "$NGINX_CONTAINER" ]; then
        docker start "$NGINX_CONTAINER"
        echo "    Started: $NGINX_CONTAINER"
    else
        echo "    No nginx container found — start your stack manually."
    fi
fi

echo ""
echo "=============================================="
echo "  SUCCESS!"
echo "  Certificate stored at:"
echo "    ${CERTS}/live/${DOMAIN}/"
echo ""
echo "  Files:"
echo "    fullchain.pem  — certificate + chain"
echo "    privkey.pem    — private key"
echo ""
echo "  Next: run certbot-renew.sh periodically"
echo "        (or use a cron job / User Script in Unraid)"
echo "=============================================="
