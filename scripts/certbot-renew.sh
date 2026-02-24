#!/usr/bin/env bash
# =============================================================================
#  certbot-renew.sh — TLS certificate renewal for Unraid
#
#  Same port topology as certbot-init.sh:
#    Router NAT: WAN:80 → Unraid:60080, WAN:443 → Unraid:60443
#    Certbot binds host :60080 via Docker -p 60080:80
#
#  Run this script periodically.  Recommended: Unraid User Scripts plugin,
#  scheduled monthly (certbot skips renewal if cert is still > 30 days valid).
#
#  Cron example (root crontab):
#    0 3 1 * * /mnt/user/appdata/matrix-textvoicevideo/scripts/certbot-renew.sh >> /var/log/certbot-renew.log 2>&1
# =============================================================================
set -euo pipefail

echo "=============================================="
echo "  Let's Encrypt — Certificate Renewal"
echo "  (Unraid 60080/60443 topology)"
echo "  $(date)"
echo "=============================================="

# ── Paths (mirror what init script used) ─────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${DATA_DIR:-$(dirname "$SCRIPT_DIR")/data}"
CERTS="${DATA_DIR}/nginx/certs"
WEBROOT="${DATA_DIR}/nginx/html"

if [ ! -d "${CERTS}/live" ]; then
    echo "ERROR: No certificates found at ${CERTS}/live"
    echo "       Run certbot-init.sh first."
    exit 1
fi

# ── Stop nginx ────────────────────────────────────────────────────────────────
echo ""
echo ">>> Stopping nginx container (if running)..."
NGINX_CONTAINER=$(docker ps --format '{{.Names}}' | grep -i 'nginx' | head -n1 || true)
if [ -n "$NGINX_CONTAINER" ]; then
    docker stop "$NGINX_CONTAINER"
    echo "    Stopped: $NGINX_CONTAINER"
else
    echo "    nginx not running — OK."
fi

# ── Check port 60080 is free ──────────────────────────────────────────────────
echo ""
echo ">>> Verifying port 60080 is free..."
if ss -tlnp 2>/dev/null | grep -q ':60080 ' || \
   lsof -i:60080 >/dev/null 2>&1; then
    echo "ERROR: Port 60080 still in use after stopping nginx."
    echo "       Cannot proceed — restart nginx manually after resolving."
    # Try to restart nginx before exiting so we don't leave it down
    [ -n "$NGINX_CONTAINER" ] && docker start "$NGINX_CONTAINER" || true
    exit 1
fi

# ── Renew ─────────────────────────────────────────────────────────────────────
echo ""
echo ">>> Running certbot renew..."
docker run --rm \
    -p 60080:80 \
    -v "${CERTS}:/etc/letsencrypt" \
    -v "${WEBROOT}:/var/www/certbot" \
    certbot/certbot renew \
        --standalone \
        --http-01-port 80 \
        --preferred-challenges http \
        --quiet

RENEW_EXIT=$?

# ── Restart nginx ─────────────────────────────────────────────────────────────
echo ""
echo ">>> Restarting nginx..."
if [ -n "$NGINX_CONTAINER" ]; then
    docker start "$NGINX_CONTAINER"
    echo "    Started: $NGINX_CONTAINER"
else
    NGINX_CONTAINER=$(docker ps -a --format '{{.Names}}' | grep -i 'nginx' | head -n1 || true)
    if [ -n "$NGINX_CONTAINER" ]; then
        docker start "$NGINX_CONTAINER"
        echo "    Started: $NGINX_CONTAINER"
    else
        echo "    WARNING: No nginx container found — start your stack manually."
    fi
fi

echo ""
if [ $RENEW_EXIT -eq 0 ]; then
    echo "=============================================="
    echo "  Renewal complete (or cert still valid)."
    echo "  $(date)"
    echo "=============================================="
else
    echo "=============================================="
    echo "  WARNING: certbot renew exited with code $RENEW_EXIT"
    echo "  Check output above for details."
    echo "=============================================="
    exit $RENEW_EXIT
fi
