#!/usr/bin/env bash
set -euo pipefail
# Renew Let's Encrypt certificate.
# Designed for monthly cron execution.
#
# Unraid User Scripts cron (monthly at 03:00 on the 1st):
#   0 3 1 * * /mnt/user/appdata/matrix-textvoicevideo/scripts/certbot-renew.sh

source "$(dirname "$0")/load-env.sh"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "[certbot-renew] $(date) — Starting renewal check..."

# Stop nginx to free port 60080
echo "[certbot-renew] Stopping nginx..."
(cd "$PROJECT_DIR" && docker compose stop nginx) || true
sleep 2

# Run renewal
docker run --rm \
  -v "${DATA_DIR}/nginx/certs:/etc/letsencrypt" \
  -v "${DATA_DIR}/nginx/html:/var/www/certbot" \
  -p "60080:80" \
  certbot/certbot renew \
    --standalone \
    --http-01-port 80 \
    --preferred-challenges http \
    --quiet

# Restart nginx
echo "[certbot-renew] Starting nginx..."
(cd "$PROJECT_DIR" && docker compose start nginx)

echo "[certbot-renew] ✓ Renewal complete."
