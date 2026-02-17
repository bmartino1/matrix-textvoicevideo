#!/usr/bin/env bash
set -euo pipefail
# Renew Let's Encrypt certs (webroot) + reload services
# Usage: ./scripts/certbot-renew.sh
source "$(dirname "$0")/load-env.sh"

if [ "${NO_TLS:-false}" = "true" ]; then
  echo "NO_TLS=true — certbot not applicable."
  exit 0
fi

WEBROOT="${DATA_DIR}/nginx/html"
CERTS="${DATA_DIR}/nginx/certs"

mkdir -p "${WEBROOT}/.well-known/acme-challenge" "${CERTS}"
chmod -R 777 "${WEBROOT}" "${CERTS}" || true

echo "Running certbot renew..."
docker run --rm \
  -v "${CERTS}:/etc/letsencrypt" \
  -v "${WEBROOT}:/var/www/certbot" \
  certbot/certbot renew --webroot -w /var/www/certbot

echo "Reloading nginx..."
docker exec matrix-nginx nginx -s reload 2>/dev/null || true

echo "Restarting coturn/synapse (they load certs at startup)..."
cd "$PROJECT_DIR"
docker compose restart coturn synapse 2>/dev/null || docker-compose restart coturn synapse 2>/dev/null || true

echo "✓ Renew complete."
