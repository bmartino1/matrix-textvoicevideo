#!/usr/bin/env bash
set -euo pipefail
#
# Obtain/renew initial Let's Encrypt certs using webroot.
#
# Usage:
#   ./scripts/certbot-init.sh
#
# Requires:
#   - DNS A records for SERVER_NAME and meet.SERVER_NAME -> EXTERNAL_IP
#   - Router forwards WAN:80 -> host:60080 (nginx http)
#   - nginx serves /.well-known/acme-challenge from DATA_DIR/nginx/html
#
source "$(dirname "$0")/load-env.sh"

if [ "${NO_TLS:-false}" = "true" ]; then
  echo "NO_TLS=true — certbot not applicable."
  exit 0
fi

MEET="meet.${SERVER_NAME}"
WEBROOT="${DATA_DIR}/nginx/html"
CERTS="${DATA_DIR}/nginx/certs"

: "${ADMIN_EMAIL:?Missing ADMIN_EMAIL in .env}"

mkdir -p "${WEBROOT}/.well-known/acme-challenge" "${CERTS}"
chmod -R 777 "${WEBROOT}" "${CERTS}" || true

echo "Requesting certs for:"
echo "  - ${SERVER_NAME}"
echo "  - ${MEET}"
echo ""
echo "Make sure nginx is RUNNING and reachable from the internet on port 80."
echo ""

docker run --rm \
  -v "${CERTS}:/etc/letsencrypt" \
  -v "${WEBROOT}:/var/www/certbot" \
  certbot/certbot certonly \
    --webroot -w /var/www/certbot \
    -d "${SERVER_NAME}" \
    -d "${MEET}" \
    --email "${ADMIN_EMAIL}" \
    --agree-tos \
    --non-interactive

echo ""
echo "Reloading nginx and restarting coturn/synapse..."
docker exec matrix-nginx nginx -s reload 2>/dev/null || true

cd "$PROJECT_DIR"
docker compose restart coturn synapse 2>/dev/null || docker-compose restart coturn synapse 2>/dev/null || true

echo "✓ Certbot init complete."
