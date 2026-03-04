#!/usr/bin/env bash
set -euo pipefail
# Obtain a real Let's Encrypt certificate (standalone mode).
# Run this AFTER the stack is up and DNS + port-forward are confirmed.
#
# Prerequisites:
#   - DNS A records pointing to your WAN IP:
#       YOUR_DOMAIN      → WAN IP
#       meet.YOUR_DOMAIN → WAN IP
#   - Router NAT: WAN:80 → Unraid:60080
#   - Router NAT: WAN:443 → Unraid:60443
#
# NOTE: turn.YOUR_DOMAIN is optional. Free DDNS services (no-ip, duckdns, etc.)
#       often do NOT support sub-subdomains like turn.yourdomain.ddns.net.
#       If you only have a top-level DDNS hostname, omit turn.DOMAIN from the cert.
#       Coturn will still work via SNI passthrough on port 443 using the main cert.
#
# What this script does:
#   1. Stops matrix-nginx by container name (docker stop matrix-nginx)
#   2. Runs certbot standalone on port 60080 (mapped from WAN:80)
#   3. Fixes cert permissions so coturn can read them
#   4. Starts matrix-nginx again (docker start matrix-nginx)
#
# Usage:
#   ./scripts/certbot-init.sh
#   ./scripts/certbot-init.sh --domains "chat.example.com meet.chat.example.com turn.chat.example.com"

source "$(dirname "$0")/load-env.sh"

# Default: main domain + meet. only (turn. excluded for DDNS compatibility)
DEFAULT_DOMAINS="-d ${SERVER_NAME} -d ${JITSI_DOMAIN}"

# Build domain flags
if [[ "${1:-}" == "--domains" ]]; then
  RAW="${2:-}"
  [[ -z "$RAW" ]] && { echo "Usage: $0 --domains \"d1.example.com d2.example.com\""; exit 1; }
  DOMAINS=""
  for D in $RAW; do DOMAINS="$DOMAINS -d $D"; done
else
  DOMAINS="$DEFAULT_DOMAINS"
fi

echo "═══════════════════════════════════════════════════════════════"
echo "  Certbot — Let's Encrypt Certificate Issuance"
echo "  Domain:      ${SERVER_NAME}"
echo "  Meet domain: ${JITSI_DOMAIN}"
echo "  Email:       ${ADMIN_EMAIL}"
echo ""
echo "  NOTE: turn.${SERVER_NAME} is NOT included by default."
echo "  Free DDNS services usually don't support sub-subdomains."
echo "  Coturn works fine using the main cert via nginx SNI passthrough."
echo "  To include it: $0 --domains \"${SERVER_NAME} ${JITSI_DOMAIN} turn.${SERVER_NAME}\""
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  This will:"
echo "   1. Stop matrix-nginx briefly (docker stop matrix-nginx)"
echo "   2. Run certbot on port 60080 (WAN:80 → Unraid:60080)"
echo "   3. Fix cert permissions for coturn"
echo "   4. Start matrix-nginx again (docker start matrix-nginx)"
echo ""
echo "  NOTE for Unraid users: if certbot fails to bind port 60080,"
echo "  manually stop matrix-nginx in the Unraid Docker UI first,"
echo "  then re-run this script."
echo ""
read -r -p "  Continue? [yes/no]: " CONFIRM
[[ "$CONFIRM" != "yes" && "$CONFIRM" != "y" ]] && { echo "Aborted."; exit 0; }
echo ""

echo "Stopping matrix-nginx..."
docker stop matrix-nginx 2>/dev/null \
  && echo "  Stopped." \
  || echo "  matrix-nginx was not running — continuing."
sleep 2

echo ""
echo "Running certbot (standalone)..."
# shellcheck disable=SC2086
docker run --rm \
  -v "${DATA_DIR}/nginx/certs:/etc/letsencrypt" \
  -v "${DATA_DIR}/nginx/html:/var/www/certbot" \
  -p "60080:80" \
  certbot/certbot certonly \
    --standalone \
    --http-01-port 80 \
    --preferred-challenges http \
    $DOMAINS \
    -m "${ADMIN_EMAIL}" \
    --agree-tos \
    --non-interactive

echo ""
echo "Fixing cert permissions for coturn..."
chmod -R 750 "${DATA_DIR}/nginx/certs/live/"    2>/dev/null || true
chmod -R 750 "${DATA_DIR}/nginx/certs/archive/" 2>/dev/null || true
find "${DATA_DIR}/nginx/certs/archive/" -name "*.pem" -exec chmod 640 {} \; 2>/dev/null || true
echo "  Done."

echo ""
echo "Starting matrix-nginx..."
docker start matrix-nginx 2>/dev/null \
  && echo "  Started." \
  || echo "  Warning: could not start matrix-nginx — start it manually in Unraid Docker UI."
sleep 3

echo ""
echo "✓ Certificate obtained, permissions fixed, nginx restarted."
echo ""
echo "  Verify TLS at: https://${SERVER_NAME}"
echo "  Run again to renew, or use: ./scripts/certbot-renew.sh"
echo "  After getting a real cert, run: ./scripts/status.sh"
echo ""
