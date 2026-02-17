#!/usr/bin/env bash
set -euo pipefail
# Deactivate a user account (blocks login, optionally erases data)
# Usage: ./scripts/deactivate-user.sh <username> <admin-token> [--erase]
#
# --erase: also purge the user's messages and personal data from the server
source "$(dirname "$0")/load-env.sh"

USERNAME="${1:?Usage: $0 <username> <admin-token> [--erase]}"
TOKEN="${2:?Usage: $0 <username> <admin-token> [--erase]}"
ERASE=false
[ "${3:-}" = "--erase" ] && ERASE=true

USER_ID="@${USERNAME}:${SERVER_NAME}"

echo "Deactivating: ${USER_ID}"
[ "$ERASE" = "true" ] && echo "  (--erase: user data will be PERMANENTLY deleted)"
echo ""
read -p "Are you sure? (y/N): " confirm
[ "$confirm" != "y" ] && [ "$confirm" != "Y" ] && { echo "Aborted."; exit 0; }

HTTP_CODE=$(curl -s -o /tmp/matrix-deact-resp.json -w "%{http_code}" -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"erase\": ${ERASE}}" \
  "http://localhost:8008/_synapse/admin/v1/deactivate/${USER_ID}")

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ ${USER_ID} deactivated."
  [ "$ERASE" = "true" ] && echo "  User data erased from server."
else
  echo "✗ Failed (HTTP ${HTTP_CODE})."
  cat /tmp/matrix-deact-resp.json 2>/dev/null && echo ""
fi
rm -f /tmp/matrix-deact-resp.json
