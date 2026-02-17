#!/usr/bin/env bash
set -euo pipefail
#
# Deactivate a Matrix user account
#
# Usage:
#   ./scripts/deactivate-user.sh <username> <admin-token> [--erase]
#
# --erase:
#   Also permanently deletes the user's messages and personal data.
#
# Token:
#   Element Web → Settings → Help & About → Access Token
#
source "$(dirname "$0")/load-env.sh"

USERNAME="${1:?Usage: $0 <username> <admin-token> [--erase]}"
TOKEN="${2:?Usage: $0 <username> <admin-token> [--erase]}"
ERASE=false
[ "${3:-}" = "--erase" ] && ERASE=true

USER_ID="@${USERNAME}:${SERVER_NAME}"

echo "Deactivating: ${USER_ID}"
if [ "$ERASE" = "true" ]; then
  echo "  (--erase: user data will be PERMANENTLY deleted)"
fi
echo ""

if ! docker ps --format '{{.Names}}' | grep -q '^matrix-synapse$'; then
  echo "ERROR: matrix-synapse container is not running."
  echo "  Check: cd \"$PROJECT_DIR\" && docker compose ps"
  exit 1
fi

read -p "Are you sure? (y/N): " confirm
[[ "$confirm" != "y" && "$confirm" != "Y" ]] && { echo "Aborted."; exit 0; }

HTTP_CODE="$(docker exec -i matrix-synapse sh -lc "
  curl -s -o /tmp/matrix-deact-resp.json -w '%{http_code}' -X POST \
    -H 'Authorization: Bearer ${TOKEN}' \
    -H 'Content-Type: application/json' \
    -d '{\"erase\": ${ERASE}}' \
    'http://localhost:8008/_synapse/admin/v1/deactivate/${USER_ID}'
")"

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ ${USER_ID} deactivated."
  [ "$ERASE" = "true" ] && echo "  User data erased from server."
else
  echo "✗ Failed (HTTP ${HTTP_CODE})."
  echo ""
  docker exec -i matrix-synapse sh -lc "cat /tmp/matrix-deact-resp.json 2>/dev/null || true"
fi

docker exec -i matrix-synapse sh -lc "rm -f /tmp/matrix-deact-resp.json" >/dev/null 2>&1 || true
