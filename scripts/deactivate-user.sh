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
# Get your admin access token:
#   Element Web → Settings → Help & About → Access Token
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/load-env.sh"

USERNAME="${1:-}"
TOKEN="${2:-}"
ERASE=false

if [ -z "$USERNAME" ] || [ -z "$TOKEN" ]; then
  echo "Usage: $0 <username> <admin-token> [--erase]"
  exit 1
fi

[ "${3:-}" = "--erase" ] && ERASE=true

USER_ID="@${USERNAME}:${SERVER_NAME}"

echo "Deactivating: ${USER_ID}"
if [ "$ERASE" = "true" ]; then
  echo "  (--erase: user data will be PERMANENTLY deleted)"
fi
echo ""

# Ensure synapse container is running
if ! docker ps --format '{{.Names}}' | grep -q "^matrix-synapse$"; then
  echo "ERROR: matrix-synapse container is not running."
  echo "  Run: docker compose ps"
  exit 1
fi

read -p "Are you sure? (y/N): " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
  echo "Aborted."
  exit 0
fi

# Execute API call inside container
HTTP_CODE="$(docker exec -i matrix-synapse sh -lc "
  curl -s -o /tmp/matrix-deact-resp.json -w '%{http_code}' -X POST \
    -H 'Authorization: Bearer ${TOKEN}' \
    -H 'Content-Type: application/json' \
    -d '{\"erase\": ${ERASE}}' \
    'http://localhost:8008/_synapse/admin/v1/deactivate/${USER_ID}'
")"

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ ${USER_ID} deactivated."
  if [ "$ERASE" = "true" ]; then
    echo "  User data erased from server."
  fi
else
  echo "✗ Failed (HTTP ${HTTP_CODE})."
  echo ""

  # Show API response (if available)
  docker exec -i matrix-synapse sh -lc "cat /tmp/matrix-deact-resp.json 2>/dev/null || true"
  echo ""

  echo "Common causes:"
  echo "  • Admin token expired — log into Element Web and copy a fresh one"
  echo "  • Username doesn't exist — check: ./scripts/list-users.sh <token>"
  echo "  • Synapse not running — check: docker compose ps"
fi

# Cleanup container temp file
docker exec -i matrix-synapse sh -lc "rm -f /tmp/matrix-deact-resp.json" >/dev/null 2>&1 || true
