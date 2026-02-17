#!/usr/bin/env bash
set -euo pipefail
#
# Reset a Matrix user's password via Synapse Admin API
#
# Usage:
#   ./scripts/reset-password.sh <username> <admin-access-token>
#
# Get your admin access token:
#   Element Web → Settings → Help & About → Access Token
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/load-env.sh"

USERNAME="${1:-}"
TOKEN="${2:-}"

if [ -z "$USERNAME" ] || [ -z "$TOKEN" ]; then
  echo "Usage: $0 <username> <admin-access-token>"
  exit 1
fi

USER_ID="@${USERNAME}:${SERVER_NAME}"

echo "Resetting password for: ${USER_ID}"
echo ""

# Ensure synapse container is running
if ! docker ps --format '{{.Names}}' | grep -q "^matrix-synapse$"; then
  echo "ERROR: matrix-synapse container is not running."
  echo "  Run: docker compose ps"
  exit 1
fi

# Prompt for new password
read -s -p "New password: " PASSWORD
echo ""
read -s -p "Confirm:      " PASSWORD2
echo ""

if [ "$PASSWORD" != "$PASSWORD2" ]; then
  echo "ERROR: Passwords do not match."
  exit 1
fi

if [ ${#PASSWORD} -lt 10 ]; then
  echo "ERROR: Password must be at least 10 characters."
  exit 1
fi

# Execute API call inside container
HTTP_CODE="$(docker exec -i matrix-synapse sh -lc "
  curl -s -o /tmp/matrix-reset-resp.json -w '%{http_code}' -X POST \
    -H 'Authorization: Bearer ${TOKEN}' \
    -H 'Content-Type: application/json' \
    -d '{\"new_password\":\"${PASSWORD}\",\"logout_devices\":true}' \
    'http://localhost:8008/_synapse/admin/v1/reset_password/${USER_ID}'
")"

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ Password reset for ${USER_ID}."
  echo "  All existing sessions have been logged out."
else
  echo "✗ Failed (HTTP ${HTTP_CODE})."
  echo ""

  # Show API response (if available)
  docker exec -i matrix-synapse sh -lc "cat /tmp/matrix-reset-resp.json 2>/dev/null || true"
  echo ""

  echo "Common causes:"
  echo "  • Admin token expired — log into Element Web and copy a fresh one"
  echo "  • Synapse not running — check: docker compose ps"
  echo "  • Username doesn't exist — check: ./scripts/list-users.sh <token>"
fi

# Cleanup container temp file
docker exec -i matrix-synapse sh -lc "rm -f /tmp/matrix-reset-resp.json" >/dev/null 2>&1 || true
