#!/usr/bin/env bash
set -euo pipefail
# Reset a user's password via Synapse Admin API
# Usage: ./scripts/reset-password.sh <username> <admin-access-token>
#
# Get your admin access token:
#   Log into Element Web → Settings → Help & About → Access Token
source "$(dirname "$0")/load-env.sh"

USERNAME="${1:?Usage: $0 <username> <admin-access-token>}"
TOKEN="${2:?Usage: $0 <username> <admin-access-token>}"
USER_ID="@${USERNAME}:${SERVER_NAME}"

echo "Resetting password for: ${USER_ID}"
echo ""

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

HTTP_CODE=$(curl -s -o /tmp/matrix-reset-resp.json -w "%{http_code}" -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"new_password\": \"${PASSWORD}\", \"logout_devices\": true}" \
  "http://localhost:8008/_synapse/admin/v1/reset_password/${USER_ID}")

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ Password reset for ${USER_ID}."
  echo "  All existing sessions have been logged out."
else
  echo "✗ Failed (HTTP ${HTTP_CODE})."
  cat /tmp/matrix-reset-resp.json 2>/dev/null && echo ""
  echo ""
  echo "Common causes:"
  echo "  • Admin token expired — log into Element Web and copy a fresh one"
  echo "  • Synapse not running — check: docker compose ps"
  echo "  • Username doesn't exist — check: ./scripts/list-users.sh <token>"
fi
rm -f /tmp/matrix-reset-resp.json
