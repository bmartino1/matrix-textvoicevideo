#!/usr/bin/env bash
set -euo pipefail
# Usage: ./scripts/reset-password.sh <username> <admin-token>
source "$(dirname "$0")/load-env.sh"

USERNAME="${1:?Usage: $0 <username> <admin-token>}"
TOKEN="${2:?Usage: $0 <username> <admin-token>}"
USER_ID="@${USERNAME}:${SERVER_NAME}"

read -s -p "New password for ${USER_ID}: " PASSWORD
echo ""
read -s -p "Confirm: " PASSWORD2
echo ""
if [ "$PASSWORD" != "$PASSWORD2" ]; then echo "Passwords don't match!"; exit 1; fi

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"new_password\": \"${PASSWORD}\", \"logout_devices\": true}" \
  "http://localhost:8008/_synapse/admin/v1/reset_password/${USER_ID}")

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ Password reset for ${USER_ID}."
else
  echo "✗ Failed (HTTP ${HTTP_CODE}). Verify your admin token is valid."
  echo ""
  echo "To get an admin token, log into Element Web as an admin user,"
  echo "then go to Settings → Help & About → Access Token."
fi
