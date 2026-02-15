#!/usr/bin/env bash
set -euo pipefail
# Usage: ./scripts/deactivate-user.sh <username> <admin-token>
source "$(dirname "$0")/load-env.sh"

USERNAME="${1:?Usage: $0 <username> <admin-token>}"
TOKEN="${2:?Usage: $0 <username> <admin-token>}"
USER_ID="@${USERNAME}:${SERVER_NAME}"

echo "Deactivating ${USER_ID}..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"erase": false}' \
  "http://localhost:8008/_synapse/admin/v1/deactivate/${USER_ID}")

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ User ${USER_ID} deactivated."
else
  echo "✗ Failed (HTTP ${HTTP_CODE}). Verify your admin token and username."
fi
