#!/usr/bin/env bash
set -euo pipefail
# Usage: ./scripts/deactivate-user.sh <username> <admin-token>
source "$(dirname "$0")/../.env"

USERNAME="${1:?Usage: $0 <username> <admin-token>}"
TOKEN="${2:?Usage: $0 <username> <admin-token>}"
USER_ID="@${USERNAME}:${SERVER_NAME}"

echo "Deactivating ${USER_ID}..."
curl -s -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"erase": false}' \
  "http://localhost:8008/_synapse/admin/v1/deactivate/${USER_ID}"
echo ""
echo "✓ User deactivated."
