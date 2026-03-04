#!/usr/bin/env bash
set -uo pipefail
# Deactivate a user (disables login; data preserved).
# Usage: ./scripts/deactivate-user.sh <username>

source "$(dirname "$0")/load-token.sh"

USERNAME="${1:?Usage: $0 <username>}"
MXID="@${USERNAME}:${SERVER_NAME}"

echo ""
echo "Deactivating: ${MXID}"
echo "(This disables login. Data is preserved. Use delete-user.sh to remove entirely.)"
echo ""
read -r -p "  Erase user's messages from all rooms too? [no]: " ERASE
if [[ "$ERASE" == "yes" || "$ERASE" == "y" ]]; then
  ERASE_BOOL=true
else
  ERASE_BOOL=false
fi

read -r -p "  Confirm deactivate ${MXID}? [yes/no]: " CONFIRM2
if [[ "$CONFIRM2" != "yes" && "$CONFIRM2" != "y" ]]; then
  echo "Aborted."
  exit 0
fi

RESPONSE=$(docker exec matrix-synapse \
  curl -s -X POST \
    "http://localhost:8008/_synapse/admin/v1/deactivate/${MXID}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"erase\": ${ERASE_BOOL}}" \
  2>&1) || { echo "✗ Failed to reach Synapse via docker exec."; exit 1; }

if echo "$RESPONSE" | grep -q "id_server_unbind_result"; then
  echo "✓ Deactivated: ${MXID}"
  echo "  User can no longer log in."
else
  ERRMSG=$(echo "$RESPONSE" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('error', str(d)))" \
    2>/dev/null || echo "$RESPONSE")
  echo "✗ Failed: ${ERRMSG}"
  exit 1
fi
