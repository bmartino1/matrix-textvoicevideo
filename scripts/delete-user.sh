#!/usr/bin/env bash
set -uo pipefail
# Permanently delete a user. User MUST be deactivated first.
# Usage: ./scripts/delete-user.sh <username>

source "$(dirname "$0")/load-token.sh"

USERNAME="${1:?Usage: $0 <username>}"
MXID="@${USERNAME}:${SERVER_NAME}"

echo ""
echo "  Permanently delete ${MXID}?"
echo "  This is IRREVERSIBLE. User must already be deactivated."
echo "  If not deactivated: ./scripts/deactivate-user.sh ${USERNAME}"
echo ""
read -r -p "  Type YES to confirm permanent deletion: " CONFIRM
if [[ "$CONFIRM" != "YES" ]]; then
  echo "Aborted."
  exit 0
fi

RESPONSE=$(docker exec matrix-synapse \
  curl -s -X DELETE \
    "http://localhost:8008/_synapse/admin/v1/users/${MXID}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
  2>&1) || { echo "✗ Failed to reach Synapse via docker exec."; exit 1; }

if echo "$RESPONSE" | grep -q "{}"; then
  echo "✓ Deleted: ${MXID}"
else
  ERRMSG=$(echo "$RESPONSE" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('error', str(d)))" \
    2>/dev/null || echo "$RESPONSE")
  echo "✗ Failed: ${ERRMSG}"
  echo "  Is the user deactivated? Run: ./scripts/deactivate-user.sh ${USERNAME} first."
  exit 1
fi
