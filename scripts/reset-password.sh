#!/usr/bin/env bash
set -uo pipefail
# Reset a user's password and log out all their sessions.
# Usage: ./scripts/reset-password.sh <username>

source "$(dirname "$0")/load-token.sh"

USERNAME="${1:?Usage: $0 <username>}"
MXID="@${USERNAME}:${SERVER_NAME}"

echo ""
echo "Resetting password for: ${MXID}"
echo ""

while true; do
  read -rs -p "New password (min 10 chars): " NEW_PASS; echo ""
  read -rs -p "Confirm:                     " CONFIRM_PW; echo ""
  if [[ "$NEW_PASS" == "$CONFIRM_PW" && ${#NEW_PASS} -ge 10 ]]; then
    break
  fi
  echo "Passwords don't match or too short. Try again."
done

RESPONSE=$(docker exec matrix-synapse \
  curl -s -X POST \
    "http://localhost:8008/_synapse/admin/v1/reset_password/${MXID}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"new_password\": \"${NEW_PASS}\", \"logout_devices\": true}" \
  2>&1) || { echo "✗ Failed to reach Synapse via docker exec."; exit 1; }

if echo "$RESPONSE" | grep -q "{}"; then
  echo "✓ Password reset for ${MXID} — all sessions logged out."
else
  ERRMSG=$(echo "$RESPONSE" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('error', str(d)))" \
    2>/dev/null || echo "$RESPONSE")
  echo "✗ Failed: ${ERRMSG}"
  echo "  Re-run: ./scripts/get-admin-token.sh"
  exit 1
fi
