#!/usr/bin/env bash
set -euo pipefail
# Log in as an admin user and save the access token for use by other scripts.
# Re-running this script always overwrites the saved token (e.g. after password change).
# Usage: ./scripts/get-admin-token.sh [--manual]

source "$(dirname "$0")/load-env.sh"

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  Admin Token Setup — ${SERVER_NAME}"
echo "══════════════════════════════════════════════════════════════"
echo ""

# Manual mode — paste a token you already have from Element
if [[ "${1:-}" == "--manual" ]]; then
  echo "  Paste your admin access token"
  echo "  (Element > Settings > Help & About > Access Token):"
  read -rs -p "  Token: " TOKEN; echo ""
  [[ -z "$TOKEN" ]] && { echo "✗ No token entered. Aborted."; exit 1; }
  # Truncate and write (overwrite any existing token)
  echo "$TOKEN" > "$ADMIN_TOKEN_FILE"
  chmod 600 "$ADMIN_TOKEN_FILE"
  echo ""
  echo "✓ Token saved → scripts/admin-token.txt"
  exit 0
fi

echo "  Log in as your admin user to generate a token."
echo ""
echo "  Don't have an admin user yet?"
echo "    ./scripts/create-admin.sh <username>"
echo ""
read -r  -p "  Admin username (without @domain): " ADMIN_USER
read -rs -p "  Password: " ADMIN_PASS; echo ""
echo ""

echo "  Logging in as @${ADMIN_USER}:${SERVER_NAME}..."
echo ""

# Run curl INSIDE the Synapse container — host networking is not needed.
# Synapse listens on localhost:8008 inside the container; this always works
# regardless of whether port 8008 is exposed to the host.
RESPONSE=$(docker exec matrix-synapse \
  curl -s -X POST \
    "http://localhost:8008/_matrix/client/v3/login" \
    -H "Content-Type: application/json" \
    -d "{\"type\":\"m.login.password\",\"user\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
  2>/dev/null) || true

if [[ -z "$RESPONSE" ]]; then
  echo "✗ No response from Synapse."
  echo "  Is matrix-synapse running?  docker ps | grep synapse"
  echo "  If just started, wait 60s and retry."
  exit 1
fi

TOKEN=$(echo "$RESPONSE" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d['access_token'])" \
  2>/dev/null || true)

if [[ -z "$TOKEN" ]]; then
  ERRCODE=$(echo "$RESPONSE" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('errcode','UNKNOWN'))" \
    2>/dev/null || echo "UNKNOWN")
  ERRMSG=$(echo "$RESPONSE" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('error','Unknown error'))" \
    2>/dev/null || echo "Unknown error")
  echo "✗ Login failed: ${ERRCODE} — ${ERRMSG}"
  echo ""
  echo "  Common causes:"
  echo "   • Wrong username or password"
  echo "   • User does not have admin privileges"
  echo "   • Synapse still starting up (wait 60s and retry)"
  echo ""
  echo "  Alternatively, paste a token from Element:"
  echo "    ./scripts/get-admin-token.sh --manual"
  exit 1
fi

# Verify the user is actually an admin before saving
IS_ADMIN=$(docker exec matrix-synapse \
  curl -s \
    "http://localhost:8008/_synapse/admin/v2/users/@${ADMIN_USER}:${SERVER_NAME}" \
    -H "Authorization: Bearer ${TOKEN}" \
  2>/dev/null \
  | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(str(d.get('admin',False)).lower())" \
  2>/dev/null || echo "false")

if [[ "$IS_ADMIN" != "true" ]]; then
  echo "✗ Login succeeded but @${ADMIN_USER}:${SERVER_NAME} is not an admin."
  echo "  Create an admin: ./scripts/create-admin.sh <username>"
  exit 1
fi

# Truncate and write — always overwrites any previous token
echo "$TOKEN" > "$ADMIN_TOKEN_FILE"
chmod 600 "$ADMIN_TOKEN_FILE"

echo "✓ Logged in as @${ADMIN_USER}:${SERVER_NAME} (admin confirmed)"
echo "✓ Token saved → scripts/admin-token.txt  (previous token replaced)"
echo ""
echo "  Scripts that now work:"
echo "    ./scripts/list-users.sh"
echo "    ./scripts/reset-password.sh   <username>"
echo "    ./scripts/deactivate-user.sh  <username>"
echo "    ./scripts/delete-user.sh      <username>"
echo ""
echo "  Token preview: ${TOKEN:0:20}..."
echo ""
echo "  Re-run this script if any admin script returns a 401 error."
echo ""
