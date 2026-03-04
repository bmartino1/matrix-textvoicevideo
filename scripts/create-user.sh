#!/usr/bin/env bash
set -euo pipefail
# Create a Matrix user on this homeserver.
# Usage: ./scripts/create-user.sh <username> [--admin]

source "$(dirname "$0")/load-env.sh"

USERNAME="${1:-}"
IS_ADMIN=false
[[ "${2:-}" == "--admin" ]] && IS_ADMIN=true

[[ -z "$USERNAME" ]] && { echo "Usage: $0 <username> [--admin]"; exit 1; }

MXID="@${USERNAME}:${SERVER_NAME}"

if [[ "$IS_ADMIN" == true ]]; then
  echo "Creating ADMIN user: ${MXID}"
else
  echo "Creating user: ${MXID}"
fi
echo ""

# Read password
while true; do
  read -rs -p "Password (min 10 chars): " PASSWORD; echo ""
  read -rs -p "Confirm:               " CONFIRM; echo ""
  [[ "$PASSWORD" == "$CONFIRM" && ${#PASSWORD} -ge 10 ]] && break
  echo "Passwords don't match or too short. Try again."
done

if [[ "$IS_ADMIN" != true ]]; then
  read -r -p "Make admin [no]: " MAKE_ADMIN
  [[ "$MAKE_ADMIN" == "yes" || "$MAKE_ADMIN" == "y" ]] && IS_ADMIN=true
fi

echo "Sending registration request..."

RESPONSE=$(docker exec matrix-synapse register_new_matrix_user \
  -c /data/homeserver.yaml \
  -u "$USERNAME" \
  -p "$PASSWORD" \
  $( [[ "$IS_ADMIN" == true ]] && echo "-a" || echo "--no-admin" ) \
  http://localhost:8008 2>&1) || true

if echo "$RESPONSE" | grep -qi "success\|registered\|already"; then
  echo "Success!"
  echo ""
  echo "✓ Created: ${MXID}"
  [[ "$IS_ADMIN" == true ]] && echo "  (admin=true)"
elif echo "$RESPONSE" | grep -qi "already in use\|already exists"; then
  echo "✗ Username '${USERNAME}' already exists."
  exit 1
else
  echo "✗ Registration failed: ${RESPONSE}"
  exit 1
fi
