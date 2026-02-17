#!/usr/bin/env bash
set -euo pipefail
# Create a new Matrix user
# Usage: ./scripts/create-user.sh <username> [--admin]
source "$(dirname "$0")/load-env.sh"

USERNAME="${1:?Usage: $0 <username> [--admin]}"
ADMIN_FLAG=""

if [ "${2:-}" = "--admin" ]; then
  ADMIN_FLAG="--admin"
  echo "Creating ADMIN user: @${USERNAME}:${SERVER_NAME}"
else
  echo "Creating user: @${USERNAME}:${SERVER_NAME}"
fi

read -s -p "Password: " PASSWORD
echo ""
read -s -p "Confirm:  " PASSWORD2
echo ""

if [ "$PASSWORD" != "$PASSWORD2" ]; then
  echo "ERROR: Passwords do not match."
  exit 1
fi

if [ ${#PASSWORD} -lt 10 ]; then
  echo "ERROR: Password must be at least 10 characters (Synapse policy)."
  exit 1
fi

docker exec -i matrix-synapse register_new_matrix_user \
  -u "$USERNAME" \
  -p "$PASSWORD" \
  -c /data/homeserver.yaml \
  $ADMIN_FLAG \
  http://localhost:8008

echo ""
echo "✓ @${USERNAME}:${SERVER_NAME} created."
[ -n "$ADMIN_FLAG" ] && echo "  This user has server admin privileges."
