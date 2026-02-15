#!/usr/bin/env bash
set -euo pipefail
# Usage: ./scripts/create-user.sh <username> [--admin]
source "$(dirname "$0")/load-env.sh"

USERNAME="${1:?Usage: $0 <username> [--admin]}"
ADMIN_FLAG=""
if [ "${2:-}" = "--admin" ]; then ADMIN_FLAG="--admin"; fi

read -s -p "Password for @${USERNAME}:${SERVER_NAME}: " PASSWORD
echo ""
read -s -p "Confirm password: " PASSWORD2
echo ""
if [ "$PASSWORD" != "$PASSWORD2" ]; then echo "Passwords don't match!"; exit 1; fi

docker exec -it matrix-synapse register_new_matrix_user \
  -u "$USERNAME" \
  -p "$PASSWORD" \
  -c /data/homeserver.yaml \
  $ADMIN_FLAG \
  http://localhost:8008

echo ""
echo "✓ User @${USERNAME}:${SERVER_NAME} created."
