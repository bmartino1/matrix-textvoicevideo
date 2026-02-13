#!/usr/bin/env bash
set -euo pipefail
# Usage: ./scripts/reset-password.sh <username>
source "$(dirname "$0")/../.env"

USERNAME="${1:?Usage: $0 <username>}"
USER_ID="@${USERNAME}:${SERVER_NAME}"

read -s -p "New password for ${USER_ID}: " PASSWORD
echo ""
read -s -p "Confirm: " PASSWORD2
echo ""
if [ "$PASSWORD" != "$PASSWORD2" ]; then echo "Passwords don't match!"; exit 1; fi

# Get an admin access token via shared secret
NONCE=$(curl -s http://localhost:8008/_synapse/admin/v1/register | python3 -c "import sys,json; print(json.load(sys.stdin)['nonce'])")

# Use the admin API
docker exec matrix-synapse python3 -c "
import hmac, hashlib, json, urllib.request

nonce = '${NONCE}'
shared_secret = '${SYNAPSE_REGISTRATION_SECRET}'

# Reset via hash_password and admin API
pw_hash = hmac.new(shared_secret.encode(), '${PASSWORD}'.encode(), hashlib.sha256).hexdigest()
data = json.dumps({'new_password': '${PASSWORD}', 'logout_devices': True}).encode()
req = urllib.request.Request(
    'http://localhost:8008/_synapse/admin/v1/reset_password/${USER_ID}',
    data=data,
    headers={'Content-Type': 'application/json'},
    method='POST'
)
# This requires an admin token; generate one first
print('Note: Password reset requires an admin access token.')
print('Use Element Web to log in as admin, get token from Settings > Help > Access Token')
" 2>/dev/null || true

echo ""
echo "To reset a password, log into Element Web as an admin user."
echo "Then use Settings → Help & About → Access Token to get a token."
echo "Then run:"
echo "  curl -X POST -d '{\"new_password\": \"NEW_PASS\", \"logout_devices\": true}' \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -H 'Authorization: Bearer YOUR_TOKEN' \\"
echo "    http://localhost:8008/_synapse/admin/v1/reset_password/${USER_ID}"
