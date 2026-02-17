#!/usr/bin/env bash
set -euo pipefail
# List all registered Matrix users
# Usage: ./scripts/list-users.sh <admin-access-token>
source "$(dirname "$0")/load-env.sh"

TOKEN="${1:?Usage: $0 <admin-access-token>}"

RESPONSE=$(curl -sf \
  -H "Authorization: Bearer ${TOKEN}" \
  "http://localhost:8008/_synapse/admin/v2/users?limit=500&guests=false" 2>&1) || {
  echo "ERROR: Could not reach Synapse. Is the stack running?"
  echo "  Check: docker compose ps"
  exit 1
}

echo "$RESPONSE" | python3 -c "
import sys, json

try:
    data = json.load(sys.stdin)
except json.JSONDecodeError as e:
    print(f'ERROR: Could not parse server response: {e}')
    sys.exit(1)

if 'errcode' in data:
    print(f'ERROR {data[\"errcode\"]}: {data.get(\"error\", \"\")}')
    print()
    print('Your admin token may be invalid or expired.')
    print('Log into Element Web → Settings → Help & About → Access Token')
    sys.exit(1)

users = data.get('users', [])
if not users:
    print('No users found.')
    sys.exit(0)

active = [u for u in users if not u.get('deactivated')]
deact  = [u for u in users if u.get('deactivated')]

fmt = '{:<45} {:<8} {:<6}'
print(fmt.format('Username', 'Admin', 'Guest'))
print('-' * 62)
for u in sorted(active, key=lambda x: x.get('name', '')):
    name  = u.get('name', '')
    admin = 'YES' if u.get('admin') else ''
    guest = 'YES' if u.get('is_guest') else ''
    print(fmt.format(name, admin, guest))

if deact:
    print()
    print(f'Deactivated users ({len(deact)}):')
    for u in deact:
        print(f'  {u.get(\"name\", \"\")}')

print()
print(f'Total: {len(active)} active, {len(deact)} deactivated')
"
