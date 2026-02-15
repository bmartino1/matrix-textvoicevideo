#!/usr/bin/env bash
set -euo pipefail
# Lists all registered users (requires admin token)
# Usage: ./scripts/list-users.sh <admin-token>
source "$(dirname "$0")/load-env.sh"

TOKEN="${1:?Usage: $0 <admin-access-token>}"

curl -s -H "Authorization: Bearer ${TOKEN}" \
  "http://localhost:8008/_synapse/admin/v2/users?limit=100" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
users = data.get('users', [])
if not users:
    print('  No users found (or invalid token).')
else:
    for u in users:
        admin = '(admin)' if u.get('admin') else ''
        print(f\"  {u['name']} {admin}\")
    print(f\"\n  Total: {len(users)} users\")
"
