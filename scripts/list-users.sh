#!/usr/bin/env bash
set -euo pipefail
# Lists all registered users (requires admin token)
# Usage: ./scripts/list-users.sh <admin-token>
source "$(dirname "$0")/../.env"

TOKEN="${1:?Usage: $0 <admin-access-token>}"

curl -s -H "Authorization: Bearer ${TOKEN}" \
  "http://localhost:8008/_synapse/admin/v2/users?limit=100" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for u in data.get('users', []):
    admin = '(admin)' if u.get('admin') else ''
    print(f\"  {u['name']} {admin}\")
"
