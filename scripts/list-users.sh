#!/usr/bin/env bash
set -uo pipefail
# List all users on this homeserver.
# Usage: ./scripts/list-users.sh [--limit N]

source "$(dirname "$0")/load-token.sh"

LIMIT="100"
[[ "${1:-}" == "--limit" ]] && LIMIT="${2:-100}"

echo ""
echo "Users on ${SERVER_NAME}:"
echo ""

RESPONSE=$(docker exec matrix-synapse \
  curl -s "http://localhost:8008/_synapse/admin/v2/users?from=0&limit=${LIMIT}&guests=false" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  2>&1) || { echo "✗ Failed to reach Synapse via docker exec. Is matrix-synapse running?"; exit 1; }

if [[ -z "$RESPONSE" ]]; then
  echo "✗ Empty response from Synapse."
  exit 1
fi

python3 << PYEOF
import json, sys

raw = """${RESPONSE}"""
try:
    data = json.loads(raw)
except Exception as e:
    print("ERROR parsing response:", e)
    print("Raw response:", raw[:400])
    sys.exit(1)

if "error" in data:
    print("ERROR:", data.get("errcode", ""), "-", data["error"])
    print("  Re-run: ./scripts/get-admin-token.sh")
    sys.exit(1)

if "users" not in data:
    print("ERROR: Unexpected response:", str(data)[:400])
    sys.exit(1)

users = data["users"]
if not users:
    print("No users found.")
    sys.exit(0)

fmt = "{:<40} {:<8} {:<12}"
print(fmt.format("User ID", "Admin", "Status"))
print("-" * 62)
for u in users:
    status = "deactivated" if u.get("deactivated") else "active"
    print(fmt.format(u["name"], str(u.get("admin", False)), status))

total = data.get("total", len(users))
print(f"\nShowing {len(users)} of {total} user(s)")
PYEOF
