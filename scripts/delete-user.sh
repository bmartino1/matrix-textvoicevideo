#!/usr/bin/env bash
set -euo pipefail
#
# DELETE a Matrix user (wrapper)
# This is just deactivate-user.sh --erase with louder warnings.
#
# Usage:
#   ./scripts/delete-user.sh <username> <admin-token>
#
source "$(dirname "$0")/load-env.sh"

USERNAME="${1:?Usage: $0 <username> <admin-token>}"
TOKEN="${2:?Usage: $0 <username> <admin-token>}"

echo "======================================================"
echo "  DANGER: PERMANENT USER DELETION"
echo "======================================================"
echo "This will deactivate AND ERASE ALL DATA for:"
echo "  @${USERNAME}:${SERVER_NAME}"
echo ""
echo "This cannot be undone."
echo ""

read -p "Type DELETE to continue: " confirm
[ "$confirm" != "DELETE" ] && { echo "Aborted."; exit 0; }

exec "$(dirname "$0")/deactivate-user.sh" "$USERNAME" "$TOKEN" --erase
