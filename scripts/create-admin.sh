#!/usr/bin/env bash
set -euo pipefail
#
# Shortcut: create an admin user
#
# Usage:
#   ./scripts/create-admin.sh <username>
#
exec "$(dirname "$0")/create-user.sh" "${1:?Usage: $0 <username>}" --admin
