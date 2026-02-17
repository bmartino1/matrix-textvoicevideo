#!/usr/bin/env bash
set -euo pipefail
#
# Toggle Synapse open registration.
#
# Usage:
#   ./scripts/toggle-registration.sh on
#   ./scripts/toggle-registration.sh off
#
source "$(dirname "$0")/load-env.sh"

MODE="${1:?Usage: $0 on|off}"
HS="${DATA_DIR}/synapse/appdata/homeserver.yaml"

[ ! -f "$HS" ] && { echo "ERROR: homeserver.yaml not found: $HS"; exit 1; }

case "$MODE" in
  on)
    echo "Enabling open registration..."
    sed -i 's/^enable_registration: .*/enable_registration: true/' "$HS"
    sed -i 's/^enable_registration_without_verification: .*/enable_registration_without_verification: true/' "$HS"
    ;;
  off)
    echo "Disabling open registration..."
    sed -i 's/^enable_registration: .*/enable_registration: false/' "$HS"
    sed -i 's/^enable_registration_without_verification: .*/enable_registration_without_verification: false/' "$HS"
    ;;
  *)
    echo "ERROR: Mode must be on or off."
    exit 1
    ;;
esac

echo "Restarting synapse..."
cd "$PROJECT_DIR"
docker compose restart synapse 2>/dev/null || docker-compose restart synapse
echo "✓ Done."
