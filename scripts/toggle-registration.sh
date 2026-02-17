#!/usr/bin/env bash
set -euo pipefail
# Toggle Synapse open registration.
# Usage:
#   ./scripts/toggle-registration.sh on
#   ./scripts/toggle-registration.sh off
source "$(dirname "$0")/load-env.sh"

MODE="${1:?Usage: $0 on|off}"
HS="$DATA_DIR/synapse/appdata/homeserver.yaml"

[ ! -f "$HS" ] && { echo "ERROR: homeserver.yaml not found: $HS"; exit 1; }

if [ "$MODE" = "on" ]; then
  echo "Enabling open registration..."
  sed -i 's/^enable_registration: .*/enable_registration: true/' "$HS" || true
  sed -i 's/^enable_registration_without_verification: .*/enable_registration_without_verification: true/' "$HS" || true
elif [ "$MODE" = "off" ]; then
  echo "Disabling open registration..."
  sed -i 's/^enable_registration: .*/enable_registration: false/' "$HS" || true
  sed -i 's/^enable_registration_without_verification: .*/enable_registration_without_verification: false/' "$HS" || true
else
  echo "ERROR: Mode must be on or off."
  exit 1
fi

echo "Restarting synapse..."
docker compose restart synapse 2>/dev/null || docker-compose restart synapse
echo "✓ Done."
