#!/usr/bin/env bash
set -euo pipefail
# Enable or disable open user registration in Synapse.
# Usage: ./scripts/toggle-registration.sh on|off

source "$(dirname "$0")/load-env.sh"

ACTION="${1:-}"
[[ "$ACTION" != "on" && "$ACTION" != "off" ]] && { echo "Usage: $0 on|off"; exit 1; }

HOMESERVER="${DATA_DIR}/synapse/appdata/homeserver.yaml"
[[ ! -f "$HOMESERVER" ]] && { echo "ERROR: homeserver.yaml not found at ${HOMESERVER}"; exit 1; }

if [[ "$ACTION" == "on" ]]; then
  sed -i 's/^enable_registration: .*/enable_registration: true/' "$HOMESERVER"
  echo "✓ Registration ENABLED — restart Synapse to apply:"
  echo "  docker restart matrix-synapse"
  echo "  ⚠ Anyone can now create an account. Disable again when done."
else
  sed -i 's/^enable_registration: .*/enable_registration: false/' "$HOMESERVER"
  echo "✓ Registration DISABLED — restart Synapse to apply:"
  echo "  docker restart matrix-synapse"
fi
