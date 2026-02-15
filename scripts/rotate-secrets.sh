#!/usr/bin/env bash
set -euo pipefail
# Rotates TURN and LiveKit secrets (requires restart)
echo "This will rotate TURN and LiveKit secrets and restart services."
read -p "Continue? (y/N): " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then exit 0; fi

source "$(dirname "$0")/load-env.sh"

NEW_TURN="$(openssl rand -base64 48 | tr -d '/+=\n' | head -c 48)"
NEW_LK_SECRET="$(openssl rand -base64 48 | tr -d '/+=\n' | head -c 48)"

# Update .env (handles quoted values)
sed -i "s|^TURN_SECRET=.*|TURN_SECRET=\"${NEW_TURN}\"|" "$PROJECT_DIR/.env"
sed -i "s|^LIVEKIT_API_SECRET=.*|LIVEKIT_API_SECRET=\"${NEW_LK_SECRET}\"|" "$PROJECT_DIR/.env"

echo "✓ Secrets rotated in .env."
echo ""
echo "IMPORTANT: You must regenerate configs and restart:"
echo "  1. Re-run:  sudo ./setup.sh --domain ${SERVER_NAME}"
echo "  2. Then:    docker compose down && docker compose up -d"
