#!/usr/bin/env bash
set -euo pipefail
# Rotates TURN and LiveKit secrets (requires restart)
echo "This will rotate TURN and LiveKit secrets and restart services."
read -p "Continue? (y/N): " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then exit 0; fi

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$PROJECT_DIR/.env"

NEW_TURN="$(openssl rand -base64 48 | tr -d '/+=\n' | head -c 48)"
NEW_LK_SECRET="$(openssl rand -base64 48 | tr -d '/+=\n' | head -c 48)"

# Update .env
sed -i "s/^TURN_SECRET=.*/TURN_SECRET=${NEW_TURN}/" "$PROJECT_DIR/.env"
sed -i "s/^LIVEKIT_API_SECRET=.*/LIVEKIT_API_SECRET=${NEW_LK_SECRET}/" "$PROJECT_DIR/.env"

# Re-run setup to regenerate configs
echo "Secrets rotated in .env. Run setup.sh again to regenerate configs, then restart:"
echo "  docker compose down && docker compose up -d"
