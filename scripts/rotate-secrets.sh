#!/usr/bin/env bash
set -euo pipefail
# Rotate the TURN secret and Jitsi passwords.
# ⚠ Do NOT rotate SYNAPSE secrets — they invalidate all user sessions.
# Usage: ./scripts/rotate-secrets.sh

source "$(dirname "$0")/load-env.sh"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

gen_secret() { openssl rand -base64 48 | tr -d '/+=\n' | head -c 48; }
gen_pass()   { openssl rand -base64 32 | tr -d '/+=\n' | head -c 32; }

echo "⚠ This will rotate: TURN_SECRET, JICOFO_AUTH_PASSWORD, JVB_AUTH_PASSWORD"
echo "  Synapse secrets are NOT touched (would invalidate all sessions)."
echo ""
read -r -p "Continue? [yes/no]: " CONFIRM
[[ "$CONFIRM" != "yes" && "$CONFIRM" != "y" ]] && { echo "Aborted."; exit 0; }

NEW_TURN="$(gen_secret)"
NEW_JICOFO="$(gen_pass)"
NEW_JVB="$(gen_pass)"

# Update .env
sed -i "s|^TURN_SECRET=.*|TURN_SECRET=\"${NEW_TURN}\"|" "$ENV_FILE"
sed -i "s|^JICOFO_AUTH_PASSWORD=.*|JICOFO_AUTH_PASSWORD=\"${NEW_JICOFO}\"|" "$ENV_FILE"
sed -i "s|^JVB_AUTH_PASSWORD=.*|JVB_AUTH_PASSWORD=\"${NEW_JVB}\"|" "$ENV_FILE"

echo "✓ .env updated with new secrets."
echo ""
echo "Re-run setup.sh to regenerate all config files with the new secrets:"
echo "  sudo bash setup.sh --domain ${SERVER_NAME}"
echo ""
echo "Then restart the stack:"
echo "  docker compose down && docker compose up -d"
