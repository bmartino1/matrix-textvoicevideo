#!/usr/bin/env bash
set -euo pipefail
#
# Rotate TURN and Jitsi secrets (safe in-place rotation)
#
# This will:
#   • Generate new TURN_SECRET
#   • Generate new JICOFO_AUTH_PASSWORD
#   • Generate new JVB_AUTH_PASSWORD
#   • Update .env
#   • Update turnserver.conf
#   • Update homeserver.yaml
#   • Recreate coturn + jitsi + synapse containers
#
# Active voice/video calls WILL disconnect.
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/load-env.sh"

echo "======================================================"
echo " Secret Rotation — matrix-textvoicevideo"
echo "======================================================"
echo ""
echo "This will rotate TURN + Jitsi authentication secrets."
echo "Active voice/video calls will be DISCONNECTED."
echo ""
read -p "Continue? (y/N): " confirm
[[ "$confirm" != "y" && "$confirm" != "Y" ]] && { echo "Aborted."; exit 0; }

gen_secret()   { openssl rand -base64 48 | tr -d '/+=\n' | head -c 48; }
gen_password() { openssl rand -base64 32 | tr -d '/+=\n' | head -c 32; }

NEW_TURN="$(gen_secret)"
NEW_JICOFO="$(gen_password)"
NEW_JVB="$(gen_password)"

echo ""
echo "Generating new secrets..."

# --- Update .env ---
echo "Updating .env ..."
sed -i "s|^TURN_SECRET=.*|TURN_SECRET=\"${NEW_TURN}\"|"                     "$PROJECT_DIR/.env"
sed -i "s|^JICOFO_AUTH_PASSWORD=.*|JICOFO_AUTH_PASSWORD=\"${NEW_JICOFO}\"|" "$PROJECT_DIR/.env"
sed -i "s|^JVB_AUTH_PASSWORD=.*|JVB_AUTH_PASSWORD=\"${NEW_JVB}\"|"          "$PROJECT_DIR/.env"

echo "  ✓ .env updated"

# --- Update coturn config ---
TURN_CONF="$DATA_DIR/coturn/config/turnserver.conf"
if [ -f "$TURN_CONF" ]; then
  sed -i "s|^static-auth-secret=.*|static-auth-secret=${NEW_TURN}|" "$TURN_CONF"
  echo "  ✓ turnserver.conf updated"
else
  echo "  ⚠ turnserver.conf not found — skipping"
fi

# --- Update Synapse config ---
HS_FILE="$DATA_DIR/synapse/appdata/homeserver.yaml"
if [ -f "$HS_FILE" ]; then
  sed -i "s|^turn_shared_secret:.*|turn_shared_secret: \"${NEW_TURN}\"|" "$HS_FILE"
  echo "  ✓ homeserver.yaml updated"
else
  echo "  ⚠ homeserver.yaml not found — skipping"
fi

echo ""
echo "Recreating affected containers..."

cd "$PROJECT_DIR"

# Recreate (not just restart) so new env vars are applied
if docker compose version >/dev/null 2>&1; then
  docker compose up -d --force-recreate coturn jitsi-prosody jitsi-jicofo jitsi-jvb synapse
else
  docker-compose up -d --force-recreate coturn jitsi-prosody jitsi-jicofo jitsi-jvb synapse
fi

echo ""
echo "✓ Secret rotation complete."
echo ""
echo "New TURN_SECRET:"
echo "  ${NEW_TURN}"
echo ""
echo "IMPORTANT:"
echo "  If you have external integrations relying on TURN or Jitsi auth,"
echo "  ensure they reload configuration."
