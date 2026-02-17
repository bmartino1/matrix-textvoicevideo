#!/usr/bin/env bash
set -euo pipefail
#
# Rotate TURN and Jitsi secrets (safe in-place rotation)
#
# Updates:
#   - .env (TURN_SECRET, JICOFO_AUTH_PASSWORD, JVB_AUTH_PASSWORD)
#   - turnserver.conf (static-auth-secret)
#   - homeserver.yaml (turn_shared_secret)
#
# Then recreates affected services so env changes apply.
#
source "$(dirname "$0")/load-env.sh"

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
echo "Updating files..."

# --- Update .env ---
sed -i "s|^TURN_SECRET=.*|TURN_SECRET=\"${NEW_TURN}\"|"                          "$PROJECT_DIR/.env"
sed -i "s|^JICOFO_AUTH_PASSWORD=.*|JICOFO_AUTH_PASSWORD=\"${NEW_JICOFO}\"|"      "$PROJECT_DIR/.env"
sed -i "s|^JVB_AUTH_PASSWORD=.*|JVB_AUTH_PASSWORD=\"${NEW_JVB}\"|"               "$PROJECT_DIR/.env"
echo "  ✓ .env"

# --- Update coturn config ---
TURN_CONF="$DATA_DIR/coturn/config/turnserver.conf"
if [ -f "$TURN_CONF" ]; then
  sed -i "s|^static-auth-secret=.*|static-auth-secret=${NEW_TURN}|" "$TURN_CONF"
  echo "  ✓ turnserver.conf"
else
  echo "  ⚠ turnserver.conf not found — skipping"
fi

# --- Update Synapse config ---
HS_FILE="$DATA_DIR/synapse/appdata/homeserver.yaml"
if [ -f "$HS_FILE" ]; then
  sed -i "s|^turn_shared_secret:.*|turn_shared_secret: \"${NEW_TURN}\"|" "$HS_FILE"
  echo "  ✓ homeserver.yaml"
else
  echo "  ⚠ homeserver.yaml not found — skipping"
fi

echo ""
echo "Recreating affected services (so new env vars apply)..."
cd "$PROJECT_DIR"

# Recreate services that consume these secrets
if docker compose version >/dev/null 2>&1; then
  docker compose up -d --force-recreate coturn jitsi-prosody jitsi-jicofo jitsi-jvb synapse
else
  docker-compose up -d --force-recreate coturn jitsi-prosody jitsi-jicofo jitsi-jvb synapse
fi

echo ""
echo "✓ Secret rotation complete."
