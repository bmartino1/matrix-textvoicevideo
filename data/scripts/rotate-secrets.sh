#!/usr/bin/env bash
set -euo pipefail
# Rotate TURN and Jitsi secrets in-place (no full reinstall needed)
# WARNING: Restarts coturn and jitsi services; active calls will drop.
source "$(dirname "$0")/load-env.sh"

echo "======================================================"
echo " Secret Rotation — matrix-textvoicevideo"
echo "======================================================"
echo ""
echo "This will:"
echo "  • Generate new TURN_SECRET"
echo "  • Generate new JICOFO_AUTH_PASSWORD + JVB_AUTH_PASSWORD"
echo "  • Update .env, turnserver.conf, homeserver.yaml"
echo "  • Restart coturn and jitsi containers"
echo ""
echo "Active voice/video calls will be DISCONNECTED."
echo ""
read -p "Continue? (y/N): " confirm
[ "$confirm" != "y" ] && [ "$confirm" != "Y" ] && { echo "Aborted."; exit 0; }

gen_secret()   { openssl rand -base64 48 | tr -d '/+=\n' | head -c 48; }
gen_password() { openssl rand -base64 32 | tr -d '/+=\n' | head -c 32; }

NEW_TURN="$(gen_secret)"
NEW_JICOFO="$(gen_password)"
NEW_JVB="$(gen_password)"

echo ""
echo "Rotating secrets..."

# Update .env
sed -i "s|^TURN_SECRET=.*|TURN_SECRET=\"${NEW_TURN}\"|"                          "$PROJECT_DIR/.env"
sed -i "s|^JICOFO_AUTH_PASSWORD=.*|JICOFO_AUTH_PASSWORD=\"${NEW_JICOFO}\"|"      "$PROJECT_DIR/.env"
sed -i "s|^JVB_AUTH_PASSWORD=.*|JVB_AUTH_PASSWORD=\"${NEW_JVB}\"|"               "$PROJECT_DIR/.env"

# Update coturn config
if [ -f "$DATA_DIR/coturn/config/turnserver.conf" ]; then
  sed -i "s|^static-auth-secret=.*|static-auth-secret=${NEW_TURN}|"              "$DATA_DIR/coturn/config/turnserver.conf"
  echo "  ✓ turnserver.conf updated"
fi

# Update homeserver.yaml
if [ -f "$DATA_DIR/synapse/appdata/homeserver.yaml" ]; then
  sed -i "s|^turn_shared_secret:.*|turn_shared_secret: \"${NEW_TURN}\"|"         "$DATA_DIR/synapse/appdata/homeserver.yaml"
  echo "  ✓ homeserver.yaml updated"
fi

echo "  ✓ .env updated"
echo ""

# Restart affected services
echo "Restarting services..."
cd "$PROJECT_DIR"
docker compose restart matrix-coturn jitsi-prosody jitsi-jicofo jitsi-jvb matrix-synapse 2>/dev/null \
  || docker-compose restart matrix-coturn jitsi-prosody jitsi-jicofo jitsi-jvb matrix-synapse 2>/dev/null \
  || echo "  ⚠ Could not restart — run 'docker compose restart' manually"

echo ""
echo "✓ Secrets rotated and services restarted."
