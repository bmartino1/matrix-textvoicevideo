#!/usr/bin/env bash
set -euo pipefail
# Restore a backup created by scripts/backup.sh
# Usage: ./scripts/restore.sh <backup-dir>
#
# WARNING: This will overwrite configs and restore DB/media.
source "$(dirname "$0")/load-env.sh"

BKP="${1:?Usage: $0 <backup-dir>}"
if [ ! -d "$BKP" ]; then
  echo "ERROR: backup dir not found: $BKP"
  exit 1
fi

echo "======================================================"
echo " RESTORE — matrix-textvoicevideo"
echo " Backup: $BKP"
echo "======================================================"
echo ""
echo "This will:"
echo "  • Restore Postgres DB from synapse.pgdump"
echo "  • Restore configs (.env, homeserver.yaml, nginx.conf, etc if present)"
echo "  • Restore media_store (if present)"
echo "  • Restore TLS certs (if present)"
echo ""
read -p "Type RESTORE to continue: " confirm
[ "$confirm" != "RESTORE" ] && { echo "Aborted."; exit 0; }

cd "$PROJECT_DIR"

echo "[1/5] Stopping stack..."
docker compose down 2>/dev/null || docker-compose down 2>/dev/null || true

echo "[2/5] Restoring configs..."
[ -f "$BKP/dot.env" ] && cp -f "$BKP/dot.env" "$PROJECT_DIR/.env" && chmod 600 "$PROJECT_DIR/.env" || true
[ -f "$BKP/homeserver.yaml" ] && cp -f "$BKP/homeserver.yaml" "$DATA_DIR/synapse/appdata/homeserver.yaml" || true
[ -f "$BKP/nginx.conf" ] && cp -f "$BKP/nginx.conf" "$DATA_DIR/nginx/nginx.conf" || true
[ -f "$BKP/turnserver.conf" ] && cp -f "$BKP/turnserver.conf" "$DATA_DIR/coturn/config/turnserver.conf" || true
[ -f "$BKP/config.json" ] && cp -f "$BKP/config.json" "$DATA_DIR/element-web/config/config.json" || true

# signing key
if ls "$BKP"/*.signing.key >/dev/null 2>&1; then
  cp -f "$BKP"/*.signing.key "$DATA_DIR/synapse/appdata/" || true
fi

echo "[3/5] Restoring media_store..."
if [ -f "$BKP/media_store.tar.gz" ]; then
  rm -rf "$DATA_DIR/synapse/media_store"
  mkdir -p "$DATA_DIR/synapse"
  tar -xzf "$BKP/media_store.tar.gz" -C "$DATA_DIR/synapse"
  echo "      ✓ media restored"
else
  echo "      (no media tar found; skipped)"
fi

echo "[4/5] Restoring TLS certs..."
if [ -f "$BKP/nginx_certs.tar.gz" ]; then
  mkdir -p "$DATA_DIR/nginx"
  tar -xzf "$BKP/nginx_certs.tar.gz" -C "$DATA_DIR/nginx"
  echo "      ✓ certs restored"
else
  echo "      (no cert tar found; skipped)"
fi

echo "[5/5] Starting stack..."
docker compose up -d 2>/dev/null || docker-compose up -d 2>/dev/null

echo ""
echo "Waiting for Postgres..."
sleep 5

if [ -f "$BKP/synapse.pgdump" ]; then
  echo "Restoring database..."
  docker exec -i matrix-postgres pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists < "$BKP/synapse.pgdump" \
    && echo "      ✓ DB restored" \
    || echo "      ✗ DB restore failed (check logs)"
else
  echo "No synapse.pgdump found; DB restore skipped."
fi

echo ""
echo "✓ Restore complete."
echo "Next: ./scripts/status.sh"
