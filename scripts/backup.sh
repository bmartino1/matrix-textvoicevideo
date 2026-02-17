#!/usr/bin/env bash
set -euo pipefail
#
# Full backup: database + configs + signing keys + media + certs
#
# Usage:
#   ./scripts/backup.sh [destination-dir]
#
source "$(dirname "$0")/load-env.sh"

TS="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${1:-${PROJECT_DIR}/backups/${TS}}"
mkdir -p "$BACKUP_DIR"

echo "======================================================"
echo " Backup — matrix-textvoicevideo — $(date)"
echo " Destination: $BACKUP_DIR"
echo "======================================================"
echo ""

ERR=0

echo "[1/5] PostgreSQL dump..."
if docker exec matrix-postgres pg_dump -U "$POSTGRES_USER" --format=custom --compress=9 "$POSTGRES_DB" \
  > "$BACKUP_DIR/synapse.pgdump" 2>/dev/null; then
  echo "      ✓ synapse.pgdump ($(du -sh "$BACKUP_DIR/synapse.pgdump" | cut -f1))"
else
  echo "      ✗ FAILED"
  ERR=$((ERR+1))
fi

echo "[2/5] Core configs..."
cp -a "$PROJECT_DIR/.env" "$BACKUP_DIR/dot.env" 2>/dev/null || true
chmod 600 "$BACKUP_DIR/dot.env" 2>/dev/null || true

cp -a "$DATA_DIR/synapse/appdata/homeserver.yaml" "$BACKUP_DIR/" 2>/dev/null || true
cp -a "$DATA_DIR/coturn/config/turnserver.conf"   "$BACKUP_DIR/" 2>/dev/null || true
cp -a "$DATA_DIR/nginx/nginx.conf"                "$BACKUP_DIR/" 2>/dev/null || true
cp -a "$DATA_DIR/element-web/config/config.json"  "$BACKUP_DIR/" 2>/dev/null || true

echo "[3/5] Synapse signing key (CRITICAL)..."
# FIX: -maxdepth must come before -name
find "$DATA_DIR/synapse/appdata" -maxdepth 1 -type f -name "*.signing.key" -print -exec cp -a {} "$BACKUP_DIR/" \; 2>/dev/null || true

echo "[4/5] Media store..."
if [ -d "$DATA_DIR/synapse/media_store" ] && [ "$(ls -A "$DATA_DIR/synapse/media_store" 2>/dev/null)" ]; then
  tar -czf "$BACKUP_DIR/media_store.tar.gz" -C "$DATA_DIR/synapse" media_store 2>/dev/null \
    && echo "      ✓ media_store.tar.gz ($(du -sh "$BACKUP_DIR/media_store.tar.gz" | cut -f1))" \
    || echo "      ⚠ Media tar failed"
else
  echo "      ⚠ Media store empty or missing (skipped)"
fi

echo "[5/5] TLS certs (nginx/certbot)..."
if [ -d "$DATA_DIR/nginx/certs" ] && [ "$(ls -A "$DATA_DIR/nginx/certs" 2>/dev/null)" ]; then
  tar -czf "$BACKUP_DIR/nginx_certs.tar.gz" -C "$DATA_DIR/nginx" certs 2>/dev/null \
    && echo "      ✓ nginx_certs.tar.gz ($(du -sh "$BACKUP_DIR/nginx_certs.tar.gz" | cut -f1))" \
    || echo "      ⚠ Certs tar failed"
else
  echo "      ⚠ No certs directory content (skipped)"
fi

echo ""
if [ "$ERR" -eq 0 ]; then
  echo "✓ Backup complete: $BACKUP_DIR"
else
  echo "⚠ Backup complete with $ERR error(s): $BACKUP_DIR"
fi
ls -lh "$BACKUP_DIR" | sed 's/^/  /'
