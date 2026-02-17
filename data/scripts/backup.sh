#!/usr/bin/env bash
set -euo pipefail
# Full backup: database, configs, signing keys, media store
# Usage: ./scripts/backup.sh [destination-dir]
source "$(dirname "$0")/load-env.sh"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${1:-${PROJECT_DIR}/backups/${TIMESTAMP}}"
mkdir -p "$BACKUP_DIR"

echo "======================================================"
echo " Matrix-TextVoiceVideo Backup — $(date)"
echo " Destination: $BACKUP_DIR"
echo "======================================================"
echo ""

ERRORS=0

# ── 1. PostgreSQL ────────────────────────────────────────────────────────────
echo "[1/4] Backing up PostgreSQL database..."
if docker exec matrix-postgres pg_dump \
    -U "$POSTGRES_USER" \
    --format=custom \
    --compress=9 \
    "$POSTGRES_DB" > "$BACKUP_DIR/synapse.pgdump" 2>&1; then
  echo "      ✓ Database: $(du -sh "$BACKUP_DIR/synapse.pgdump" | cut -f1)"
else
  echo "      ✗ Database backup FAILED"
  ERRORS=$((ERRORS + 1))
fi

# ── 2. Secrets + configs ─────────────────────────────────────────────────────
echo "[2/4] Backing up configs and secrets..."
cp "$DATA_DIR/synapse/appdata/homeserver.yaml" "$BACKUP_DIR/" 2>/dev/null && echo "      ✓ homeserver.yaml" || true
cp "$DATA_DIR/coturn/config/turnserver.conf"   "$BACKUP_DIR/" 2>/dev/null && echo "      ✓ turnserver.conf"  || true
# Copy .env with a safe name (won't auto-source if placed somewhere)
cp "$PROJECT_DIR/.env" "$BACKUP_DIR/dot.env" 2>/dev/null && \
  chmod 600 "$BACKUP_DIR/dot.env" && \
  echo "      ✓ .env (saved as dot.env)" || true

# ── 3. Signing key — CRITICAL ────────────────────────────────────────────────
echo "[3/4] Backing up Synapse signing key..."
KEYS=$(find "$DATA_DIR/synapse/appdata" -name "*.signing.key" 2>/dev/null)
if [ -n "$KEYS" ]; then
  echo "$KEYS" | while read -r key; do
    cp "$key" "$BACKUP_DIR/"
    echo "      ✓ $(basename "$key")  ← KEEP THIS SAFE — loss = server identity gone"
  done
else
  echo "      ⚠ No signing key found yet (stack may not have started)"
fi

# ── 4. Media store ───────────────────────────────────────────────────────────
echo "[4/4] Backing up media store..."
if [ -d "$DATA_DIR/synapse/media_store" ] && [ "$(ls -A "$DATA_DIR/synapse/media_store" 2>/dev/null)" ]; then
  tar -czf "$BACKUP_DIR/media_store.tar.gz" \
    -C "$DATA_DIR/synapse" \
    media_store 2>/dev/null && \
    echo "      ✓ Media: $(du -sh "$BACKUP_DIR/media_store.tar.gz" | cut -f1)" || \
    echo "      ⚠ Media tar failed"
else
  echo "      ⚠ Media store empty or not found — skipped"
fi

echo ""
echo "======================================================"
if [ "$ERRORS" -eq 0 ]; then
  echo "✓ Backup complete: $BACKUP_DIR"
else
  echo "⚠ Backup completed with ${ERRORS} error(s): $BACKUP_DIR"
fi
echo "======================================================"
echo ""
ls -lh "$BACKUP_DIR/"
echo ""
echo "Restore commands:"
echo "  Database:  docker exec -i matrix-postgres pg_restore -U $POSTGRES_USER -d $POSTGRES_DB < $BACKUP_DIR/synapse.pgdump"
echo "  Configs:   cp $BACKUP_DIR/homeserver.yaml $DATA_DIR/synapse/appdata/"
echo "  Env:       cp $BACKUP_DIR/dot.env $PROJECT_DIR/.env && chmod 600 $PROJECT_DIR/.env"
