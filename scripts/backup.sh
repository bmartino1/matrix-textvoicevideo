#!/usr/bin/env bash
set -euo pipefail
# Creates a full backup of the Matrix server
source "$(dirname "$0")/../.env"
BACKUP_DIR="${1:-./backups/$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$BACKUP_DIR"

echo "Backing up PostgreSQL..."
docker exec matrix-postgres pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > "$BACKUP_DIR/synapse.sql"

echo "Backing up configs..."
cp "$DATA_DIR/synapse/appdata/homeserver.yaml" "$BACKUP_DIR/"
cp -r "$DATA_DIR/synapse/appdata/"*.signing.key "$BACKUP_DIR/" 2>/dev/null || true
cp "$(dirname "$0")/../.env" "$BACKUP_DIR/"

echo "Backing up media..."
tar -czf "$BACKUP_DIR/media_store.tar.gz" -C "$DATA_DIR/synapse" media_store 2>/dev/null || true

echo "✓ Backup complete: $BACKUP_DIR"
ls -lh "$BACKUP_DIR/"
