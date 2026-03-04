#!/usr/bin/env bash
set -euo pipefail
# Backup all persistent data to a timestamped tar.gz archive.
# Usage: ./scripts/backup.sh [output-dir]

source "$(dirname "$0")/load-env.sh"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

BACKUP_DIR="${1:-${PROJECT_DIR}/backups}"
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/matrix-backup-${TIMESTAMP}.tar.gz"

echo "Creating backup: ${BACKUP_FILE}"
echo "This may take a while for large media stores..."
echo ""

# Dump postgres first
echo "Dumping PostgreSQL..."
docker exec matrix-postgres pg_dump -U "${POSTGRES_USER}" "${POSTGRES_DB}" \
  > "/tmp/matrix-postgres-${TIMESTAMP}.sql"

# Create archive
tar -czf "$BACKUP_FILE" \
  -C "${DATA_DIR}" \
  --exclude="./postgres" \
  . \
  -C /tmp \
  "matrix-postgres-${TIMESTAMP}.sql" \
  2>/dev/null

rm -f "/tmp/matrix-postgres-${TIMESTAMP}.sql"

SIZE=$(du -sh "$BACKUP_FILE" | cut -f1)
echo "✓ Backup complete: ${BACKUP_FILE} (${SIZE})"
echo ""
echo "To restore: ./scripts/restore.sh ${BACKUP_FILE}"
