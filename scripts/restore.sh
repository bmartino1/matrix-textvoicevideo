#!/usr/bin/env bash
set -euo pipefail
# Restore from a backup created by backup.sh.
# Usage: ./scripts/restore.sh <backup-file.tar.gz>

source "$(dirname "$0")/load-env.sh"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

BACKUP_FILE="${1:?Usage: $0 <backup-file.tar.gz>}"
[[ ! -f "$BACKUP_FILE" ]] && { echo "ERROR: Backup file not found: ${BACKUP_FILE}"; exit 1; }

echo "⚠ This will restore from: ${BACKUP_FILE}"
echo "  Current data will be REPLACED."
read -r -p "Type YES to confirm: " CONFIRM
[[ "$CONFIRM" != "YES" ]] && { echo "Aborted."; exit 0; }

echo "Stopping stack..."
(cd "$PROJECT_DIR" && docker compose down)

echo "Extracting backup..."
tar -xzf "$BACKUP_FILE" -C "${DATA_DIR}"

# Find and restore postgres dump
SQL_FILE=$(tar -tzf "$BACKUP_FILE" | grep "matrix-postgres.*\.sql" | head -1 || true)
if [[ -n "$SQL_FILE" ]]; then
  echo "Restoring PostgreSQL from dump..."
  (cd "$PROJECT_DIR" && docker compose up -d postgres)
  sleep 10
  docker exec -i matrix-postgres psql -U "${POSTGRES_USER}" "${POSTGRES_DB}" \
    < "${DATA_DIR}/${SQL_FILE}" 2>/dev/null || true
fi

echo "Starting stack..."
(cd "$PROJECT_DIR" && docker compose up -d)

echo ""
echo "✓ Restore complete."
