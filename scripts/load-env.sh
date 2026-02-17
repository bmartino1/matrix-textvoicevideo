#!/usr/bin/env bash
# Safe .env loader — exports key=value pairs, strips surrounding quotes.
# Usage: source "$(dirname "$0")/load-env.sh"
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/../.env"

# Resolve in case of symlinks
if [ ! -f "$ENV_FILE" ] && command -v readlink >/dev/null 2>&1; then
  ENV_FILE="$(readlink -f "${SCRIPT_DIR}/..")/.env" 2>/dev/null || true
fi

if [ -z "${ENV_FILE:-}" ] || [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: .env not found at repo root. Run setup.sh first." >&2
  exit 1
fi

while IFS= read -r line || [ -n "$line" ]; do
  [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

  key="${line%%=*}"
  val="${line#*=}"

  # strip surrounding quotes only
  val="${val#\"}"; val="${val%\"}"
  val="${val#\'}"; val="${val%\'}"

  if [[ "$key" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
    export "${key}=${val}"
  fi
done < "$ENV_FILE"

PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
export PROJECT_DIR

: "${DATA_DIR:?Missing DATA_DIR in .env}"
: "${SERVER_NAME:?Missing SERVER_NAME in .env}"
