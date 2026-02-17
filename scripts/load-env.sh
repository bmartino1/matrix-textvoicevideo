#!/usr/bin/env bash
# Safe .env loader — exports key=value pairs, strips quotes.
# Usage: source "$(dirname "$0")/load-env.sh"
set -euo pipefail

_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_ENV_FILE="${_SCRIPT_DIR}/../.env"

if [ ! -f "$_ENV_FILE" ]; then
  _ENV_FILE="$(readlink -f "${_SCRIPT_DIR}/..")/.env" 2>/dev/null || true
fi

if [ -z "${_ENV_FILE:-}" ] || [ ! -f "$_ENV_FILE" ]; then
  echo "ERROR: .env not found at repo root. Run setup.sh first." >&2
  exit 1
fi

while IFS= read -r _line || [ -n "$_line" ]; do
  [[ -z "$_line" || "$_line" =~ ^[[:space:]]*# ]] && continue

  _key="${_line%%=*}"
  _val="${_line#*=}"

  _val="${_val#\"}"; _val="${_val%\"}"
  _val="${_val#\'}"; _val="${_val%\'}"

  if [[ "$_key" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
    export "${_key}=${_val}"
  fi
done < "$_ENV_FILE"

PROJECT_DIR="$(cd "${_SCRIPT_DIR}/.." && pwd)"
export PROJECT_DIR

# Basic sanity
: "${DATA_DIR:?Missing DATA_DIR in .env}"
: "${SERVER_NAME:?Missing SERVER_NAME in .env}"
