#!/usr/bin/env bash
# Safe .env loader — sources key=value pairs, strips quotes, handles spaces.
# Usage: source "$(dirname "$0")/load-env.sh"
# Sets all .env vars as exported shell variables + sets PROJECT_DIR

_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_ENV_FILE="${_SCRIPT_DIR}/../.env"

if [ ! -f "$_ENV_FILE" ]; then
  # Try absolute resolve in case of symlinks
  _ENV_FILE="$(readlink -f "${_SCRIPT_DIR}/..")/.env" 2>/dev/null || _ENV_FILE=""
fi

if [ -z "$_ENV_FILE" ] || [ ! -f "$_ENV_FILE" ]; then
  echo "ERROR: .env not found. Run setup.sh first to generate it." >&2
  exit 1
fi

while IFS= read -r _line || [ -n "$_line" ]; do
  # Skip blank lines and comments
  [[ -z "$_line" || "$_line" =~ ^[[:space:]]*# ]] && continue
  _key="${_line%%=*}"
  _val="${_line#*=}"
  # Strip surrounding double-quotes
  _val="${_val#\"}"
  _val="${_val%\"}"
  # Strip surrounding single-quotes
  _val="${_val#\'}"
  _val="${_val%\'}"
  # Only export valid shell variable names (no spaces, starts with letter/_)
  if [[ "$_key" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
    export "$_key=$_val"
  fi
done < "$_ENV_FILE"

PROJECT_DIR="$(cd "${_SCRIPT_DIR}/.." && pwd)"
export PROJECT_DIR
