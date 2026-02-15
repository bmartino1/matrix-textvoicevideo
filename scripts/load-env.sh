#!/usr/bin/env bash
# Safe .env loader — reads key=value pairs even if values contain spaces.
# Usage:  source "$(dirname "$0")/load-env.sh"

_ENV_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.env"
if [ ! -f "$_ENV_FILE" ]; then
  echo "ERROR: .env not found at $_ENV_FILE" >&2
  echo "       Run setup.sh first to generate it." >&2
  exit 1
fi

# Read each non-comment, non-empty line and export it safely
while IFS= read -r line || [ -n "$line" ]; do
  # Skip blanks and comments
  [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
  # Strip surrounding quotes from the value
  key="${line%%=*}"
  val="${line#*=}"
  # Remove leading/trailing double-quotes if present
  val="${val#\"}"
  val="${val%\"}"
  # Remove leading/trailing single-quotes if present
  val="${val#\'}"
  val="${val%\'}"
  export "$key=$val"
done < "$_ENV_FILE"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
