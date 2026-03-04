#!/usr/bin/env bash
# Sourced by admin scripts to load the admin token.
# Exits with an error if the token file doesn't exist.

source "$(dirname "${BASH_SOURCE[0]}")/load-env.sh"

if [[ ! -f "$ADMIN_TOKEN_FILE" ]]; then
  echo "ERROR: No admin token found."
  echo "Run: ./scripts/get-admin-token.sh"
  exit 1
fi

ADMIN_TOKEN=$(cat "$ADMIN_TOKEN_FILE")
[[ -z "$ADMIN_TOKEN" ]] && { echo "ERROR: admin-token.txt is empty. Re-run ./scripts/get-admin-token.sh"; exit 1; }
