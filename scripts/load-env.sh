#!/usr/bin/env bash
# Sourced by other scripts to load .env and set common vars.
# Usage: source "$(dirname "$0")/load-env.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${PROJECT_DIR}/.env"

[[ ! -f "$ENV_FILE" ]] && { echo "ERROR: .env not found at ${ENV_FILE}"; echo "Run: sudo bash setup.sh --domain YOUR_DOMAIN"; exit 1; }

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

SYNAPSE_URL="http://localhost:8008"
ADMIN_TOKEN_FILE="${SCRIPT_DIR}/admin-token.txt"
