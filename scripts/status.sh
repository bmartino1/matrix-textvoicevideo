#!/usr/bin/env bash
# Show status of all stack services and external endpoint checks.
# Usage: ./scripts/status.sh

source "$(dirname "$0")/load-env.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
fail() { echo -e "  ${RED}✗${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; }

check_container() {
  local name=$1 label=$2
  if docker inspect --format='{{.State.Status}}' "$name" 2>/dev/null | grep -q "running"; then
    ok "${label} (${name})"
  else
    fail "${label} (${name}) — NOT RUNNING"
  fi
}

check_http() {
  local url=$1 label=$2
  if curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null | grep -qE "^[23]"; then
    ok "${label}: ${url}"
  else
    fail "${label}: ${url} — NOT REACHABLE"
  fi
}

echo ""
echo "=== Container Status ==="
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" 2>/dev/null || echo "(docker not available)"
echo ""

echo "=== Internal Services ==="
check_container "matrix-postgres"     "PostgreSQL"
check_container "matrix-valkey"       "Valkey"
check_container "matrix-synapse"      "Synapse"
check_container "matrix-element-web"  "Element Web"
check_container "matrix-nginx"        "Nginx"
check_container "matrix-coturn"       "Coturn"
check_container "jitsi-web"           "Jitsi Web"
check_container "jitsi-prosody"       "Jitsi Prosody"
check_container "jitsi-jicofo"        "Jitsi Jicofo"
check_container "jitsi-jvb"           "Jitsi JVB"
echo ""

echo "=== External Endpoints ==="
check_http "https://${SERVER_NAME}" "Element Web"
check_http "https://${SERVER_NAME}/_matrix/client/versions" "Matrix API"
check_http "https://${SERVER_NAME}/.well-known/matrix/client" "Well-Known Client"
check_http "https://${SERVER_NAME}/.well-known/matrix/server" "Well-Known Server"
check_http "https://${JITSI_DOMAIN}" "Jitsi Meet"
echo ""

echo "=== Synapse Health ==="
HEALTH=$(docker exec matrix-synapse curl -sf http://localhost:8008/health 2>/dev/null || echo "FAIL")
if [[ "$HEALTH" == "OK" ]]; then
  ok "Synapse internal health check: OK"
else
  fail "Synapse internal health check: ${HEALTH}"
fi
echo ""

echo "=== Coturn (TURNS TLS) ==="
if command -v nc >/dev/null 2>&1; then
  if nc -z -w3 localhost 5349 2>/dev/null; then
    ok "Coturn TURNS port 5349 accepting connections"
  else
    fail "Coturn port 5349 not responding"
  fi
else
  warn "Install netcat (nc) to test Coturn TCP reachability"
  check_container "matrix-coturn" "Coturn container"
fi
echo ""

echo "=== Resource Usage ==="
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" \
  matrix-nginx matrix-element-web matrix-synapse matrix-postgres \
  matrix-valkey matrix-coturn jitsi-web jitsi-prosody jitsi-jicofo jitsi-jvb \
  2>/dev/null || echo "(could not get stats)"
echo ""

echo "=== Configuration Summary ==="
echo "  Domain:       ${SERVER_NAME}"
echo "  Public URL:   ${PUBLIC_URL}"
echo "  Jitsi URL:    https://${JITSI_DOMAIN}"
echo "  External IP:  ${EXTERNAL_IP}"
echo "  Internal IP:  ${INTERNAL_IP}"
echo "  Data Dir:     ${DATA_DIR}"

if [[ -f "${DATA_DIR}/nginx/certs/live/${SERVER_NAME}/fullchain.pem" ]]; then
  if openssl x509 -noout -issuer \
      -in "${DATA_DIR}/nginx/certs/live/${SERVER_NAME}/fullchain.pem" 2>/dev/null \
      | grep -qi "let.s encrypt"; then
    echo "  TLS:          Let's Encrypt ✓"
  else
    echo "  TLS:          Self-signed ⚠"
  fi
else
  echo "  TLS:          No cert found"
fi
echo ""
