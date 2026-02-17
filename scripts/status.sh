#!/usr/bin/env bash
# Check health and status of all matrix-textvoicevideo services
# Usage: ./scripts/status.sh
set -euo pipefail
source "$(dirname "$0")/load-env.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1  ${YELLOW}($2)${NC}"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }

check_http() {
  local name="$1" url="$2"
  if curl -sf --connect-timeout 3 --max-time 5 "$url" >/dev/null 2>&1; then ok "$name"; else fail "$name" "$url"; fi
}

check_https() {
  local name="$1" url="$2"
  if curl -sfk --connect-timeout 5 --max-time 10 "$url" >/dev/null 2>&1; then ok "$name"; else fail "$name" "check DNS/ports for $url"; fi
}

echo -e "${CYAN}${BOLD}=== Container Status ===${NC}"
cd "$PROJECT_DIR"
docker compose ps 2>/dev/null || docker-compose ps 2>/dev/null || echo "  (docker compose unavailable)"

echo ""
echo -e "${CYAN}${BOLD}=== Internal Services ===${NC}"

if docker exec matrix-postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" -q 2>/dev/null; then
  ok "PostgreSQL (matrix-postgres)"
else
  fail "PostgreSQL" "not ready"
fi

if docker exec matrix-valkey valkey-cli ping 2>/dev/null | grep -q PONG; then
  ok "Valkey (matrix-valkey)"
else
  fail "Valkey" "not ready"
fi

check_http "Synapse API"  "http://172.42.0.3:8008/_matrix/client/versions"
check_http "Element Web"  "http://172.42.0.4:80"
check_http "Nginx (HTTP)" "http://172.42.0.10:80"
check_http "Jitsi Web"    "http://172.42.0.22:80"

echo ""
echo -e "${CYAN}${BOLD}=== External Endpoints ===${NC}"
check_https "Matrix HTTPS"      "${PUBLIC_URL}/_matrix/client/versions"
check_https "Well-Known Client" "${PUBLIC_URL}/.well-known/matrix/client"
check_https "Well-Known Server" "${PUBLIC_URL}/.well-known/matrix/server"
check_https "Jitsi Video"       "${JITSI_PUBLIC_URL:-https://meet.${SERVER_NAME}}"

echo ""
echo -e "${CYAN}${BOLD}=== Coturn TURN Server ===${NC}"
if command -v nc >/dev/null 2>&1; then
  if nc -zu "${EXTERNAL_IP}" 3478 -w2 2>/dev/null; then ok "Coturn UDP 3478 reachable"; else warn "Coturn UDP 3478 — check port forwarding"; fi
else
  warn "Install netcat (nc) to test Coturn UDP reachability"
fi

if docker ps --format '{{.Names}}' | grep -q '^matrix-coturn$'; then
  ok "Coturn container running"
else
  fail "Coturn container" "not running"
fi

echo ""
echo -e "${CYAN}${BOLD}=== Resource Usage ===${NC}"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>/dev/null \
  | grep -E "(NAME|matrix-|jitsi-)" | head -25 || echo "  (no containers matched)"

echo ""
echo -e "${CYAN}${BOLD}=== Configuration Summary ===${NC}"
echo "  Domain:       ${SERVER_NAME}"
echo "  Public URL:   ${PUBLIC_URL}"
echo "  Jitsi URL:    ${JITSI_PUBLIC_URL:-https://meet.${SERVER_NAME}}"
echo "  External IP:  ${EXTERNAL_IP}"
echo "  Internal IP:  ${INTERNAL_IP}"
echo "  Data Dir:     ${DATA_DIR}"
echo "  TLS:          ${NO_TLS:-false}"
echo ""
