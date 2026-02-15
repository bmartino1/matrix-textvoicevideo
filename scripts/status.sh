#!/usr/bin/env bash
set -euo pipefail
# Shows the status of all services

echo "=== Container Status ==="
docker compose ps 2>/dev/null || docker-compose ps 2>/dev/null || echo "(docker compose not available)"

echo ""
echo "=== Service Health ==="
source "$(dirname "$0")/load-env.sh"

check() {
  local name="$1" url="$2"
  if curl -sf --connect-timeout 3 "$url" > /dev/null 2>&1; then
    echo "  ✓ $name"
  else
    echo "  ✗ $name (unreachable)"
  fi
}

check "Synapse API"       "http://172.42.0.3:8008/_matrix/client/versions"
check "Element Web"       "http://172.42.0.4:80"
check "Element Call"      "http://172.42.0.5:8080"
check "LiveKit SFU"       "http://172.42.0.6:7880"
check "LK-JWT-Service"    "http://172.42.0.8:8080/healthz"
check "Nginx (HTTP)"      "http://172.42.0.10:80"

echo ""
echo "=== External Endpoints ==="
check "Public HTTPS"      "${PUBLIC_URL}/_matrix/client/versions"
check "Well-Known Client" "${PUBLIC_URL}/.well-known/matrix/client"
check "LiveKit JWT Health" "${PUBLIC_URL}/livekit/jwt/healthz"

echo ""
echo "=== Resource Usage ==="
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>/dev/null | head -20
