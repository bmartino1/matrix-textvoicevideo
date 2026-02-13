#!/usr/bin/env bash
set -euo pipefail
# Shows the status of all services
echo "=== Container Status ==="
docker compose ps 2>/dev/null || docker-compose ps

echo ""
echo "=== Service Health ==="
source "$(dirname "$0")/../.env"

check() {
  local name="$1" url="$2"
  if curl -sf --connect-timeout 3 "$url" > /dev/null 2>&1; then
    echo "  ✓ $name"
  else
    echo "  ✗ $name (unreachable)"
  fi
}

check "Synapse API"    "http://localhost:8008/_matrix/client/versions"
check "Element Web"    "http://localhost:80"
check "LiveKit"        "http://localhost:7880"
echo ""
echo "=== Resource Usage ==="
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>/dev/null | head -20
