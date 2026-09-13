#!/usr/bin/env bash
# Gateway diagnostics are in tmpfs. Docker log storage is disabled for it.
set -euo pipefail
cd "$(dirname "$0")"
N="${1:-50}"
[[ "$N" =~ ^[1-9][0-9]*$ ]] || { echo "Usage: ./logs.sh [positive line count]" >&2; exit 1; }
if [ "$(docker inspect -f '{{.State.Status}}' safebrowse-gw 2>/dev/null)" != running ]; then
  echo "Gateway is not running. Check configuration with:"
  echo "  docker compose run --rm --no-deps gateway squid -k parse"
  exit 1
fi
echo "=== gateway diagnostics (memory-backed) ==="
docker exec safebrowse-gw tail -n "$N" /var/log/squid/cache.log
echo "=== optional access log (disabled by default) ==="
docker exec safebrowse-gw tail -n "$N" /var/log/squid/access.log 2>/dev/null \
  || echo "No access log. See README.md to enable temporary diagnostics."
