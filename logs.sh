#!/usr/bin/env bash
# Show the gateway's logs. Squid cannot write to the container's stdout (it
# drops to the 'proxy' user), so its access and cache logs live inside the
# container. Startup failures still land in `docker logs safebrowse-gw`.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
N="${1:-50}"

echo "=== squid startup / fatals (docker logs) ==="
docker logs safebrowse-gw --tail "$N" 2>&1 | tail -n "$N"

if [ "$(docker inspect -f '{{.State.Status}}' safebrowse-gw 2>/dev/null)" = "running" ]; then
  echo
  echo "=== cache.log (warnings, errors) ==="
  docker exec safebrowse-gw tail -n "$N" /var/log/squid/cache.log 2>/dev/null || echo "(none yet)"
  echo
  echo "=== access.log (TCP_DENIED here names whatever the gateway refused) ==="
  docker exec safebrowse-gw tail -n "$N" /var/log/squid/access.log 2>/dev/null || echo "(none yet)"
else
  echo
  echo "(gateway is not running - only the startup output above is available)"
fi
