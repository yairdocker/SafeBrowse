#!/usr/bin/env bash
# Tear the sandbox down. The profile lived in tmpfs, so this destroys
# every cookie, cache entry and download the session ever created.
set -euo pipefail
cd "$(dirname "$0")"
# Teardown must work even if .env was lost; this value is never used to start a container.
SANDBOX_PASSWORD=unused-for-teardown docker compose down --volumes --remove-orphans
echo "==> Sandbox destroyed. Session containers and profile removed; this is not secure disk erasure."
