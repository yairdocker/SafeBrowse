#!/usr/bin/env bash
# Tear the sandbox down. The profile lived in tmpfs, so this destroys
# every cookie, cache entry and download the session ever created.
set -euo pipefail
cd "$(dirname "$0")"
docker compose down --volumes --remove-orphans
echo "==> Sandbox destroyed. Nothing persisted."
