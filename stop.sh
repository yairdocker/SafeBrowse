#!/usr/bin/env bash
# Tear the sandbox down. The profile lived in tmpfs, so this destroys
# every cookie, cache entry and download the session ever created.
set -euo pipefail
cd "$(dirname "$0")"
unset SANDBOX_SUBNET SQUID_CONFIG_PATH
# Use the same generated configuration when available. Teardown still works if
# the state file or credentials have been lost.
if [ -f .runtime/network.json ] && command -v python3 >/dev/null 2>&1; then
  if SANDBOX_SUBNET=$(python3 scripts/network.py current 2>/dev/null); then
    SQUID_CONFIG_PATH="$(pwd)/.runtime/squid.conf"
    export SANDBOX_SUBNET SQUID_CONFIG_PATH
  fi
fi
# Teardown must work even if .env was lost; this value is never used to start a container.
SANDBOX_PASSWORD=unused-for-teardown docker compose down --volumes --remove-orphans
echo "==> Sandbox destroyed. Session containers and profile removed; this is not secure disk erasure."
