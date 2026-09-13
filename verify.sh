#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
command -v python3 >/dev/null 2>&1 || { echo "Python 3.9+ is required for ./verify.sh" >&2; exit 1; }
exec python3 scripts/verify.py "$@"
