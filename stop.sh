#!/usr/bin/env bash
# Tear the sandbox down. The profile lived in tmpfs, so this destroys
# every cookie, cache entry and download the session ever created.
# Thin wrapper: the implementation is scripts/safebrowse.py. Arguments pass through
# unchanged and the exit status is the launcher's own.
case "${BASH_SOURCE[0]}" in */*) here=${BASH_SOURCE[0]%/*} ;; *) here=. ;; esac
command -v python3 >/dev/null 2>&1 || {
  echo "python3 was not found on your PATH. Install Python 3.12 or newer, open a new terminal, then rerun ./stop.sh." >&2
  exit 1
}
exec python3 "$here/scripts/safebrowse.py" stop "$@"
