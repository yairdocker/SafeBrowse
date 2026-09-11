#!/usr/bin/env bash
# safebrowse - build and launch the disposable browsing sandbox.
# No `set -e`: every step is checked explicitly so failures explain themselves.
set -uo pipefail
cd "$(dirname "$0")" || exit 1

RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; CYN=$'\033[36m'; OFF=$'\033[0m'
step() { printf '%s==>%s %s\n' "$CYN" "$OFF" "$1"; }
warn() { printf '%sWARNING%s %s\n' "$YLW" "$OFF" "$1"; }
die()  { printf '\n%sERROR%s  %s\n\n' "$RED" "$OFF" "$1" >&2; exit 1; }

# --------------------------------------------------------------------------
# Preflight - fail with a sentence you can act on, not a stack trace
# --------------------------------------------------------------------------
step "Checking Docker"
command -v docker >/dev/null 2>&1 \
  || die "docker is not on your PATH. Install Docker Desktop, then open a new terminal."
docker info >/dev/null 2>&1 \
  || die "Docker is installed but the daemon isn't answering. Start Docker Desktop, wait for the whale icon to stop animating, then re-run this script."
docker compose version >/dev/null 2>&1 \
  || die "'docker compose' (v2) isn't available. Update Docker Desktop."

mem=$(docker info --format '{{.MemTotal}}' 2>/dev/null) || mem=0
case "$mem" in ''|*[!0-9]*) mem=0 ;; esac
if [ "$mem" -gt 0 ] && [ "$mem" -lt 5500000000 ]; then
  warn "Docker has $((mem / 1024 / 1024 / 1024)) GiB of RAM; the sandbox alone is capped at 4 GiB."
  warn "If Chromium dies on startup, raise it in Docker Desktop > Settings > Resources > Memory."
fi

# --------------------------------------------------------------------------
# Credentials for the remote-desktop login
# --------------------------------------------------------------------------
ENV_FILE=".env"
if [ ! -f "$ENV_FILE" ]; then
  step "First run: generating $ENV_FILE with a random UI password"
  if command -v openssl >/dev/null 2>&1; then
    PW=$(openssl rand -hex 12)
  else
    PW=$(dd if=/dev/urandom bs=1 count=16 2>/dev/null | od -An -tx1 | tr -d ' \n')
  fi
  [ -n "${PW:-}" ] || die "could not generate a password - no openssl and /dev/urandom unreadable."
  printf 'SANDBOX_USER=sandbox\nSANDBOX_PASSWORD=%s\n' "$PW" > "$ENV_FILE" \
    || die "could not write $ENV_FILE - check permissions on $(pwd)"
  chmod 600 "$ENV_FILE"
fi
# shellcheck disable=SC1090
. "./$ENV_FILE" || die "could not read $ENV_FILE"
: "${SANDBOX_USER:?SANDBOX_USER missing from .env - delete .env and re-run}"
: "${SANDBOX_PASSWORD:?SANDBOX_PASSWORD missing from .env - delete .env and re-run}"

# --------------------------------------------------------------------------
# Build and start
# --------------------------------------------------------------------------
step "Building image (first build pulls ~1.5 GB and takes a few minutes)"
docker compose build \
  || die "build failed - the reason is in the output above. Most often: no network, a registry blocking the pull, or Docker out of disk (Settings > Resources)."

step "Starting containers"
if ! docker compose up -d; then
  docker compose logs --tail 40
  die "containers failed to start (logs above)."
fi

step "Waiting for the remote desktop (up to 3 minutes)"
# The UI sits behind HTTP basic auth, so "/" legitimately answers 401.
# Any HTTP status at all means nginx is up and the path through socat works;
# only a connection failure (curl writes 000) means not-ready.
ready=0
for _ in $(seq 1 90); do
  code=$(curl -ks --max-time 3 -o /dev/null -w '%{http_code}' "https://127.0.0.1:3011/" 2>/dev/null)
  case "$code" in
    000|"") : ;;                      # nothing listening yet
    *)      ready=1; break ;;         # 200, 301, 401 - all mean it is serving
  esac
  sleep 2
done

if [ "$ready" -ne 1 ]; then
  printf '\n%sThe desktop did not come up. Recent logs:%s\n\n' "$YLW" "$OFF"
  docker compose logs --tail 40
  die "not ready in time. If Chromium is crash-looping, see 'Chromium doesn't start' in README.md."
fi

cat <<INFO

  ${GRN}safebrowse is running.${OFF}

    URL       https://127.0.0.1:3011/     (self-signed cert - accept the warning)
    user      ${SANDBOX_USER}
    password  ${SANDBOX_PASSWORD}

  Next:  ./verify.sh     confirm the hardening actually applied
         ./stop.sh       destroy everything

INFO
