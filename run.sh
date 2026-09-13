#!/usr/bin/env bash
# safebrowse - build and launch the disposable browsing sandbox.
# No `set -e`: every step is checked explicitly so failures explain themselves.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
# shellcheck source=scripts/launch-lib.sh
. ./scripts/launch-lib.sh

RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; CYN=$'\033[36m'; OFF=$'\033[0m'
step() { printf '%s==>%s %s\n' "$CYN" "$OFF" "$1"; }
warn() { printf '%sWARNING%s %s\n' "$YLW" "$OFF" "$1"; }
die()  { printf '\n%sERROR%s  %s\n\n' "$RED" "$OFF" "$1" >&2; exit 1; }

# --------------------------------------------------------------------------
# Preflight - fail with a sentence you can act on, not a stack trace
# --------------------------------------------------------------------------
step "Checking prerequisites"
for tool in docker curl python3; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required. Install it and retry."
done
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || die "Python 3.9+ is required."
step "Checking Docker"
command -v docker >/dev/null 2>&1 \
  || die "docker is not on your PATH. Install Docker Desktop, then open a new terminal."
docker info >/dev/null 2>&1 \
  || die "Docker is installed but the daemon isn't answering. Start Docker Desktop, wait for the whale icon to stop animating, then re-run this script."
docker compose version >/dev/null 2>&1 \
  || die "'docker compose' (v2) isn't available. Update Docker Desktop."

engine_version=$(docker version --format '{{.Server.Version}}') || die "could not read Docker Engine version."
engine_major=${engine_version%%.*}
[[ "$engine_major" =~ ^[0-9]+$ ]] && [ "$engine_major" -ge 28 ] \
  || die "Docker Engine 28+ is required for isolated bridge mode and localhost port isolation."

# A pre-upgrade bridge cannot be changed in place. Never tear down a session
# automatically just to migrate its network configuration.
if mode=$(docker network inspect safebrowse_sandbox \
  -f '{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}' 2>/dev/null); then
  [ "$mode" = isolated ] || die "existing sandbox bridge needs migration: ./stop.sh discards the current session, then rerun ./run.sh."
fi

mem=$(docker info --format '{{.MemTotal}}' 2>/dev/null) || mem=0
case "$mem" in ''|*[!0-9]*) mem=0 ;; esac
if [ "$mem" -gt 0 ] && [ "$mem" -lt 5500000000 ]; then
  warn "Docker has $((mem / 1024 / 1024 / 1024)) GiB of RAM; the sandbox alone is capped at 4 GiB."
  warn "If Firefox dies on startup, raise it in Docker Desktop > Settings > Resources > Memory."
fi

# --------------------------------------------------------------------------
# Credentials for the remote-desktop login
# --------------------------------------------------------------------------
ENV_FILE=".env"
[ ! -L "$ENV_FILE" ] || die ".env must be a regular file, not a symlink."
if [ ! -f "$ENV_FILE" ]; then
  step "First run: generating $ENV_FILE with a random UI password"
  if command -v openssl >/dev/null 2>&1; then
    PW=$(openssl rand -hex 12)
  else
    PW=$(dd if=/dev/urandom bs=1 count=16 2>/dev/null | od -An -tx1 | tr -d ' \n')
  fi
  [ -n "${PW:-}" ] || die "could not generate a password - no openssl and /dev/urandom unreadable."
  (umask 077; set -o noclobber; printf 'SANDBOX_USER=sandbox\nSANDBOX_PASSWORD=%s\n' "$PW" > "$ENV_FILE") \
    || die "could not write $ENV_FILE - check permissions on $(pwd)"
fi
chmod 600 "$ENV_FILE" || die "could not restrict .env permissions."
load_credentials "$ENV_FILE" || die ".env must contain unquoted SANDBOX_USER and SANDBOX_PASSWORD values only; shell syntax, whitespace and duplicate keys are rejected."

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
ready=0
deadline=$((SECONDS + 180))
while [ "$SECONDS" -lt "$deadline" ]; do
  if desktop_ready; then ready=1; break; fi
  sleep 2
done

if [ "$ready" -ne 1 ]; then
  printf '\n%sThe desktop did not come up. Recent logs:%s\n\n' "$YLW" "$OFF"
  docker compose logs --tail 40
  die "not ready in time. Check Firefox startup, UI authentication and the Troubleshooting section of README.md."
fi

step "Checking the egress gateway"
docker exec --user 1000:1000 safebrowse curl --disable --silent --show-error --fail \
  --max-time 15 --noproxy '' --proxy http://172.28.0.2:3128 https://example.com/ -o /dev/null \
  || die "desktop is up but gateway access failed. Run ./logs.sh; use ./stop.sh to tear down."

cat <<INFO

  ${GRN}safebrowse is running.${OFF}

    URL       https://127.0.0.1:3011/     (self-signed cert - accept the warning)
    user      ${SANDBOX_USER}
    password  ${SANDBOX_PASSWORD}

  Next:  ./verify.sh     confirm the hardening actually applied
         ./stop.sh       destroy everything

INFO
