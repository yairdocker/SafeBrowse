#!/usr/bin/env bash
# safebrowse - build and launch the disposable browsing sandbox.
# No `set -e`: every step is checked explicitly so failures explain themselves.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
# shellcheck source=scripts/launch-lib.sh
. ./scripts/launch-lib.sh
# Ignore inherited Compose addressing; the launcher owns these values.
unset SANDBOX_SUBNET SQUID_CONFIG_PATH

RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; CYN=$'\033[36m'; OFF=$'\033[0m'
step() { printf '%s==>%s %s\n' "$CYN" "$OFF" "$1"; }
warn() { printf '%sWARNING%s %s\n' "$YLW" "$OFF" "$1"; }
die()  { printf '\n%sERROR%s  %s\n\n' "$RED" "$OFF" "$1" >&2; exit 1; }
set_network() {
  SANDBOX_SUBNET=$(python3 scripts/network.py "$@") || die "could not prepare the isolated sandbox network."
  SQUID_CONFIG_PATH="$(pwd)/.runtime/squid.conf"
  export SANDBOX_SUBNET SQUID_CONFIG_PATH
}

usage() {
  cat <<'HELP'
Usage: ./run.sh [--fresh | --resume] [--url https://example.com/]
  No session exists: build and start a new disposable session.
  --fresh   Build, then destroy any existing session and start with an empty profile.
  --resume  Verify and use the existing running session; do not rebuild or restart it.
  --url     Open one HTTP(S) URL inside Firefox after all automated checks pass.
  --help    Show this help without contacting Docker.
HELP
}
mode=; target_url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --fresh|--resume)
      [ -z "$mode" ] || die "choose --fresh or --resume once."
      mode=$1; shift ;;
    --url)
      [ "$#" -ge 2 ] && [ -n "$2" ] && [ -z "$target_url" ] || die "--url requires one URL and may appear only once."
      target_url=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; die "unknown argument; see usage above." ;;
  esac
done

# --------------------------------------------------------------------------
# Preflight - fail with a sentence you can act on, not a stack trace
# --------------------------------------------------------------------------
step "Checking prerequisites"
for tool in docker curl python3; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required. Install it and retry."
done
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || die "Python 3.9+ is required."
if [ -n "$target_url" ]; then
  python3 scripts/open_url.py --validate "$target_url" || die "invalid --url; session unchanged."
fi
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
if bridge_mode=$(docker network inspect safebrowse_sandbox \
  -f '{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}' 2>/dev/null); then
  [ "$bridge_mode" = isolated ] || [ "$mode" = --fresh ] || die "existing sandbox bridge needs migration: ./stop.sh discards the current session, then rerun ./run.sh."
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
  [ "$mode" != --resume ] || die "cannot resume without the original .env credentials."
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
existing=$(docker compose ps --all --quiet) || die "could not inspect existing session."
if [ -n "$existing" ] && [ -z "$mode" ]; then
  die "a session already exists. Use --resume to keep it or --fresh to discard its profile."
fi
# Use the current config for build/down when replacing or cleaning up a session.
# A missing or damaged state file must not prevent --fresh from recovering it.
if [ "$mode" != --resume ] && [ -f .runtime/network.json ]; then
  if saved_subnet=$(python3 scripts/network.py current 2>/dev/null); then
    SANDBOX_SUBNET=$saved_subnet
    SQUID_CONFIG_PATH="$(pwd)/.runtime/squid.conf"
    export SANDBOX_SUBNET SQUID_CONFIG_PATH
  fi
fi
if [ "$mode" = --resume ]; then
  [ -n "$existing" ] || die "no session exists to resume. Run ./run.sh to create one."
  set_network current
  # Never let Compose recreate an existing profile while claiming to resume it.
  running=$(docker inspect --format '{{.State.Running}}' safebrowse safebrowse-gw safebrowse-ui) \
    || die "session is incomplete; use --fresh to replace it."
  [ "$running" = $'true\ntrue\ntrue' ] || die "session is not running; use --fresh to create a new profile."
  step "Resuming the existing profile and tabs"
else
  step "Building image (first build pulls ~1.5 GB and takes a few minutes)"
  docker compose build \
    || die "build failed; existing session was not discarded. Check the output above."
  if [ "$mode" = --fresh ]; then
    step "Discarding the previous session and its profile"
    docker compose down --volumes --remove-orphans || die "could not discard the previous session."
  else
    # A failed earlier launch may have left Compose networks but no containers.
    docker compose down --volumes --remove-orphans || die "could not clear partial Compose networks."
  fi
  up_log=$(mktemp) || die "could not create a temporary startup log."
  trap 'rm -f "$up_log"' EXIT
  skipped=()
  started=0
  for attempt in 1 2 3; do
    if [ "$attempt" -eq 1 ]; then
      set_network select
    else
      set_network select "${skipped[@]}"
    fi
    step "Starting a fresh session on $SANDBOX_SUBNET"
    if docker compose up -d >"$up_log" 2>&1; then
      cat "$up_log"
      started=1
      break
    fi
    cat "$up_log"
    if [ "$attempt" -lt 3 ] && grep -Eqi 'invalid pool request|pool overlaps' "$up_log"; then
      warn "Docker rejected $SANDBOX_SUBNET; trying another subnet."
      docker compose down --volumes --remove-orphans || die "could not clean up the failed network attempt."
      skipped+=(--skip "$SANDBOX_SUBNET")
    else
      docker compose logs --tail 40
      die "containers failed to start (logs above)."
    fi
  done
  [ "$started" -eq 1 ] || die "Docker rejected every attempted sandbox subnet."
  rm -f "$up_log"
  trap - EXIT
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

step "Desktop running; checking containment and browser controls"
# A blank tab creates content processes without visiting the requested site.
step "Waiting for Firefox (up to 60 seconds)"
firefox_ready=0
deadline=$((SECONDS + 60))
while [ "$SECONDS" -lt "$deadline" ]; do
  if python3 scripts/open_url.py --initialize >/dev/null 2>&1; then
    firefox_ready=1
    break
  fi
  sleep 2
done
[ "$firefox_ready" -eq 1 ] || die "desktop is running but Firefox could not initialize; requested URL was not opened."
./verify.sh --wait-browser
verification=$?
case "$verification" in
  0) step "All automated checks passed" ;;
  2) printf '\nVerification incomplete; requested URL was not opened. Run ./verify.sh or ./stop.sh.\n' >&2; exit 2 ;;
  *) die "verification failed; requested URL was not opened. Run ./verify.sh or ./stop.sh." ;;
esac
if [ -n "$target_url" ]; then
  python3 scripts/open_url.py "$target_url" || die "checks passed, but Firefox could not open the requested URL."
  step "Requested URL sent to Firefox"
fi

cat <<INFO

  ${GRN}safebrowse is running; automated checks passed.${OFF}

    URL       https://127.0.0.1:3011/     (self-signed cert - accept the warning)
    user      ${SANDBOX_USER}
    password  ${SANDBOX_PASSWORD}

  Next:  ./run.sh --resume --url https://example.com/   keep this session
         ./run.sh --fresh                               discard it and start fresh
         ./stop.sh                                     destroy the session

INFO
