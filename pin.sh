#!/usr/bin/env bash
# Pin every upstream base image to the exact digest currently on this machine.
#
# Why: the build pulls four things from the internet - the LinuxServer Firefox
# image, Squid, socat, and the uBlock Origin add-on. A `:latest` tag is a
# moving target: whoever controls that tag controls what runs inside your
# sandbox on your next rebuild. A digest is content-addressed and cannot be
# changed under you.
#
# Run this once after a successful build. Re-run it deliberately when you want
# to take upstream updates (`docker compose pull` first, then this).
set -uo pipefail
cd "$(dirname "$0")" || exit 1

RED=$'\033[31m'; GRN=$'\033[32m'; CYN=$'\033[36m'; OFF=$'\033[0m'
step() { printf '%s==>%s %s\n' "$CYN" "$OFF" "$1"; }
die()  { printf '\n%sERROR%s  %s\n\n' "$RED" "$OFF" "$1" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not on PATH"
docker info >/dev/null 2>&1 || die "Docker daemon not responding - start Docker Desktop"

pin_one() {
  repo="$1"; file="$2"
  step "Resolving $repo"

  docker image inspect "$repo:latest" >/dev/null 2>&1 || {
    printf '    not present locally, pulling...\n'
    docker pull "$repo:latest" >/dev/null 2>&1 || { printf '    %sFAILED to pull%s\n' "$RED" "$OFF"; return 1; }
  }

  full=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$repo:latest" 2>/dev/null \
          | grep "^${repo}@sha256:" | head -1)
  [ -n "$full" ] || { printf '    %sno digest available%s (image built locally, not pulled?)\n' "$RED" "$OFF"; return 1; }

  # Escape regex-significant characters in the repo path.
  esc=$(printf '%s' "$repo" | sed 's/[.[\*^$]/\\&/g')

  before=$(grep -c "$repo" "$file" 2>/dev/null || echo 0)
  sed -E -i.bak "s#${esc}(:[A-Za-z0-9._-]+|@sha256:[0-9a-f]{64})#${full}#g" "$file" \
    || { printf '    %srewrite failed%s\n' "$RED" "$OFF"; return 1; }
  rm -f "${file}.bak"

  printf '    %spinned%s in %s (%s reference(s))\n' "$GRN" "$OFF" "$file" "$before"
  printf '%s\n' "$full" >> PINS.txt
  return 0
}

: > PINS.txt
{
  printf '# Image digests pinned on %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf '# Regenerate with ./pin.sh after `docker compose pull`.\n'
} >> PINS.txt

fails=0
pin_one lscr.io/linuxserver/firefox Dockerfile        || fails=$((fails+1))
pin_one ubuntu/squid                docker-compose.yml || fails=$((fails+1))
pin_one alpine/socat                docker-compose.yml || fails=$((fails+1))

echo
if grep -qE '(lscr\.io/linuxserver/firefox|ubuntu/squid|alpine/socat):latest' Dockerfile docker-compose.yml 2>/dev/null; then
  printf '%sSome images are still on :latest%s\n' "$RED" "$OFF"
  grep -nE ':latest' Dockerfile docker-compose.yml
  exit 1
fi

[ "$fails" -eq 0 ] || die "$fails image(s) could not be pinned - see above"

step "All base images pinned. Digests recorded in PINS.txt"
printf '\n    The uBlock Origin add-on is fetched by URL at build time and cannot be\n'
printf '    digest-pinned the same way; the build asserts its extension ID instead.\n'
printf '    To pin it too, download the .xpi, drop it beside this script, and\n'
printf '    point UBO_XPI_URL at file:///opt/... in the Dockerfile.\n\n'
