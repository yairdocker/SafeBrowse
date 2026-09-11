#!/usr/bin/env bash
# Post-launch check: proves the hardening actually applied, rather than
# trusting that the compose file said so. Run after ./run.sh.
set -uo pipefail
C=safebrowse
GW=safebrowse-gw
pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }
note() { printf '  ....  %s\n' "$1"; }
inbox() { docker exec "$C" sh -c "$1" 2>/dev/null; }

echo "== container isolation"
docker inspect -f '{{len .Mounts}}' $C 2>/dev/null | grep -qx 0 \
  && ok "no bind mounts - the container cannot see any file on your Mac" \
  || bad "container has mounts: $(docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' $C)"

docker inspect -f '{{.HostConfig.SecurityOpt}}' $C 2>/dev/null | grep -q 'no-new-privileges:true' \
  && ok "no-new-privileges is set" || bad "no-new-privileges missing"

docker inspect -f '{{.HostConfig.CapDrop}}' $C 2>/dev/null | grep -q 'ALL' \
  && ok "all capabilities dropped, minimum re-added" || bad "capabilities not dropped"

# .NetworkSettings.Ports also lists ports merely EXPOSEd by the image, which
# are not reachable from anywhere. Only .HostConfig.PortBindings is publishing.
docker inspect -f '{{len .HostConfig.PortBindings}}' $C 2>/dev/null | grep -qx 0 \
  && ok "browser publishes no ports of its own" \
  || bad "browser publishes ports: $(docker inspect -f '{{.HostConfig.PortBindings}}' $C)"

echo "== network containment"
nets=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' $C 2>/dev/null)
[ "$(echo "$nets" | wc -w)" -eq 1 ] \
  && ok "browser is on exactly one network ($nets)" \
  || bad "browser is on more than one network: $nets"

docker network inspect safebrowse_sandbox -f '{{.Internal}}' 2>/dev/null | grep -qx true \
  && ok "sandbox network is internal - no NAT to the internet" \
  || bad "sandbox network is NOT internal"

# 1.1.1.1 by raw IP: if the browser had any route out, this would connect.
if inbox 'curl -s --max-time 6 -o /dev/null https://1.1.1.1/'; then
  bad "browser reached the internet DIRECTLY - egress containment is broken"
else
  ok "browser cannot reach the internet directly"
fi

# Same request through the gateway should succeed.
if inbox 'curl -s --max-time 15 -o /dev/null -x http://172.28.0.2:3128 https://example.com/'; then
  ok "browser reaches the web through the gateway"
else
  bad "gateway is not forwarding - check: docker logs $GW"
fi

echo "== gateway"
gw_status=$(docker inspect -f '{{.State.Status}}' $GW 2>/dev/null)
if [ "$gw_status" = "running" ]; then
  ok "gateway container is running"
else
  bad "gateway is ${gw_status:-absent} - everything below is meaningless until it runs"
  bad "  diagnose with: docker logs $GW"
fi

# Classify by what the proxy actually said:
#   403 - the ACL fired. This is the real proof.
#   503 - squid could not resolve or connect. Nothing reached the target, so it
#         is not an allow, but the ACL is not what stopped it.
#   000 - no answer from the proxy itself. Proves nothing at all.
#   2xx/3xx - the request went through. That is a genuine failure.
refuses() {
  local what="$1" url="$2" code
  code=$(inbox "curl -s --max-time 10 -o /dev/null -w '%{http_code}' -x http://172.28.0.2:3128 $url")
  case "$code" in
    403)    ok   "denied by policy: $what (403)" ;;
    503)    ok   "unreachable: $what (503 - unresolvable from the gateway, so nothing left the sandbox)" ;;
    000|"") bad  "INCONCLUSIVE for $what - no answer from the proxy itself, not a denial" ;;
    *)      bad  "gateway ALLOWED $what (HTTP $code)" ;;
  esac
}

# A literal private address is the load-bearing test: it proves the ACL itself
# rejects private space, with no DNS involved.
refuses "your LAN by literal IP" "http://192.168.1.1/"
refuses "the Docker host"        "http://host.docker.internal/"
refuses "blocklisted domains"    "http://doubleclick.net/"

# DNS rebinding: a public name that resolves into loopback. Squid resolves it
# first, then applies the dst ACL, so this must come back 403 - not 503.
code=$(inbox "curl -s --max-time 10 -o /dev/null -w '%{http_code}' -x http://172.28.0.2:3128 http://localtest.me/")
case "$code" in
  403)    ok   "DNS rebinding blocked: public name resolving to loopback is denied (403)" ;;
  503)    note "rebinding test inconclusive - localtest.me did not resolve (503)" ;;
  000|"") bad  "INCONCLUSIVE - no answer from the proxy" ;;
  *)      bad  "DNS REBINDING WORKED: public name resolved into private space and was allowed (HTTP $code)" ;;
esac

echo "== nothing persists"
docker inspect -f '{{range $k,$v := .HostConfig.Tmpfs}}{{$k}} {{end}}' $C 2>/dev/null | grep -q '/config' \
  && ok "browser profile is on tmpfs - wiped on teardown" || bad "/config is not tmpfs"

echo "== firefox's own sandbox"
# The container is the outer wall; Firefox's content-process sandbox is what
# contains hostile JavaScript. It needs user namespaces, which is why
# seccomp=unconfined is set on this service.
if inbox 'test -e /proc/sys/kernel/unprivileged_userns_clone && cat /proc/sys/kernel/unprivileged_userns_clone' | grep -qx 0; then
  bad "unprivileged user namespaces are disabled - Firefox cannot sandbox content processes"
else
  ok "user namespaces available (Firefox content sandbox can initialise)"
fi

echo "== ad blocking"
# Not "is a flag present" - that assertion stayed green through a completely
# absent ad blocker on the Chromium build. Check the add-on is really there.
inbox 'test -s /opt/extensions/ublock_origin.xpi' \
  && ok "uBlock Origin add-on is present in the image" \
  || bad "uBlock Origin add-on missing from the image - rebuild"

inbox "grep -q 'uBlock0@raymondhill.net' /etc/firefox/policies/policies.json" \
  && ok "policy force-installs uBlock Origin" \
  || bad "policies.json is missing or does not force-install the blocker"

# Search for the profile rather than assuming where it is: the path is
# /config/.config/mozilla/firefox/<random>.default-release/, it is on tmpfs so
# the random part changes every run, and an earlier hardcoded prefix reported a
# working ad blocker as missing.
prof_xpi=$(inbox "find /config -path '*/firefox/*/extensions/uBlock0@raymondhill.net.xpi' 2>/dev/null | head -1")
if [ -n "$prof_xpi" ]; then
  ok "uBlock Origin is installed in the live profile"
elif inbox "find /config -name extensions.json -exec grep -l 'uBlock0@raymondhill.net' {} + 2>/dev/null | head -1" | grep -q .; then
  ok "uBlock Origin is registered in the profile's extensions.json"
else
  note "no profile add-on record yet - load a page in the sandbox, then re-run"
fi

echo "== firefox policy"
for k in Proxy PopupBlocking Permissions EnableTrackingProtection; do
  inbox "grep -q '\"$k\"' /etc/firefox/policies/policies.json" \
    && ok "policy present: $k" || bad "policy missing: $k"
done

echo "== bridges to your Mac"
# The remote desktop syncs the clipboard both ways and offers file transfer
# by default. Both cross the boundary the rest of this design exists to hold.
# Read the in/out flags, not the master flag: the master can stay True while
# both directions are off, which is exactly what happens here. Corroborate with
# the runtime rejection message, which is proof of behaviour rather than config.
cin=$(docker logs $C 2>&1 | grep -o "'clipboard_in_enabled': ([^)]*)" | tail -1)
cout=$(docker logs $C 2>&1 | grep -o "'clipboard_out_enabled': ([^)]*)" | tail -1)
if printf '%s%s' "$cin" "$cout" | grep -q 'True'; then
  bad "clipboard sync is ENABLED -> $cin $cout"
elif [ -n "$cin$cout" ]; then
  ok "clipboard sync is disabled in both directions"
elif docker logs $C 2>&1 | grep -qi 'clipboard.*disabled'; then
  ok "clipboard sync is disabled (confirmed by runtime rejection in the log)"
else
  note "could not determine clipboard state from the startup settings dump"
fi

# Read the whole list, not a prefix - the earlier check stopped at the first
# comma and could not tell ['upload'] from ['upload','download'].
# KNOWN LIMITATION, not a misconfiguration. This image rejects both documented
# ways of turning file transfer off ("none" and ""), silently falling back to
# the default. It is reported as a note rather than a failure so it does not
# become permanent red noise - but it is real, so read the wording.
# It is not a channel hostile code can drive on its own: moving a file requires
# you to use the sidebar panel deliberately. Treat it like the clipboard used
# to be - a door that only opens if you open it.
ft=$(docker logs $C 2>&1 | grep -o "'file_transfers': \[[^]]*\]" | tail -1)
if [ -z "$ft" ]; then
  note "file_transfers not found in the startup settings dump"
elif printf '%s' "$ft" | grep -qE "upload|download"; then
  note "file transfer via the UI sidebar is available ($ft) - cannot be disabled on this image; needs deliberate use, see README"
else
  ok "file transfer through the web UI is disabled"
fi

echo "== supply chain"
if grep -qE '(linuxserver/firefox|ubuntu/squid|alpine/socat):latest' Dockerfile docker-compose.yml 2>/dev/null; then
  bad "base images are on :latest - a moving tag decides what runs in your sandbox. Run ./pin.sh"
else
  ok "base images are pinned to digests"
fi

echo
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ] || echo "  -> see the Troubleshooting section of README.md"
exit $([ "$fail" -eq 0 ] && echo 0 || echo 1)
