# ---------------------------------------------------------------------------
# safebrowse - a disposable, hardened Firefox sandbox reachable from a browser
# tab on the host. Built on the LinuxServer.io Firefox image (Selkies remote
# desktop, audio over the web UI, no X11 or GPU passthrough needed on macOS).
#
# Firefox rather than Chromium because Chromium has removed every supported
# way to run a third-party content blocker outside its own Web Store:
# Manifest V2 is gone, --load-extension is ignored, and Debian's build has no
# Web Store access. Mozilla has committed to keeping MV2, so uBlock Origin
# works here with its full capabilities and is installed through Firefox's
# own enterprise policy mechanism.
# ---------------------------------------------------------------------------
FROM lscr.io/linuxserver/firefox@sha256:bc5b08fa66d505e5a600d474365e57e2d858bcf12d4e80e7c79a3d3dc3b7ca66

ARG UBO_XPI_URL=https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi

USER root

# ---- uBlock Origin, baked into the image so startup needs no network -------
# The build asserts the download really is a Firefox add-on. If Mozilla ever
# moves the URL, this fails loudly at build time rather than producing an
# image whose blocker silently never loads - which is exactly how the
# Chromium version of this failed three times.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates unzip; \
    mkdir -p /opt/extensions; \
    curl -fsSL "${UBO_XPI_URL}" -o /opt/extensions/ublock_origin.xpi; \
    unzip -p /opt/extensions/ublock_origin.xpi manifest.json > /tmp/m.json; \
    grep -q 'uBlock0@raymondhill.net' /tmp/m.json; \
    rm -f /tmp/m.json; \
    chmod 0644 /opt/extensions/ublock_origin.xpi; \
    apt-get purge -y unzip; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*

# ---- Enterprise policy ----------------------------------------------------
# Firefox reads policies.json from /etc/firefox/policies/ and from a
# distribution/ folder beside the binary. The install path varies between
# builds, so resolve it rather than hardcoding, and write to every candidate.
COPY policies/firefox-policies.json /opt/firefox-policies.json
RUN set -eux; \
    install -d -m 0755 /etc/firefox/policies; \
    install -m 0644 /opt/firefox-policies.json /etc/firefox/policies/policies.json; \
    ffbin="$(readlink -f "$(command -v firefox)")"; \
    ffdir="$(dirname "$ffbin")"; \
    echo "firefox resolved to: $ffbin"; \
    for d in "$ffdir/distribution" /usr/lib/firefox/distribution \
             /opt/firefox/distribution /usr/lib/firefox-esr/distribution; do \
      install -d -m 0755 "$d"; \
      install -m 0644 /opt/firefox-policies.json "$d/policies.json"; \
    done; \
    test -s /etc/firefox/policies/policies.json

LABEL org.opencontainers.image.title="safebrowse" \
      org.opencontainers.image.description="Disposable hardened Firefox sandbox for untrusted sites"
