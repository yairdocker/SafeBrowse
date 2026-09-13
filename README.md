# safebrowse

**A disposable, hardened Firefox that runs in a container and renders into a tab
on your machine.** For opening sites you don't trust: it has no access to your
host files through bind mounts, uses a filtered proxy for web access, and starts
with a fresh Firefox profile. Stopping the session discards that profile; this
is not an anonymity service or a secure-erasure tool.

No X11, no XQuartz, no GPU passthrough — the container ships a remote desktop
you open at `https://127.0.0.1:3011/`. Audio works, so video plays with sound.

Built and tested on **macOS + Docker Desktop (Apple Silicon)**. It should run
on Linux and Windows/WSL2, but those platforms have not been runtime-tested.
Requires **Docker Engine 28+**, Compose v2, **Python 3.9+**, Bash and curl on the
host. Isolated bridge mode is required; do not silently fall back to a normal
internal bridge on an older engine.

---

## Quick start

```bash
git clone https://github.com/yairdocker/SafeBrowse.git
cd SafeBrowse
./run.sh        # builds, generates a random UI password, starts, prints the URL
./verify.sh     # checks runtime controls; exit 1 = failure, 2 = inconclusive
```

For an existing installation, run `./stop.sh` once before upgrading so Compose
can recreate the sandbox bridge with isolated gateway mode. This discards the
current session. The launcher refuses an existing bridge with the old mode.

First build pulls roughly 1.5 GB. Open the printed URL, accept the self-signed
certificate warning, log in with the generated credentials, and browse.

```bash
./stop.sh       # destroys the container and everything in it
./logs.sh       # gateway startup, cache and access logs in one place
```

Docker needs about 6 GB of memory allocated (Settings → Resources); the sandbox
alone is capped at 4 GB. `run.sh` warns you if it's lower.

---

## Architecture

```
  your machine
  127.0.0.1:3011 ──► uiproxy ──┐
                               │  safebrowse_sandbox  (internal: true)
                               ├──► safebrowse : Firefox, no route out
                               │         │
                               │         ▼
                               └──► gateway : Squid ──► internet
```

The browser sits on an **internal** Docker network. Docker installs firewall
rules blocking ordinary external routing. Isolated IPv4 gateway mode removes
the bridge's host address, closing the host-service path a plain `internal`
bridge leaves open. IPv6 is disabled on this bridge. Docker DNS remains present
for container names. Firefox web requests use the Squid gateway through locked
enterprise policy; this policy is not a boundary against arbitrary native code.

To expose the desktop while keeping Firefox on the isolated network, a `socat`
container forwards `127.0.0.1:3011` to the browser's remote desktop. It's raw
TCP passthrough, so TLS stays end-to-end.

---

## What is hardened

### Egress — `gateway/squid.conf`

- **Private address space is denied**: `10/8`, `172.16/12`, `192.168/16`,
  `169.254/16`, loopback and the IPv6 equivalents. Your LAN, your NAS, your
  router's admin page and `host.docker.internal` are all unreachable.
  Squid resolves the hostname *then* checks the address, so a DNS-rebinding
  trick pointing a public name at a private IP is blocked too.
- **Only ports 80 and 443 leave**, and `CONNECT` is restricted to 443. No
  proxy connections on other ports. Ports alone do not prevent tunnelling or
  exfiltration over allowed HTTPS connections.
- **All name resolution happens at the gateway**, on filtering resolvers. The
  locked HTTP proxy delegates web hostname resolution to Squid. This does not
  establish that every possible name-resolution channel is absent.
- A domain blocklist at `gateway/blocklist.txt` for anything you specifically
  never want reached.
- `forwarded_for delete`, `via off` — the gateway doesn't announce the sandbox
  upstream.

### Isolation

| Control | Effect |
|---|---|
| No browser bind mounts or persistent volumes | No direct sharing of host files with Firefox. |
| Internal bridge with isolated gateway mode | No ordinary direct external routing or bridge host-service endpoint. |
| No published ports on the browser | Only its network peers, including the UI relay, can normally connect directly. |
| `cap_drop: ALL` + minimum re-add | Six capabilities instead of the default fourteen. |
| `no-new-privileges` | No setuid escalation inside the container. |
| UI bound to `127.0.0.1` | Nothing on your network can reach it. |
| `mem_limit` / `cpus` / `pids_limit` | A cryptominer hits a ceiling instead of your fans. |

### Disposability

The Firefox profile lives on `tmpfs` and is discarded when the container stops.
Tmpfs can be swapped to disk. Container writable layers, host/VM storage and
external DNS/network logs are outside this guarantee; deletion is not secure
erasure.

Squid access logging is disabled by default. Its diagnostic directory is a
bounded tmpfs, and its Docker logging driver is `none` because the upstream
entrypoint also copies logs to stdout. Browser startup logs may still be stored
by Docker. Do not claim that a session leaves no traces.

### Browser policy — `policies/firefox-policies.json`

Configured using Firefox enterprise policy. Check `about:policies` for active
policies and errors after image updates; comparing JSON alone does not prove
that Firefox accepted every policy.

- Notifications, camera, microphone and geolocation blocked and **locked**.
- Popups blocked and locked. (Note: a click opening `target="_blank"` is a
  *navigation*, not a popup — no browser blocks those, which is why the ad
  blocker and the gateway matter.)
- Proxy pinned and locked, with `UseProxyForDNS`. DNS-over-HTTPS disabled and
  locked, so the browser can't route around the gateway.
- Enhanced Tracking Protection on, including cryptomining and fingerprinting.
- Password manager, form history, autofill, Firefox Accounts and telemetry all
  off — there are no credentials in this browser to steal.
- Extension installation blocked except the one force-installed blocker.

### Bridges to your machine

Clipboard sync is **disabled in both directions**, and the microphone is off.
See *Known limitations* for file transfer.

### Supply chain

Upstream image references are committed as digests. `./pin.sh` records digests
from locally cached `:latest` tags without contacting a registry. To deliberately
fetch upstream updates:

```bash
./pin.sh --refresh   # pull all three upstream tags, resolve, then rewrite pins
./run.sh            # rebuild and start; this can replace the current session
./verify.sh         # open a page first; resolve failures/inconclusive checks
```

Do not use `docker compose pull` to refresh pins: it pulls the references already
in Compose, and does not update the Dockerfile's base image. All resolutions and
replacement checks must succeed before pinning writes any files. Updates do not
automatically change running containers. Review the diff and validate the new
image before committing the pins.

uBlock Origin **1.74.0** is pinned to a versioned Mozilla download URL and SHA-256
in `Dockerfile`. The build rejects a hash mismatch before extracting the XPI.
The recorded hash matches Mozilla's [version metadata](https://addons.mozilla.org/api/v5/addons/addon/ublock-origin/versions/?page_size=5).
To update it, independently review the version and change both `UBO_XPI_URL` and
`UBO_XPI_SHA256`; changing only the URL must fail. Browser and extension app
updates are disabled, so schedule deliberate image/blocker maintenance. A digest
pins an artifact; it does not establish that artifact is vulnerability-free.

---

## Verification

`verify.sh` reads Docker JSON, checks the exact network membership, bridge mode,
UI binding, mounts, capability allowlist and resource limits, and attempts direct
TCP and proxied requests. It runs browser probes as UID 1000. It also compares the
deployed policy JSON, checks active uBlock profile registration, attempts a user
namespace, and examines observed Firefox content-process seccomp/no-new-privileges
flags. These are bounded checks, not a full security certification.

- Exit **0**: all automated checks passed.
- Exit **1**: at least one verified check failed.
- Exit **2**: no failure was observed, but a required check was inconclusive.

A missing probe, absent add-on registration, unknown clipboard direction or
unreadable process state must not produce a pass. Open a normal page and rerun
if Firefox has not yet created its content processes or profile records.

For proxy denials, only a completed `403` with Squid's `ERR_ACCESS_DENIED` header counts
as policy-denial evidence. An origin server's `403` is insufficient. A `503`,
timeout or DNS error is inconclusive; an unavailable target
does not prove that an ACL works. The `localtest.me` check tests a hostname that
resolves to loopback; it is not a comprehensive changing-DNS/rebinding test.

After browser/image changes, also manually inspect `about:policies` for errors
and `about:support` for sandbox details, and test clipboard and permission prompts
through the desktop. The verifier cannot establish these UI behaviors from a
configuration file or startup log alone.

Run offline regression tests with:

```bash
python3 -m unittest discover -s tests -v
```

---

## Why Firefox, not Chromium

This started on Chromium. It doesn't work there any more, and the reasons
aren't well documented in one place:

1. **Manifest V2 is gone.** uBlock Origin is MV2. Chromium 139+ removed MV2
   support outright, and the `ExtensionManifestV2Availability` policy that used
   to re-enable it no longer exists.
2. **`--load-extension` is ignored.** Chrome 137 disabled the switch. The
   `--disable-features=DisableLoadExtensionCommandLineSwitch` workaround stops
   working once the feature itself is removed.
3. **No Web Store access.** `ExtensionInstallForcelist` is the supported path,
   but Debian's Chromium build ships without Google API keys, so force-install
   downloads nothing.

Each failure is **silent** — the browser starts normally and simply has no
content blocker. Mozilla has committed to keeping MV2, so Firefox runs the full
uBlock Origin, installed via its own `ExtensionSettings` policy.

Firefox also doesn't implement WebUSB, Web Serial, Web Bluetooth or the File
System Access API at all, so several things that needed explicit blocking in
Chromium simply don't exist here.

---

## Known limitations

Stated plainly, because a control you *think* you have is worse than one you
know you don't.

- **File transfer via the remote desktop sidebar cannot be disabled.** The
  upstream image rejects both documented values (`none` and empty) and falls
  back to `upload,download`. The panel is hidden, but that's cosmetic. It is
  still an available data-transfer channel. Hiding the panel is not enforcement;
  do not treat it as a disabled capability.
- **Firefox has no download-blocking policy.** Downloads are pointed at a
  non-existent locked directory, which is friction rather than a hard block.
  The real protection is the tmpfs profile and the absence of any bind mount.
- **Container escape is not impossible.** Docker Desktop runs containers in a
  Linux VM, which is a real boundary — but a kernel exploit chain gets an
  attacker into that VM. This is strong isolation, not a guarantee.

---

## Threat model

**Designed for:** malvertising, drive-by redirects, popunders, push-notification
spam, fingerprinting and tracking, hostile JavaScript, and anything that wants
to reach your filesystem or your LAN.

**Does not help with:**

- **You, deciding to log into something.** All of it is worth nothing the
  moment you sign into an account inside the sandbox.
- **Social engineering that reaches past the browser** — a page telling you to
  call a number or run something on your real machine.
- **Your machine as a source.** Compromised code inside can still reach the
  internet on 80/443. It can't touch your files or LAN, but traffic comes from
  your IP.
- **Legal exposure.** A container changes technical risk and nothing else.

---

## Files

```
Dockerfile                      base image + uBlock Origin + policy install
docker-compose.yml              topology, isolation, tmpfs, caps, limits
policies/firefox-policies.json  Firefox enterprise policy
gateway/squid.conf              egress rules: no private space, no odd ports
gateway/blocklist.txt           extra domains to refuse
run.sh / stop.sh                launch and destroy
pin.sh / scripts/pin.py         pin cached images; --refresh pulls updates
verify.sh / scripts/verify.py   structured runtime checks and live egress tests
tests/test_security.py         offline regression tests
.dockerignore                  allowlist of build inputs; excludes .env and .git
logs.sh                         gateway startup, cache and access logs
```

---

## Troubleshooting

**A tab crashes on rich pages.** `seccomp=unconfined` is a compatibility
exception: Docker's default filter prevented user namespace creation on the
tested host. This removes an outer defense for the whole browser container.
The verifier probes namespace creation as Firefox's UID and checks observed
content-process filters. That does not prove complete process isolation. A
narrower custom profile needs its own Firefox/runtime testing; do not add
`SYS_ADMIN` as a shortcut. Keep Docker Desktop and its kernel updated.

**Nothing loads at all.** Check the gateway first: `./logs.sh`. Squid refusing
everything usually means the sandbox subnet in `squid.conf`
(`acl sandbox src 172.28.0.0/24`) no longer matches the one in
`docker-compose.yml`. They must agree.

**A site you need is half-broken.** `./logs.sh` shows memory-backed gateway
diagnostics. Access logs are off by default. For temporary request diagnostics,
change `access_log none` to `access_log stdio:/var/log/squid/access.log` in
`gateway/squid.conf`, then recreate the gateway. Logs contain browsing metadata,
use a bounded tmpfs and disappear when that container stops. Restore `none`
after debugging; a full diagnostic filesystem can interrupt the proxy.

**The ad blocker isn't active.** Check `about:policies` and the extension manager.
The verifier rejects disabled registrations and reports an absent/unreadable
registration as inconclusive. Load a page and rerun; rebuild if it remains absent.

**Playback is choppy.** The remote desktop encodes H.264 on CPU with no GPU
passthrough, so pixel count is the cost driver. Drop the resolution in the
sidebar's screen settings.

**You need a file out.** You shouldn't, from an untrusted site. If the reason is
legitimate, unlock `browser.download.dir` in the policy file, add a bind mount
to a dedicated empty folder, and treat whatever lands there as hostile.

---

## License

MIT — see [LICENSE](LICENSE).

## Local credentials

`run.sh` generates `.env` with mode 0600 before writing the password. It parses
this file as data and exports the same values to Compose; it never sources it
as shell code. Use unquoted `SANDBOX_USER` and `SANDBOX_PASSWORD` entries only.
Usernames allow letters, digits, `_`, `.`, `-`; passwords additionally allow
`+`, `/`, `:`, `@`, `%`. Whitespace, shell substitutions, duplicate or unknown
keys are rejected. The default generated hex password is supported.

The build context is an allowlist containing only `Dockerfile` and the Firefox
policy file, so `.env`, Git history and local scratch files never enter the build.
