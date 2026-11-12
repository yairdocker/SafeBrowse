# safebrowse

**A disposable, hardened Firefox that runs in a container and renders into a tab
on your machine.** For opening sites you don't trust: it has no access to your
host files through bind mounts, uses a filtered proxy for web access, and starts
with a fresh Firefox profile. Stopping the session discards that profile; this
is not an anonymity service or a secure-erasure tool.

Optionally, the gateway can reach the internet **only through a WireGuard
tunnel** (initially: a configuration exported from Mullvad), without touching
the rest of your computer's networking. See [VPN_SECURITY.md](VPN_SECURITY.md).
The default remains a direct connection.

No X11, no XQuartz, no GPU passthrough — the container ships a remote desktop
you open at `https://127.0.0.1:3011/`. Audio works, so video plays with sound.

Built and tested on **macOS + Docker Desktop (Apple Silicon)**. Native Linux
has a defined target (Ubuntu 24.04 with a rootful Docker Engine) but **has not
been run there**, so treat it as experimental; see
[LINUX_SECURITY.md](LINUX_SECURITY.md). Windows and WSL2 are not supported.

Requires **Docker Engine 28+**, Compose v2 and **Python 3.12+** on the host.
Bash is needed only for the `./*.sh` commands, which are thin wrappers; curl is
no longer needed to launch. Isolated bridge mode is required; do not
silently fall back to a normal internal bridge on an older engine.

Run it as your normal user. `./run.sh` and `./pin.sh` refuse to run as root or
with `sudo`, and `./run.sh` refuses a rootless Docker daemon or one that
reports no seccomp support. Those refusals happen before anything is created.

---

## Quick start

```bash
git clone https://github.com/yairdocker/SafeBrowse.git
cd SafeBrowse
./run.sh --fresh --url https://example.com/  # new profile; verify before opening the site
```

Choose the session lifecycle explicitly:

```bash
./run.sh                               # first launch, only if no session exists
./run.sh --resume --url https://example.com/  # keep current profile and tabs
./run.sh --fresh                        # build, discard old session, start empty, same mode
```

Choose the mode explicitly too. A first session is direct unless you ask for a
VPN, `--resume` keeps the session's mode, `--fresh` without a mode option keeps
it as well, and changing modes always needs `--fresh` with the new mode:

```bash
./run.sh --vpn mullvad --vpn-config ~/mullvad/se-got-wg-001.conf   # new VPN session
./run.sh --fresh --direct                                          # replace it with a direct one
./run.sh --fresh --vpn mullvad --vpn-config ~/mullvad/se-got-wg-001.conf
```

A VPN session is never replaced by a direct one unless you type `--direct`, and
if the tunnel is down nothing leaves: there is no fallback. The full rules, the
setup steps and what has and has not been verified are in
[VPN_SECURITY.md](VPN_SECURITY.md).

All host logic lives in one Python entry point, `scripts/safebrowse.py`, with the
subcommands `run`, `stop`, `verify`, `logs` and `pin`. The shell commands only
locate `python3`, pass their arguments through unchanged and return its exit
status, so these are equivalent:

```bash
./run.sh --resume --url https://example.com/
python3 scripts/safebrowse.py run --resume --url https://example.com/
```

Either form works from any directory. The Python entry point has only been
runtime-tested on macOS, with Python 3.12 and 3.14. It has not been run on a
Linux host: CI is configured for Ubuntu 24.04, but no passing run has been
observed yet. It does not make Windows a supported host.

If a session already exists, a plain `./run.sh` refuses to replace or reuse it.
`--resume` requires all session containers to be running and never rebuilds or
restarts them. `--fresh` builds before discarding the old session, so a failed
build preserves it. Once teardown begins, startup failures cannot restore the
old profile. After the teardown the launcher looks for the session's containers
again before it deletes anything that belonged to them or starts anything new.
If some still exist (for example because the checkout directory was renamed, so
they belong to another Compose project and Compose left them alone), or Docker
cannot say, it stops there, removes nothing of theirs and tells you how to
remove them. The login credentials in `.env` remain the same across sessions.
`--fresh` also recreates an older sandbox bridge with isolated gateway mode.
The launcher selects an unused private `/24` for that bridge, retries a Docker
pool collision with another subnet, and stores its choice in the ignored
`.runtime/` directory. `--resume` reuses the selected network; the desktop URL
stays on `127.0.0.1:3011`. Run `./run.sh` rather than `docker compose up` to get
automatic subnet selection.

The launcher waits for authenticated desktop readiness, opens a blank tab, and
runs all automated verification checks. The requested URL is sent to Firefox
only after they all pass. A failed check exits **1**; incomplete verification
exits **2**. The containers remain available for diagnosis using `./verify.sh`
and can be removed with `./stop.sh`. This gate does not prevent someone from
manually using the running desktop before verification finishes.

`--url` accepts one absolute HTTP(S) URL without embedded credentials, whitespace
or backslashes. Quote URLs containing shell metacharacters. URLs are passed as
separate arguments to Firefox, never interpolated into shell code or
`FIREFOX_CLI`.

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
for container names. For any other name, the only place Docker's resolver is
allowed to pass a query on to is the browser container's own loopback address
(`dns: 127.0.0.1`), where nothing listens, so the query is refused inside the
container. Firefox web requests use the Squid gateway through locked
enterprise policy. The policy uses Docker's `gateway` service name, while the
launcher writes a Squid source ACL for the selected bridge subnet. The policy
is not a boundary against arbitrary native code.

To expose the desktop while keeping Firefox on the isolated network, a `socat`
container forwards `127.0.0.1:3011` to the browser's remote desktop. It's raw
TCP passthrough, so TLS stays end-to-end.

That is the direct topology, `docker-compose.yml`. In VPN mode the launcher
selects `docker-compose.vpn.yml` instead: Squid runs inside a VPN container's
network namespace, whose firewall lets it talk only to the browser and into the
tunnel. The two files are complete topologies, never layered; what the services
run is defined once in `compose.services.yml`. Inherited `COMPOSE_*` variables
are ignored, and every Compose command names its file explicitly.

The browser's timezone is **UTC** in every session (it was the maintainer's
local zone before), so the clock zone a site can read says nothing about where
you are or which network you leave by. That removes one signal; it is not
fingerprinting protection.

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
| Seccomp profile `security/seccomp-firefox.json` | Docker's default syscall filter plus three calls Firefox's own sandbox needs. Replaces the earlier `seccomp=unconfined`. |
| AppArmor `docker-default` (Linux hosts with AppArmor) | Docker's default container profile; expected on Ubuntu, not available in Docker Desktop. Not yet observed. |
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
from locally cached tags (`:latest`, or Gluetun's release tag) without
contacting a registry. To deliberately fetch upstream updates:

```bash
./pin.sh --refresh   # pull every upstream tag, resolve, then rewrite pins
./run.sh --fresh    # rebuild, discard old session, start and verify
./verify.sh         # rerun checks at any time
```

Four images are pinned: Firefox, Squid, socat and, for VPN mode, Gluetun. The
first three follow their `:latest` tags when refreshed. Gluetun is held at a
reviewed release (see [VPN_SECURITY.md](VPN_SECURITY.md)); a refresh re-resolves
that release tag, and moving to another release is an edit to `scripts/pin.py`.
The verifier fails if a `FROM` line in the Dockerfile or an `image:` line in a
Compose file names an image that is not one of those four, or if `PINS.txt`
disagrees. It reads those two line forms as the files are written today; it is
not a Dockerfile or YAML parser, so it does not rule out every other way such a
file could name an image (`COPY --from=`, a lower-case `from`, a quoted key).

Pulls, builds and pin refreshes are made by Docker on your computer's own
connection. They are never routed through a session's VPN.

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
flags. Startup allows up to 30 seconds for initial Firefox profile registration. These are bounded checks, not a full security certification.

The Python probes among those checks run inside the browser container, and that
container's user has a writable home directory. Each probe is therefore started
with `python3 -I` (isolated mode), so Python ignores the user site directory,
every `PYTHON*` environment variable and the working directory when it starts:
a `.pth` file left in that home does not run inside a probe. What a probe prints
is checked against fixed lists, types and ranges before any of it is shown, and
every result is a single printable line; a malformed answer is a failure or an
inconclusive result, never a pass. This closes that one start-up injection path.
It does not make a compromised container trustworthy and it is not tamper-proof
attestation: the probes still run inside the container they examine, where code
already running as the same user may be able to interfere in other ways. The
helper that opens a URL in Firefox (`scripts/open_url.py`) is not a verifier
probe and is not started in isolated mode.

Every session container carries labels saying which session and mode it belongs
to. The verifier treats them as a claim and checks the live topology against it:
a direct session must have a gateway with its own network namespace and no VPN
container; a VPN session must pass the namespace, firewall, tunnel and listener
checks listed in [VPN_SECURITY.md](VPN_SECURITY.md). A session whose labels are
missing or disagree (for example one started by an older version) is reported
as inconclusive and never passes; start a new one with `./run.sh --fresh` and an
explicit mode.

In both modes the verifier reports two DNS results for the browser container.
A lookup that merely fails is not evidence: a resolver elsewhere can receive a
query and answer that the name does not exist, or just be slow.

- **Enforcement.** The container was created with its own loopback address as
  the only DNS forwarding target, its resolver configuration names only
  Docker's resolver (`127.0.0.11`), and Docker's own note in that file lists
  only `127.0.0.1` as a server it may forward to. Missing or contradictory:
  FAIL. Unreadable: INCONCLUSIVE.
- **Behaviour.** The gateway's name resolves, and an external name gets an
  explicit refusal from Docker's resolver. If the external name resolves: FAIL.
  A timeout, an error or a "no such name" answer: INCONCLUSIVE. PASS needs the
  refusal *and* a passing enforcement check.

A session started before this restriction existed fails the enforcement check;
start a new one with `./run.sh --fresh`.

Docker's confinement of the container is checked separately from Firefox's own
sandbox, because a filter on a Firefox content process says nothing about the
container's outer filter. The verifier requires the daemon to support seccomp,
rejects `seccomp=unconfined`, `apparmor=unconfined` and any unreviewed security
option, compares the profile Docker stored for the container with
`security/seccomp-firefox.json` by content, and observes the filter from a
UID 1000 process outside Firefox. On a daemon with AppArmor it requires
`docker-default` in enforce mode. A confirmed missing protection fails;
evidence that cannot be read is inconclusive. Details and limits are in
[LINUX_SECURITY.md](LINUX_SECURITY.md).

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

Run the three real-container suites with Docker running:

```bash
python3 tests/integration.py       # the stack and verifier
python3 tests/cli_integration.py   # the launcher: launch, resume, fresh, stop
python3 tests/integration_vpn.py   # the launcher in VPN mode, against a fixture peer
```

| Suite | Needs on the host, besides Docker, Compose and Python 3.12+ |
|---|---|
| `tests/integration.py` | OpenSSL and curl. Working DNS for one control (see below). |
| `tests/cli_integration.py` | OpenSSL. |
| `tests/integration_vpn.py` | OpenSSL, and a Docker kernel with WireGuard. It builds a small peer image with `apt-get`, so its first run needs network access even when the SafeBrowse images are cached. |

All three build the pinned Firefox image, so a cold machine also needs network
access for that. The VPN suite is the slowest (several minutes).

The first suite builds the pinned Firefox image and derives an isolated fixture from the
production Compose configuration. Unique container/network names, unused
subnets and a temporary localhost desktop port keep it separate from an existing
session. It changes only fixture addressing and test
service wiring; it runs the same verifier with explicit fixture settings.
Local HTTP/TLS servers and a local Squid hosts file make request outcomes
independent of public websites and DNS. Building/pulling images still needs
network access on a cold machine.

The DNS checks use a resolver that records every query it receives, placed on
the browser's own network, and a packet capture inside the browser's network
namespace. Control containers show what the observer and the capture see when
forwarding is allowed, including a "no such name" answer to a query that
demonstrably arrived. One control resolves a name through this computer's own
DNS (`host.docker.internal` on Docker Desktop, otherwise `example.com`), so
that step needs working DNS on the host.

The suite checks authentication, runtime containment, active uBlock registration,
HTTP and certificate-verified HTTPS CONNECT, live private-IP/hostname denial,
restricted ports, actual Firefox navigation, failure with a stopped gateway,
and profile disposal after teardown/recreation. It also starts throwaway
containers without the outer filter, with Docker's built-in filter and with
AppArmor opted out, and requires the verifier to reject each; and it checks
that a blocklisted hostname pointing at a live local server is refused while
another name for the same server is reachable. In the fixture it also plants
Python start-up files as the browser user (a `.pth` file in the user site, a
module on `PYTHONPATH`, a module in a writable working directory), shows that
ordinary Python runs each one, and requires that the verifier's probes and a
complete verification do not. It removes its own containers,
networks and image in a `finally` block. Build caches may remain; a hard kill or
Docker daemon failure can prevent cleanup. It does not verify the desktop UI's
clipboard behavior or prove that every uBlock filter is effective.

`tests/cli_integration.py` drives the real launcher code through plain launch,
refusal of an existing session, `--resume`, refusal of a stopped session,
`--fresh`, `verify`, `logs` and `stop`, checking that resume leaves container
IDs and start times unchanged and that fresh discards the profile. The launcher
runs unmodified; only the names it acts on are replaced, from Python, with a
uniquely named Compose project, containers, networks, localhost port and a
temporary state directory. No command-line option or environment variable
selects a fixture. Before starting anything the test confirms that its
effective Compose configuration contains no production name, port or path, and
afterwards that the real `.env` and `.runtime/` files are unchanged. It uses the
same local targets and verifier settings as the suite above, so it does not
exercise the production `verify.py` and `open_url.py` command lines.

`tests/integration_vpn.py` does the same for VPN mode against a WireGuard peer
that is another container, with keys generated for the run. It uses the
production parser, generated configuration, pinned Gluetun image, Compose
topology, firewall rules and verifier; only names, port, state directory and the
permission to use a private endpoint are fixture settings, set in Python. It
injects faults (route loss, interface removal, peer outage, container restart,
stop/start and recreation) from a helper container and records every packet on
the VPN container's egress interface. Its results on macOS are summarised in
[VPN_SECURITY.md](VPN_SECURITY.md).

GitHub Actions is configured to run the offline tests on `ubuntu-24.04` with
Python 3.12 and 3.14, and the three integration suites with Python 3.12. The
integration job first prints the runner's host and daemon security settings
(`tests/host_baseline.py`) and finally fails if they differ from the Linux
baseline, because a hosted runner is not necessarily a stock Ubuntu
installation. All of that is configured coverage, not an observed result: the
workflow has not run, so inspect a passing run before treating Linux as
verified.

Run `python3 tests/host_baseline.py` on any host to print the same facts. It
only reads.

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
- **Native Linux has no such VM.** There the container shares the host's own
  kernel, so the same kernel bug is more serious, and the Linux configuration
  has not been validated at all yet. See [LINUX_SECURITY.md](LINUX_SECURITY.md).
- **VPN mode has only been run against a controlled peer, on macOS.** No real
  Mullvad server, no Linux host. It hides your address from sites; it is not
  anonymity, and the VPN provider sees what the gateway connects to. See
  [VPN_SECURITY.md](VPN_SECURITY.md).
- **The seccomp profile is wider than Docker's default.** It additionally lets
  processes in the browser container create user namespaces with their own
  network and IPC namespaces, because Firefox's sandbox needs that.

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
  your IP, or in VPN mode from the VPN server's.
- **Legal exposure.** A container changes technical risk and nothing else.

---

## Files

```
Dockerfile                      base image + uBlock Origin + policy install
compose.services.yml            what each service runs: images, tmpfs, caps, limits
docker-compose.yml              direct topology: networks and start order
docker-compose.vpn.yml          VPN topology: adds Gluetun; Squid shares its namespace
VPN_SECURITY.md                 VPN mode: setup, rules, evidence and what is unverified
scripts/vpn.py                  WireGuard file parsing, generated config and firewall rules
security/gluetun-auth.toml      locks Gluetun's loopback control server
policies/firefox-policies.json  Firefox enterprise policy
gateway/squid.conf              egress rules: no private space, no odd ports
gateway/blocklist.txt           extra domains to refuse
security/seccomp-firefox.json   syscall filter for the browser container
security/README.md, upstream/   where that filter comes from and how it differs
LINUX_SECURITY.md               Linux baseline, evidence and what is unverified
.gitattributes                  keeps scripts and security inputs LF in every checkout
scripts/safebrowse.py           host launcher: run, stop, verify, logs, pin
run.sh / stop.sh / logs.sh      thin wrappers around the launcher
scripts/network.py              subnet selection and generated Squid ACL
scripts/open_url.py             validated URL dispatch to the running Firefox
pin.sh / scripts/pin.py         pin cached images; --refresh pulls updates
verify.sh / scripts/verify.py   structured runtime checks and live egress tests
tests/test_*.py                 offline security, launcher and wrapper regressions
tests/integration.py            real stack against disposable local fixtures
tests/cli_integration.py        real launcher against a disposable fixture session
tests/integration_vpn.py        real launcher in VPN mode against a fixture WireGuard peer
tests/host_baseline.py          read-only record of host and daemon security settings
.dockerignore                   allowlist of build inputs; excludes .env and .git
```

---

## Troubleshooting

**The launcher refuses to start.** It names the reason and changes nothing:
running as root or with `sudo` (rerun as your own user), a rootless Docker
daemon or one without seccomp (outside what has been validated; see
[LINUX_SECURITY.md](LINUX_SECURITY.md)), a Python older than 3.12, or carriage
returns in `gateway/squid.conf` or `gateway/blocklist.txt`. `./stop.sh`,
`./logs.sh` and `./verify.sh` still work in the first two cases.

**The launcher or `./stop.sh` says VPN storage is unsafe or was not removed
completely.** Generated VPN secrets live in `.runtime/vpn/<session>/`. If
`.runtime`, `.runtime/vpn` or a session directory is a symbolic link, is not a
directory, belongs to another user or is open to other users, `./run.sh`
refuses before it creates or changes anything, in either mode. `./stop.sh`
still removes the containers, then exits non-zero and says what it left
alone. It also exits non-zero when a session directory holds a file SafeBrowse
did not create: its own files are deleted, yours is not. Look at the path it
names, fix or delete it by hand, and rerun the command.

`./stop.sh` may be run as root or with `sudo`, and it will remove the
containers. The ownership checks on `.runtime` are not relaxed for it, though:
under `sudo` those directories belong to another user, so the generated-secret
cleanup is refused and the command exits non-zero after the containers are
gone, even for a direct session. Rerun `./stop.sh` as your own user to finish.
If `.runtime/network.json` cannot be read at all, `./stop.sh` carries on
without it; that file is only a convenience for teardown.

**"teardown ran, but these containers still exist".** Compose only removes
containers of this checkout's own project. If the checkout was renamed, moved
or copied after a session was started, its containers belong to the old project
name and survive. `./run.sh --fresh` then stops before starting anything and
keeps the stored VPN configuration those containers may be using; `./stop.sh`
reports the same thing. If another copy of the checkout started them, run
`./stop.sh` there. After a rename there is no such copy: remove them with
`docker rm --force` and the names in the message. Then rerun the command.

**A launch failed and mentions `.runtime/vpn/<session>/`.** If a VPN launch
fails after its containers were created, they are kept for diagnosis, and so is
the generated configuration they mount, which contains the WireGuard private
key. That covers containers that did not start and every later step of a new
VPN session: the desktop or Firefox not becoming ready, verification failing or
being incomplete, the requested URL not opening, and Ctrl-C during any of
them. The message names the directory, once, and never prints what is in it.
`./stop.sh` removes the containers and then tries to remove that directory,
and says so if it cannot. If the launch failed before any container was
created, the generated configuration is removed again straight away. A failed
`./run.sh --resume` changes nothing and prints no such note: the session and
its configuration are the ones that were already there.

**A VPN session will not start, or stops loading pages.** Nothing is sent
outside the tunnel in either case. `./logs.sh` shows the VPN container's
warnings as well as the gateway's. If the VPN container was restarted, stopped
or replaced, the gateway is left without a network and `./verify.sh` says so:
run `./run.sh --fresh`, which keeps VPN mode and reuses the stored
configuration. If the launcher says the session's mode or configuration cannot
be established, it has changed nothing; pick the mode explicitly, as it
describes. A configuration file is rejected if it contains `PostUp`/`PreDown`
commands (export it again without the kill switch), a host name instead of an
IP endpoint, or split routes.

**"contains carriage returns".** Squid reads its configuration and blocklist
byte for byte, so the launcher will not start with Windows line endings in
them. `.gitattributes` keeps a fresh checkout LF, but cannot repair a file that
was edited or checked out before it existed. Convert the file to LF (your
editor, or `dos2unix`) and check `git config core.autocrlf`. The `.env`
credentials file is parsed separately and may use either line ending.

**Tabs crash, or verification reports user namespaces as incomplete.** The
browser runs under `security/seccomp-firefox.json`, which allows the three
calls Firefox's sandbox makes to isolate its content processes. If the
verifier reports that user-namespace creation failed, the message lists the
kernel settings it could read; the error alone does not say whether seccomp,
AppArmor or a kernel setting refused it. Do not work around it with
`seccomp=unconfined`, `apparmor=unconfined`, `--privileged` or `SYS_ADMIN`;
[LINUX_SECURITY.md](LINUX_SECURITY.md) explains how to tell the layers apart.
Keep Docker and its kernel updated.

**Nothing loads at all.** Check the gateway first: `./logs.sh`. Squid refusing
everything may mean `.runtime/squid.conf` has an `acl sandbox src` that differs
from the subnet in `.runtime/network.json` or Docker's `safebrowse_sandbox`
network. `./run.sh --fresh` regenerates the ACL and network configuration.

**Docker reports an overlapping pool.** The launcher checks existing Docker
networks and tries up to three unused subnets. A direct `docker compose up`
uses the fallback `172.28.0.0/24` and can still collide; launch with `./run.sh`.

**A site you need is half-broken.** `./logs.sh` shows memory-backed gateway
diagnostics. Access logs are off by default. To see requests temporarily:

1. In `gateway/squid.conf`, change `access_log none` to
   `access_log stdio:/var/log/squid/access.log`.
2. Run `./run.sh --fresh`. This is required, and it **discards the current
   profile, tabs and anything else in the session**; the login in `.env` and a
   VPN session's mode and stored configuration are kept.
3. Reproduce the problem, then run `./logs.sh`.
4. Put `access_log none` back and run `./run.sh --fresh` again.

Editing the file and recreating only the gateway container does not work. The
gateway does not read `gateway/squid.conf`: it mounts `.runtime/squid.conf`,
which the launcher generates from it (with the session's subnet filled in) when
it starts a new session, and at no other time. Until the next `--fresh`, the
generated copy no longer matches its source, so `./run.sh --resume` and
`./verify.sh` refuse the existing session; they do not repair it. A gateway
recreated by hand with `docker compose` would also lose the session's labels
and subnet. Access logs contain browsing metadata, live in a bounded tmpfs and
disappear when the gateway stops; a full diagnostic filesystem can interrupt
the proxy, which is one more reason to turn them off again.

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

The launcher creates `.env` exclusively with mode 0600 before writing a password
from Python's `secrets` module, and never replaces an existing file. It refuses
a symlink or any non-regular file, parses the file as data and passes the same
values to Compose in the environment; nothing evaluates it as shell code. The
password is printed only in the login details after a successful launch. Use
unquoted `SANDBOX_USER` and `SANDBOX_PASSWORD` entries only.
Usernames allow letters, digits, `_`, `.`, `-`; passwords additionally allow
`+`, `/`, `:`, `@`, `%`. Whitespace, shell substitutions, duplicate or unknown
keys are rejected. The default generated hex password is supported.

The build context is an allowlist containing only `Dockerfile` and the Firefox
policy file, so `.env`, Git history and local scratch files never enter the build.
