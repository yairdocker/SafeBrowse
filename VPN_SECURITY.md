# VPN mode

SafeBrowse can send the gateway's traffic through a WireGuard tunnel, so that
sites see the VPN server's address instead of yours. Only SafeBrowse uses the
tunnel. Nothing on your computer is installed, re-routed or reconfigured.

This document says how to use it, what it is built from, what was measured,
and what was not. Statements about behaviour are marked **observed** only where
they were measured in the environment named in [Observed results](#observed-results).

| | State |
|---|---|
| VPN mode on macOS + Docker Desktop, against a controlled WireGuard peer | observed |
| VPN mode against a real Mullvad server | **NOT VERIFIED** |
| VPN mode on native Linux, on amd64, or in CI | **NOT VERIFIED** |
| Direct mode | unchanged; still the default |

Native Linux remains experimental until the release gate in
[LINUX_SECURITY.md](LINUX_SECURITY.md) is met. VPN mode does not change that.

## What it is, and what it is not

- It is a tunnel for the gateway (Squid) only. Firefox still has no route off
  its isolated bridge and still reaches the web only through `gateway:3128`.
- It is a kill switch enforced by a firewall inside the VPN container's network
  namespace, all the time, whether or not the tunnel is up. SafeBrowse never
  falls back to a direct connection.
- It is **not** anonymity. Your VPN provider sees your traffic's destinations and
  knows your account. Sites can still fingerprint the browser. The desktop
  connection between you and the container never leaves your machine.
- It does not identify or attest the VPN provider. SafeBrowse connects to the
  endpoint and key in your file; it cannot tell whose server that is.
- It does not cover the host. Image pulls, builds and `./pin.sh --refresh` are
  made by Docker on your computer's own connection, outside the tunnel.
- Stopping a session deletes the generated configuration. That is ordinary file
  deletion, not secure erasure.

## Setting it up from a Mullvad export

1. In your Mullvad account, generate a WireGuard configuration file for Linux
   and download one `.conf` file. Leave the kill-switch option **off**: it adds
   `PostUp` and `PreDown` commands, and SafeBrowse rejects any file that
   contains commands. Do not use multihop.
2. Keep the file somewhere private (`chmod 600` is sensible).
3. Start a session:

```bash
./run.sh --vpn mullvad --vpn-config ~/mullvad/se-got-wg-001.conf --url https://example.com/
```

The file is read, checked and left exactly as it was. Never paste keys into a
chat, an issue or a command line; SafeBrowse only ever takes a path.

Each file names one server. SafeBrowse connects to that literal address and
never looks servers up, picks one, or switches. To use another server, export
another file and start a fresh session with it.

## Commands

```
run [--fresh | --resume] [--direct | --vpn mullvad] [--vpn-config PATH] [--url URL]
```

| Command | Result |
|---|---|
| `./run.sh` | No session exists: a **direct** session. |
| `./run.sh --vpn mullvad --vpn-config PATH` | No session exists: a VPN session. |
| `./run.sh --resume` | Verify and reuse the existing session **in the mode it was started in**. Nothing is rebuilt, restarted or reconfigured. |
| `./run.sh --resume --direct` or `--resume --vpn mullvad` | Same, but refuses if the session is in the other mode. |
| `./run.sh --resume ... --vpn-config PATH` | Refused: resume never replaces a configuration. |
| `./run.sh --fresh` | Replace the session, **keeping its mode**. A VPN session is rebuilt from its stored configuration. |
| `./run.sh --fresh --direct` | Replace the session with a direct one. The only way to leave VPN mode. |
| `./run.sh --fresh --vpn mullvad --vpn-config PATH` | Replace the session with a VPN one using this file. |
| `./run.sh --direct --vpn mullvad`, `--vpn-config` without `--vpn mullvad`, `--vpn other` | Refused before Docker is contacted. |
| `./stop.sh`, `./verify.sh`, `./logs.sh` | Work in either mode and take no mode option. |

Rules that hold in every case:

- A VPN session is never replaced by a direct one unless you type `--direct`.
- If the existing session's mode cannot be established (containers from an older
  SafeBrowse, labels that disagree, a stored configuration that is missing or
  altered), `--resume` and a mode-less `--fresh` refuse **before anything is
  removed** and tell you the explicit commands. `./stop.sh` still works.
- If no session exists but a generated VPN configuration is still stored, a plain
  `./run.sh` refuses rather than assume direct mode.
- A stored configuration is reused only if it is still, byte for byte, the file
  its session was created with. `--resume` and a mode-less `--fresh` both check
  this first and refuse before anything is touched; see
  [Where secrets live](#where-secrets-live).
- If the place generated secrets are kept is unsafe (a symbolic link, not a
  directory, another user's, open to other users), `run` refuses in **either**
  mode before credentials, files or containers are created or changed. It is
  never read as "there is no VPN session".
- The new session's configuration is checked, the Compose model is validated and
  images are built and fetched **before** the old session is discarded. A failure
  there leaves the old session and its configuration as they were.
- The old session's stored configuration is deleted only after its containers
  have been looked for again and found gone. A teardown that reports success is
  not enough: if a container with a session name still exists, or Docker cannot
  say, nothing is started and that configuration stays where it is.
- The requested URL is opened only after every check passes, as in direct mode.

The banner printed after a successful launch states the mode.

## Topology

```
  your machine
  127.0.0.1:3011 ──► uiproxy ──┐
                               │  safebrowse_sandbox  (internal, isolated)
                               ├──► safebrowse : Firefox, no route out
                               │         │ gateway:3128
                               │         ▼
                               │   ┌─ one network namespace ──────────────┐
                               └──►│ vpn (Gluetun): sbx0, egr0, tun0      │
                                   │ gateway (Squid): no network of its own│
                                   └───────────────┬──────────────────────┘
                                                   │ WireGuard, UDP to one endpoint
                                 safebrowse_egress ▼
                                                internet ──► VPN server ──► sites
```

There are two complete Compose topologies and the launcher selects exactly one:

| File | Role |
|---|---|
| `compose.services.yml` | What the gateway, desktop relay and browser run. Never started alone. No networking. |
| `docker-compose.yml` | Direct topology: the gateway is on the sandbox and egress networks. |
| `docker-compose.vpn.yml` | VPN topology: adds `vpn`; the gateway uses `network_mode: service:vpn`. |

The VPN file is not an overlay on the direct file, so the gateway cannot keep an
egress attachment by accident. Before every launch the launcher reads the
effective model (`docker compose config`) and refuses it unless it is the
selected topology: the right services, the gateway with no network of its own,
the VPN container on exactly two networks with the `gateway` alias only on the
sandbox, no published port except the desktop on `127.0.0.1`, and the reviewed
capabilities and mounts.

To check the effective VPN model yourself, with no secret involved:

```bash
SANDBOX_PASSWORD=validation-only-not-a-session docker compose -f docker-compose.vpn.yml config --quiet
```

In VPN mode:

- The browser container is defined by the same shared service as in direct mode:
  same isolated bridge, capabilities, seccomp profile, `no-new-privileges`, tmpfs
  profile, and no mounts.
- The desktop relay is outside the VPN namespace, so the desktop stays reachable
  for diagnosis when the tunnel is down.
- Nothing in the VPN namespace is published to the host.
- No container has a restart policy. Docker never replaces a container for you.
- Inherited `COMPOSE_*` variables are ignored (and named in a warning), and the
  launcher passes its file selection explicitly on every Compose command.

### VPN container privileges

| Granted | Why | Evidence |
|---|---|---|
| `NET_ADMIN` | Create the WireGuard interface, routes and firewall rules in its own namespace. | Gluetun starts and connects with this alone on Docker Desktop. |
| `DAC_OVERRIDE` | Read the configuration, which is mode 0600 and owned by you, not by the container's root. | With real Linux file ownership a root process holding only `NET_ADMIN` gets `Permission denied`; with `DAC_OVERRIDE` it reads the file. Docker Desktop presents bind mounts as root-owned, so there it is not needed, but one configuration is kept. Measured on a volume inside the Docker Desktop VM; a native Linux bind mount is NOT VERIFIED. |

Not granted: `privileged`, `SYS_ADMIN`, `SYS_MODULE`, `NET_RAW`, any device
(kernel WireGuard needs no `/dev/net/tun`; the userspace fallback is not
configured), host networking, sysctls. `DAC_READ_SEARCH` would also have read
the file but was rejected: with it, Docker's default seccomp profile permits
`open_by_handle_at`, a known way to reach host files.

If the kernel has no WireGuard support, the VPN container fails to start and the
launch fails. NOT VERIFIED on any kernel other than Docker Desktop's.

## The pinned image

`qmcgaw/gluetun` **v3.41.3**, commit `3d1e20c`, multi-architecture index
`sha256:fa19cc76b2af13d57a8d3dc3066f2ada061b1c761b8aecf989b3877c0486e027`
(amd64, arm64 and others). The source at that tag was read alongside the running
image; setting names below are that release's.

`./pin.sh --refresh` re-resolves the `v3.41.3` tag, never `latest`, which follows
Gluetun's development branch. Moving to another release means changing the tag
in `scripts/pin.py`, re-reading this section against the new source, and
re-running `tests/integration_vpn.py`.

### What the image does by default, and what SafeBrowse changes

Observed in the running image with its own settings, then with SafeBrowse's:

| Finding in v3.41.3 | SafeBrowse |
|---|---|
| Firewall accepts **any** inbound packet on every local network (`-A INPUT -i <if> -d <subnet> -j ACCEPT`). The browser could reach any port in the namespace. | Own chain, evaluated first, accepts only TCP 3128 from the sandbox subnet on the sandbox interface. Observed: ports 53, 8000, 8388, 8888, 9999 do not answer. |
| Firewall accepts outbound traffic to every local network. Observed: Squid fetched a page from a host on the egress bridge **outside the tunnel**. | Own chain drops everything leaving that is not WireGuard to the one endpoint. Observed: that request now times out and the DROP counter rises. |
| Control server cannot be disabled and listens on `:8000`. With no auth file, `PUT /v1/vpn/status` (stop the VPN) needs no credentials. | Bound to `127.0.0.1`; `security/gluetun-auth.toml` leaves only `GET /v1/version` open. Observed: every other route returns 401. |
| Health server on `127.0.0.1:9999`. | Kept; Docker's health check needs it. |
| DNS server on port 53, HTTP proxy, Shadowsocks. | `DNS_SERVER=off`, `HTTPPROXY=off`, `SHADOWSOCKS=off`. Observed: no such listeners. |
| At the `info` log level the settings summary prints a shortened private key (first and last three characters). | `LOG_LEVEL=warn`. Observed: nothing of the key in `docker logs`. |
| Public-IP lookups, version check, server-list updates, blocklist downloads, a 20,000-entry server file. | `PUBLICIP_ENABLED=off`, `VERSION_INFORMATION=off`, `UPDATER_PERIOD=0`, `BLOCK_*=off`, `STORAGE_FILEPATH=` (empty). |
| Default WireGuard `AllowedIPs` includes `::/0`. | `WIREGUARD_ALLOWED_IPS=0.0.0.0/0`. |
| Docker's embedded resolver (`127.0.0.11`) inside the namespace forwards public names from the host, **outside the tunnel**. Observed: `example.com` resolved. | Dropped by the first rule of the output chain. Observed: it times out. Nothing in the namespace needs it. |
| `docker restart` of the VPN container creates a **new** network namespace; Squid stays in the old one, which has no interfaces. | Not repaired. Verification fails and says to use `--fresh`. See [Failure and recovery](#failure-and-recovery). |

### Firewall

Gluetun applies `/iptables/post-rules.txt` as the last step of enabling its own
firewall. SafeBrowse generates that file for each session (the sandbox subnet and
your endpoint are in it; no key is). The rules create two chains and insert a
jump to each at position 1, ahead of everything Gluetun added:

```
SAFEBROWSE_INPUT
  -i lo   -> back to Gluetun's rules
  -i tun0 -> back to Gluetun's rules (which accept only established traffic)
  -i sbx0 -s <sandbox subnet> -p tcp --dport 3128          ACCEPT
  -i egr0 -s <endpoint> -p udp --sport <port> ESTABLISHED   ACCEPT
  everything else                                           DROP

SAFEBROWSE_OUTPUT
  -d 127.0.0.11                                             DROP
  -o lo   -> back to Gluetun's rules
  -o tun0 -> back to Gluetun's rules
  -o sbx0 -d <sandbox subnet> -p tcp --sport 3128 ESTABLISHED  ACCEPT
  -o egr0 -d <endpoint> -p udp --dport <port>               ACCEPT
  everything else                                           DROP

FORWARD: DROP first
```

Anything that is not loopback or the tunnel must match one of four narrow
ACCEPTs. No private address range is exempted, and no return-path rule is wider
than one protocol, one port and one interface.

The interfaces are named `sbx0` and `egr0` by the Compose file
(`com.docker.network.endpoint.ifname`, Docker Engine 28+) rather than assumed to
be `eth0`. The verifier does not trust the names: it finds the interface that
holds an address in the sandbox subnet and requires it to be the one the rules
name. If naming ever failed, the ACCEPT rules would match nothing and the
session would be unusable, not open.

When the rules apply:

- **Start.** Gluetun sets DROP policies, adds its rules, then these, before it
  opens any listener or connects. Squid is not started until the VPN container
  reports healthy, and the browser after that.
- **Reconnect.** Gluetun removes and re-adds only its own two VPN rules, at the
  end of the chain. Observed: the SafeBrowse chains and the first rule of each
  built-in chain are identical before and after.
- **Rebuild.** Gluetun rebuilds its firewall only when its process starts, which
  means a new namespace (above). Observed after `docker restart`: the same chains,
  first.

### IPv4 only

The sandbox bridge has IPv6 disabled. IPv6 addresses and `::/0` routes in your
file are recognised, reported, and left out of the generated configuration; a
partial IPv6 route is rejected, not kept. Gluetun sets IPv6 policies to DROP.
Observed: no global IPv6 address and no IPv6 default route in the namespace; a
request for an IPv6 destination fails and no packet leaves.

### DNS

- **Web names** are resolved by Squid, as in direct mode, using the AdGuard
  resolvers in `gateway/squid.conf`. Observed: those queries arrive at the far end
  of the tunnel from the tunnel address. Squid's private-address and blocklist
  rules are unchanged, and observed to hold.
- **The browser container's resolver** is Docker's embedded one, needed to find
  `gateway`. In both modes the browser is created with `dns: 127.0.0.1`, which
  makes its own loopback address the only server that resolver may pass any
  other name on to. Observed on Engine 29.9.2: `gateway` resolves; an external
  name is refused (SERVFAIL) and no DNS packet leaves the container's loopback
  interface. An internal network on its own is not enough: a control container
  on the same internal network, given a resolver on that network, forwarded
  its queries there. `./verify.sh` checks the restriction and the behaviour
  separately and passes only on both (see README.md, Verification). Other
  engines are NOT VERIFIED; there the check fails or is inconclusive rather
  than passing.
- **Inside the VPN namespace** Docker's resolver is blocked (above).
- Your file's `DNS =` line is recognised and not used: the gateway keeps its own
  filtering resolvers. The launcher says so.

NOT VERIFIED: whether a real Mullvad server delivers port-53 queries to AdGuard
or answers them itself. Mullvad's documentation describes DNS redirection only
for its own app. If a server did intercept them, AdGuard's filtering would not
apply in VPN mode; Squid's blocklist and uBlock Origin still would.

### Health traffic

All of it goes through the tunnel. None can be turned off in this release.

| When | What |
|---|---|
| Start, then every 5 minutes | TCP connection to `94.140.14.14:53` or `94.140.15.15:53` (the resolvers Squid already uses). No query is sent. |
| Every minute | One DNS query for `github.com` to `1.1.1.1`, moving through a built-in list of public resolvers if it fails. |

The second exists because the VPN container does not hold `NET_RAW`: without it
Gluetun cannot send ICMP and falls back to DNS. Granting `NET_RAW` would replace
those queries with pings to the AdGuard addresses; the capability was not
considered worth it. If the checks fail, Gluetun restarts the tunnel inside the
same namespace.

## Your configuration file

`scripts/vpn.py` treats the file as data:

- Exactly one `[Interface]` and one `[Peer]`. Duplicate sections or fields are
  rejected.
- `PrivateKey` and `PublicKey` (and `PresharedKey` if present) must be the
  canonical base64 encoding of 32 bytes.
- `Endpoint` must be a literal public IPv4 address and a port. Host names and
  IPv6 endpoints are rejected.
- `Address` must contain exactly one IPv4 `/32`. `AllowedIPs` must contain
  `0.0.0.0/0`; any narrower or split route is rejected.
- `MTU` (1280–1420, default 1320) and `PersistentKeepalive` (0–65535) are
  optional.
- `PreUp`, `PostUp`, `PreDown`, `PostDown`, includes, and every directive not
  listed here are rejected. Nothing from the file is ever executed.
- Symbolic links, directories, devices and pipes are rejected as the path.

What the VPN container receives is a new, minimal file generated from those
values, not your file.

### Where secrets live

| | |
|---|---|
| Your file | Read once per launch that names it. Never modified, moved or deleted. |
| Generated configuration | `.runtime/vpn/<session>/wg0.conf`, mode 0600, in directories of mode 0700, created exclusively. Ignored by Git; outside the Docker build context. |
| Generated firewall rules | `.runtime/vpn/<session>/post-rules.txt`, same protection. Contains the endpoint, no key. |
| In Docker | Mounted read-only into the VPN container only. Never in an environment variable, a command-line argument, a label, an image, or anything SafeBrowse prints. |
| Fingerprint | The SHA-256 of the generated configuration, as the label `safebrowse.vpn-config-sha256` on all four containers. A hash of the file, not its contents. |

A replacement session's files go in their own new directory; the old session's
are deleted only after that session has been removed, and removal is confirmed
by inspecting the session's container names, not assumed from the teardown's
exit status. Compose removes only this checkout's own project, so after a
checkout is renamed, moved or copied, `--fresh` can find the old containers
still there. It then refuses, removes neither them nor their configuration, and
says how to remove them.

**Storage boundary.** The checkout directory is taken as given. Below it,
`.runtime`, `.runtime/vpn` and the session directory are each checked before
anything is read, written or deleted through them: not a symbolic link (dangling
or not), a directory, owned by you, not writable by others (`.runtime`) or not
accessible to others at all (the two below it). The generated files must be
regular files with the same ownership and no access for others. Nothing is
repaired or re-permissioned; an unsafe path is reported and left alone. On
macOS and Linux each directory is opened once and later steps are made relative
to that open directory, without following links, so a path swapped afterwards
is not followed.

**Reuse.** `--resume` and `--fresh` without `--vpn-config` read the stored file
and compare its SHA-256 with the fingerprint on the session's containers. They
refuse, before changing anything, if the file is missing, differs in any way
(including an edit that is itself a valid, well-formed configuration, such as
another `Endpoint`), or if the containers carry no fingerprint, a malformed
one, or different ones. A fingerprint is only ever computed from a file you
name with `--vpn-config`, or carried over from a stored file that matched; it
is never adopted from whatever is on disk.

This detects a changed configuration file. It is not protection against someone
who controls Docker on this computer: they can replace the containers and the
file together.

**Sessions from before fingerprints.** A VPN session started by an earlier
version has no fingerprint label. `--resume` and a mode-less `--fresh` refuse
it and name the way forward: `./run.sh --fresh --vpn mullvad --vpn-config PATH`
(or `--fresh --direct`). `./stop.sh` still removes it. Direct sessions are not
affected by this.

**Cleanup.** `./stop.sh` removes the containers first, then the generated
files. It deletes only the four file names SafeBrowse itself creates, inside a
directory that passed the checks above, and it exits non-zero, without saying
the sandbox was destroyed, if storage is unsafe or a session directory could
not be removed (for example because it holds a file SafeBrowse did not create,
which is left untouched). Deletion is ordinary file deletion, not secure
erasure.

`./stop.sh` is allowed to run as root, so that a session can always be removed,
but the ownership checks above are the same for every user. Run with `sudo`,
it removes the containers and then refuses the cleanup, because `.runtime`
belongs to another user from root's point of view; it exits non-zero and says
so, in either mode. Rerun it as your own user. The checks are not bypassed to
make `sudo` succeed. Saved network state (`.runtime/network.json`) is optional
for teardown: if it cannot be read, the containers are still removed.

**After a failed launch.** A new session's configuration is generated before
the old session is touched. If the launch fails before any container of the new
session is created, that configuration is removed again; if it cannot be
removed, the message says where it is. If the launch fails after containers
were created, they are kept for diagnosis and may mount it, so it is kept too:
the message names `.runtime/vpn/<session>/` and says that `./stop.sh` removes
the containers and then the directory. The same note is printed if the launch
is interrupted at that point.

A new VPN session whose containers started can still fail a later step: the
authenticated desktop or Firefox does not become ready in time, verification
fails or is incomplete (exit code 2), or the requested URL cannot be opened.
Nothing is stopped or deleted then, and the exit code is unchanged. The message
says once that `.runtime/vpn/<session>/` holds generated configuration
containing the WireGuard private key, that the containers may still need it,
and that `./stop.sh` removes the containers and then attempts to remove that
directory. Ctrl-C during those steps prints the same note and exits 130. The
directory named is the one this launch created, taken from the launcher's own
state, not found by looking through storage. A failed `--resume` prints no
such note and leaves the resumed session's configuration alone. File contents
are never printed.

The verifier never reads the configuration and never runs `wg show`.

## Failure and recovery

The firewall, not a health flag, is what keeps traffic in the tunnel.

| Event | What happens |
|---|---|
| Tunnel never connects at launch | The VPN container goes unhealthy; the gateway and browser are never started; the launch fails. The containers stay for diagnosis. |
| Server unreachable, route lost | New connections fail. Packets the kernel sends towards the ordinary route are dropped and counted. Recovers by itself when the tunnel does. |
| Tunnel interface removed | Gluetun rebuilds it in the same namespace within seconds; traffic resumes. |
| VPN container restarted, stopped and started, or recreated | Squid is left in the old namespace with no interfaces: browsing fails closed. `./verify.sh` and `--resume` fail and say so. **Use `./run.sh --fresh`**, which keeps VPN mode. |
| Verification fails or is inconclusive | The URL is not opened. Nothing is torn down or restarted. |

There is no repair command. `--resume` never restarts a container. Data already
in flight towards you through the tunnel may still arrive during a failure;
nothing goes out by another path.

## Verification

`./verify.sh` reads the session's labels (session identifier, schema, mode) as a
claim, then checks the live containers against it. In VPN mode, in addition to
every direct-mode check:

- all four containers carry the same session and mode;
- the gateway's network mode names the current VPN container, and the two share
  one live network namespace (compared from inside each container);
- the gateway has no network or port of its own; the VPN container is on exactly
  the sandbox and egress networks, publishes nothing, and is `gateway` only on
  the sandbox;
- capabilities, devices and mounts are within the reviewed lists;
- a kernel WireGuard interface is up and is the route for non-local traffic;
- firewall policies are DROP, SafeBrowse's chains come first and are exactly the
  generated rules, and Gluetun connects to the one endpoint they allow;
- no IPv6 address or route; only Squid listens beyond loopback; from the browser
  only port 3128 answers.

In direct mode it also fails if a container with the VPN container's name exists.
A session whose labels are missing or disagree is reported inconclusive; it never
passes. Exit codes are unchanged: 0, 1 (a check failed), 2 (inconclusive).

The checks made from inside the browser container (including the listener probe
above and the DNS probe) are Python started with `python3 -I`, and their output
is validated before any of it is displayed; see README.md, Verification. That
closes one start-up injection path. It is not attestation of a container that
is already compromised.

Routine verification only reads. It never stops a tunnel or changes a rule.

## Observed results

Environment: macOS 26.5.2, Apple Silicon, Docker Desktop (Engine 29.9.2, Compose
5.6.1, VM kernel 7.0.14-linuxkit, arm64), Python 3.14 and 3.12.

`tests/integration_vpn.py` drives the real launcher with the same parser,
generator, image, Compose topology, firewall and verifier as production. Its
WireGuard server is a container holding keys generated for the run; the
destinations, including the AdGuard resolver addresses, exist only behind it. A
packet capture on the VPN container's egress interface records everything that
is not WireGuard.

| Scenario | Result |
|---|---|
| HTTP, HTTPS CONNECT, DNS | Every request and query arrived from the tunnel address. |
| Squid ACLs and blocklist | Unchanged; denied requests never arrived. |
| Direct TCP from the browser, IPv6, auxiliary ports, a host on the egress bridge, Docker's resolver | All blocked. |
| Tunnel that cannot connect | Launch failed; gateway and browser never started; nothing arrived anywhere. |
| Route loss, with an open connection and new ones | Kernel chose the ordinary route; only WireGuard left the interface; DROP counter rose. |
| Interface removal, server outage | Blocked, then recovered in place; rules unchanged. |
| VPN container restart, stop/start, recreation | Fail closed; verification and resume rejected each. |
| Mode changes, missing and damaged stored configuration | As described under [Commands](#commands). |
| Stored configuration with a valid but different `Endpoint` | `--fresh` and `--resume` refused; session untouched. |
| VPN storage reached through a symbolic link | `--resume`, `--fresh` and `--fresh --direct` refused; nothing changed. |
| `./stop.sh` with a foreign file in the session directory | Containers and generated files removed, foreign file kept, exit 1; exit 0 once it was gone. |
| Browser DNS (direct-mode suite, `tests/integration.py`) | See [DNS](#dns): observer and capture saw forwarded queries from the controls and none from the browser. |
| Python start-up injection as the browser user (direct-mode suite) | A planted `.pth` file, `PYTHONPATH` module and working-directory module each ran under ordinary Python; none ran in the verifier's seven probes or during a complete verification. |
| Keys | Not found in launcher or Docker output, container metadata, environment, labels or logs. |
| Host | Default route identical before, during and after; an unrelated container's traffic was not tunnelled. |
| Positive control | With rules opened by hand, the capture and an observer both saw the ordinary route. |

The capture cannot attach before the VPN container starts, so the start-up
ordering is established from Gluetun's source and from Squid starting only after
the health check, not from a capture.

## Not verified

- A real Mullvad account, server or exported file. No account was created or used.
- Native Linux, amd64, Ubuntu 24.04, AppArmor, and the CI workflow.
- Kernel WireGuard availability outside Docker Desktop's VM.
- Reading the 0600 configuration through a bind mount on native Linux.
- Docker's embedded-resolver behaviour, including how it treats `dns: 127.0.0.1`,
  on engines other than 29.9.2.
- Ownership and permission checks on storage, and directory-relative file
  operations, on anything but macOS. The fallback used where those operations do
  not exist was exercised only by simulation on macOS.
- `--fresh` after a real checkout rename, and the reporting of generated
  configuration kept after a failed launch. Both were exercised offline against
  a simulated Docker only.
- Probe isolation against anything other than the three start-up injections
  listed above, in any image other than the pinned one.
- Gluetun's behaviour over long sessions (key rotation, roaming, hours of uptime).
- Whether the VPN provider intercepts DNS.
