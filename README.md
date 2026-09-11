# safebrowse

**A disposable, hardened Firefox that runs in a container and renders into a tab
on your machine.** For opening sites you don't trust: it has no access to your
filesystem, no route to your network, no account you're signed into, and no
memory of itself once you stop it.

No X11, no XQuartz, no GPU passthrough — the container ships a remote desktop
you open at `https://127.0.0.1:3011/`. Audio works, so video plays with sound.

Built and tested on **macOS + Docker Desktop (Apple Silicon)**. It should run
anywhere Docker does; Linux and Windows/WSL2 are untested.

---

## Quick start

```bash
git clone https://github.com/yairdocker/SafeBrowse.git
cd SafeBrowse
./run.sh        # builds, generates a random UI password, starts, prints the URL
./pin.sh        # pins base images to the digests now on your machine
./verify.sh     # proves the hardening applied, against the running system
```

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

The browser sits on an **internal** Docker network. Docker installs a firewall
rule dropping anything entering that bridge from outside its own subnet, and
gives its members no NAT — so the browser container has no default route, no
DNS of its own, and no published ports. Its only path outward is the Squid
gateway, pinned by Firefox enterprise policy so a page can't switch it off.

Because an internal-network container can't publish ports, a one-line `socat`
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
  exfiltration over an odd port, no DNS tunnelling.
- **All name resolution happens at the gateway**, on filtering resolvers. The
  browser has no resolver of its own to bypass it with.
- A domain blocklist at `gateway/blocklist.txt` for anything you specifically
  never want reached.
- `forwarded_for delete`, `via off` — the gateway doesn't announce the sandbox
  upstream.

### Isolation

| Control | Effect |
|---|---|
| No bind mounts, no volumes | The browser cannot read or write a single file on your machine. |
| Internal-only network | No route to the internet, your LAN, or the host. |
| No published ports on the browser | Nothing can connect *to* it either. |
| `cap_drop: ALL` + minimum re-add | Six capabilities instead of the default fourteen. |
| `no-new-privileges` | No setuid escalation inside the container. |
| UI bound to `127.0.0.1` | Nothing on your network can reach it. |
| `mem_limit` / `cpus` / `pids_limit` | A cryptominer hits a ceiling instead of your fans. |

### Disposability

The Firefox profile lives on `tmpfs` — RAM, not disk. Cookies, cache, service
workers, IndexedDB, anything a site persisted: destroyed on `./stop.sh`, and
never written to your SSD at any point.

### Browser policy — `policies/firefox-policies.json`

Applied as Firefox enterprise policy, so nothing can prompt its way around it.

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

`./pin.sh` rewrites every upstream image reference to the exact digest on your
machine and records them in `PINS.txt`. A `:latest` tag means whoever controls
that tag controls what runs in your sandbox on the next rebuild; a digest can't
change under you. Re-run it deliberately (`docker compose pull && ./pin.sh`)
when you want upstream updates — the point of pinning is that updates become a
decision rather than a side effect.

---

## Verification

`verify.sh` is the part worth reading. It doesn't check the compose file — it
interrogates the running containers and **attempts the connections that should
fail**: a direct fetch to the internet, a request to `host.docker.internal`, a
request into `192.168.1.1`, and a public hostname that resolves to loopback.

```
== network containment
  PASS  browser cannot reach the internet directly
  PASS  browser reaches the web through the gateway
== gateway
  PASS  denied by policy: your LAN by literal IP (403)
  PASS  DNS rebinding blocked: public name resolving to loopback is denied (403)
== bridges to your Mac
  PASS  clipboard sync is disabled in both directions
```

It classifies proxy responses carefully, because these are not the same thing:

| Response | Meaning |
|---|---|
| `403` | The ACL fired. This is the real proof. |
| `503` | Squid couldn't resolve or connect. Nothing reached the target, but the ACL isn't what stopped it. |
| `000` | No answer from the proxy at all. Proves nothing. |
| `2xx`/`3xx` | The request went through. Genuine failure. |

That distinction exists because an earlier version treated `000` as a denial,
which made a **completely dead gateway report three confident passes**. A
verification tool that fails toward reassurance is worse than no tool.

The same lesson applies to the ad-blocker check: it searches the live profile
for the installed add-on rather than checking that a flag was passed. An earlier
version asserted the flag and stayed green through three entirely absent ad
blockers.

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
  not a channel hostile code can drive by itself — moving a file requires you
  to use that panel deliberately.
- **Firefox has no download-blocking policy.** Downloads are pointed at a
  non-existent locked directory, which is friction rather than a hard block.
  The real protection is the tmpfs profile and the absence of any bind mount.
- **The uBlock Origin XPI isn't digest-pinned.** It's fetched by URL at build
  time; the build asserts its extension ID, which catches a moved or wrong file
  but not a compromised one served from the right place. `pin.sh` prints how to
  close this.
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
pin.sh                          pin base images to digests (writes PINS.txt)
verify.sh                       post-launch assertions, including live egress tests
logs.sh                         gateway startup, cache and access logs
```

---

## Troubleshooting

**A tab crashes on rich pages.** Firefox content processes need user namespaces
to sandbox themselves; `seccomp=unconfined` is set on the `safebrowse` service
for that reason. If you removed it, put it back.

> That flag looks like weakening security and isn't. Docker's default seccomp
> profile gates `clone(CLONE_NEWUSER)` behind `CAP_SYS_ADMIN`, so with
> capabilities dropped the browser has **no usable sandbox at all**. Relaxing
> the outer filter buys back per-process isolation on the exact processes that
> execute hostile JavaScript. The alternative, `cap_add: SYS_ADMIN`, keeps
> seccomp but grants the most escape-prone capability there is.

**Nothing loads at all.** Check the gateway first: `./logs.sh`. Squid refusing
everything usually means the sandbox subnet in `squid.conf`
(`acl sandbox src 172.28.0.0/24`) no longer matches the one in
`docker-compose.yml`. They must agree.

**A site you need is half-broken.** Run `./logs.sh` and look for `TCP_DENIED`
in the access log — it names exactly what was refused. Most often a
non-standard port, which is deliberate.

**The ad blocker isn't active.** `verify.sh` distinguishes three cases: the
`.xpi` missing from the image (rebuild), the policy not force-installing it
(check `policies/firefox-policies.json`), or the add-on present but not yet
registered in the profile (load a page, then re-run).

**Playback is choppy.** The remote desktop encodes H.264 on CPU with no GPU
passthrough, so pixel count is the cost driver. Drop the resolution in the
sidebar's screen settings.

**You need a file out.** You shouldn't, from an untrusted site. If the reason is
legitimate, unlock `browser.download.dir` in the policy file, add a bind mount
to a dedicated empty folder, and treat whatever lands there as hostile.

---

## License

MIT — see [LICENSE](LICENSE).
