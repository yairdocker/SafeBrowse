# Linux security baseline

This file records how the browser container is confined by Docker, what was
measured, on which hosts, and what has not been measured. Observed results,
configured CI and intended support are kept apart on purpose.

## Status

**Native Linux is not yet a supported or hardened platform.** Everything below
that is marked *observed* was observed on macOS with Docker Desktop. No part of
SafeBrowse has been run on a Linux host, and the updated CI workflow has not
run. Treat native Linux as experimental until the release gate at the end of
this file has been met on a real Ubuntu 24.04 host.

| Host | State | Evidence |
|---|---|---|
| macOS 26.5 (arm64), Docker Desktop, Engine 29.9.2, Compose 5.6.1, VM kernel 7.0.14-linuxkit, Python 3.12 and 3.14 | Supported; observed | Offline tests and both container suites pass with the configuration described here (2026-11-12). The daemon reports `seccomp` (built-in profile) and no AppArmor. |
| Ubuntu 24.04, rootful Docker Engine 28+, AppArmor and Ubuntu's user-namespace restriction left on, launched as a non-root user | Target baseline; **NOT VERIFIED** | Nothing has been run. CI is configured for `ubuntu-24.04`, but a configured workflow is not a passing run. |
| GitHub-hosted `ubuntu-24.04` runner | Configured only | The workflow records the runner's settings and fails if they differ from the baseline. The runner is not assumed to be a stock Ubuntu installation. |
| amd64 (any host) | **NOT VERIFIED** | The profile and probes cover amd64, but only arm64 has been run. |
| Rootless Docker; launching as root or with `sudo` | Refused | See *Unsupported configurations*. |
| Windows, WSL2, other Linux distributions, SELinux hosts | Outside this phase | Not tested. On a Linux daemon without AppArmor the verifier reports an inconclusive result. |

## Two separate layers

There are two syscall-filtering layers around web content, and a check of one
says nothing about the other.

1. **Docker's outer filter.** A seccomp filter that Docker installs on every
   process in the browser container, including the Firefox parent process, the
   remote-desktop stack and anything an attacker manages to start. On Linux
   hosts with AppArmor, Docker also confines the container with the
   `docker-default` AppArmor profile.
2. **Firefox's own sandbox.** Firefox installs a second, tighter seccomp filter
   on each content process, and, when it can create user namespaces, also gives
   each one its own user, network and IPC namespaces and a `chroot` into an
   empty directory.

`Seccomp: 2` in a content process's `/proc/<pid>/status` shows only that *a*
filter is present there. It was also `2` when Docker's outer filter was
disabled, because Firefox's own filter was still installed. The verifier
therefore checks the outer layer from a separate process that is not a Firefox
content process.

## What was measured

The pinned image (`lscr.io/linuxserver/firefox@sha256:bc5b08fa…`, Firefox
155.0.1) was started in disposable fixtures under five filters. Each run opened
a page on a local test server.

| Outer filter | Page loads | Firefox parent filtered | Content processes | User namespace as UID 1000 |
|---|---|---|---|---|
| `seccomp=unconfined` (previous configuration) | yes | **no** (`Seccomp: 0`) | own user/net/IPC namespaces, chroot, 1 filter | allowed |
| Docker's built-in profile | yes | yes | **share the container's namespaces, no chroot**, 2 filters | refused |
| Built-in + `clone` rule | yes | yes | share the container's namespaces, no chroot | `clone` allowed, Firefox's follow-up `unshare` refused |
| Built-in + `clone` + `unshare` rules | request sent | yes | **none survive** | allowed |
| Built-in + `clone` + `unshare` + `chroot` rules (**chosen**) | yes | yes | own user/net/IPC namespaces, chroot, 2 filters | allowed |

How the refusals were attributed. Under the built-in profile, `unshare(0)` and
`personality(ADDR_NO_RANDOMIZE)` both returned `EPERM`. The kernel permits those
two calls to any process, so those refusals can only come from a filter. The
same calls succeeded with `seccomp=unconfined`. `clone(CLONE_NEWUSER)` returned
`EPERM` under the built-in profile and succeeded with the filter removed, on a
daemon with no AppArmor and with `user.max_user_namespaces` non-zero, so on this
host the refusal was seccomp's. An `EPERM` on its own would not have shown that.

Firefox's namespace-related calls were traced with `strace` in a throwaway
image, both for a headless start and for the live browser opening pages:

| Call | Made by |
|---|---|
| `clone(CLONE_NEWUSER\|SIGCHLD)`, then `unshare(CLONE_NEWPID)` in the child | Start-up test for usable user namespaces |
| `clone(CLONE_NEWUSER\|CLONE_NEWIPC\|SIGCHLD)` | Socket process |
| `clone(CLONE_NEWUSER\|CLONE_NEWNET\|SIGCHLD)` | Media (RDD) process |
| `clone(CLONE_NEWUSER\|CLONE_NEWIPC\|CLONE_NEWNET\|SIGCHLD)` | Content and utility processes |
| `chroot("/proc/self/fdinfo")` | Every sandboxed child |

No `setns`, `mount`, `pivot_root` or other `unshare` call was made. These match
Firefox's source (`SandboxInfo.cpp`, `SandboxLaunch.cpp`).

## The chosen configuration

Docker's built-in profile was tried first and is not used, because it refuses
user-namespace creation and Firefox then runs its content processes without
namespaces or a chroot. The browser instead uses
`security/seccomp-firefox.json`: Docker's default profile with three rules
added. `security/README.md` holds the provenance (moby/profiles
`seccomp/v0.2.4`, commit `245180c5…`, Apache 2.0, the version Engine 29.9.2 is
built with) and a byte-identical copy of the upstream file.

Exact differences from upstream, all appended to `syscalls`:

```json
{ "names": ["clone"], "action": "SCMP_ACT_ALLOW",
  "args": [{ "index": 0, "value": 906100736, "valueTwo": 268435456, "op": "SCMP_CMP_MASKED_EQ" }],
  "excludes": { "caps": ["CAP_SYS_ADMIN"], "arches": ["s390", "s390x"] } }
{ "names": ["unshare"], "action": "SCMP_ACT_ALLOW",
  "args": [{ "index": 0, "value": 536870912, "op": "SCMP_CMP_EQ" }],
  "excludes": { "caps": ["CAP_SYS_ADMIN"] } }
{ "names": ["chroot"], "action": "SCMP_ACT_ALLOW",
  "excludes": { "caps": ["CAP_SYS_CHROOT"] } }
```

- **`clone`**: `906100736` is `0x36020000`, the bits for new user, PID, UTS,
  cgroup and mount namespaces; `268435456` is `0x10000000`, the user-namespace
  bit. The rule matches only when the user-namespace bit is set and the other
  four are clear. New IPC and network namespaces may accompany it, because
  Firefox asks for them. A new namespace without a new user namespace is still
  refused.
- **`unshare`**: only the exact argument `CLONE_NEWPID`. `unshare(CLONE_NEWUSER)`,
  which `unshare -Ur` uses, stays refused because Firefox never makes that call.
- **`chroot`**: the argument is a path, which seccomp cannot inspect. The kernel
  still demands `CAP_SYS_CHROOT` in the caller's user namespace. The container
  is not given that capability, so in practice only a process inside a user
  namespace it created can use the call.
- **`clone3`** keeps upstream's `ENOSYS` answer. Its flags are passed in memory
  where seccomp cannot read them, so it cannot be limited by argument.
- **Architectures**: on amd64 and arm64 the `clone` flags are the first
  argument, which is what the rule tests. The rule is excluded on s390, where
  the order differs. The profile keeps upstream's architecture map.

What the profile costs compared with Docker's built-in one: any process in the
browser container, not only Firefox, can create a user namespace with its own
network and IPC namespaces. Inside it the process holds capabilities over that
namespace only, which exposes kernel code (for example network configuration
inside the new network namespace) that the built-in profile keeps out of reach.
`mount`, `setns`, `bpf`, `keyctl`, `perf_event_open` and the rest remain
refused. Compared with the previous `seccomp=unconfined`, every process in the
container is now filtered.

There is no automatic fallback. If the profile cannot be applied, or Firefox
cannot create namespaces under it, the launch reports that and stops; it never
switches to `seccomp=unconfined`.

## What the verifier checks

`./verify.sh` (and every launch) checks Docker's confinement separately from
Firefox's:

| Check | Pass | Fail | Inconclusive |
|---|---|---|---|
| Daemon supports seccomp | daemon lists `seccomp` | daemon does not list it | daemon options unreadable |
| No opt-out | only `no-new-privileges` and a seccomp profile | `seccomp=unconfined`, `apparmor=unconfined`, privileged, or any other security option | |
| Profile selected | profile stored with the container equals `security/seccomp-firefox.json`, compared as parsed JSON | any other profile, the daemon default, or `unconfined` | stored profile or the repository file unreadable |
| Observed state | a UID 1000 process started outside Firefox has `Seccomp: 2` and `NoNewPrivs: 1` | `Seccomp: 0`, or `NoNewPrivs: 0` | probe could not run |
| Filter is acting | `unshare(0)` and `personality(ADDR_NO_RANDOMIZE)` refused | either call succeeds | any other result |
| Limits are in force | `clone3` gives `ENOSYS`; `unshare(CLONE_NEWUSER)` and `clone` with a new mount namespace refused | any of them is accepted | any other result |
| AppArmor | daemon lists `apparmor`, container profile is `docker-default`, observed label is `docker-default (enforce)` | another profile, `unconfined`, or complain mode | label unreadable; or a Linux daemon with no AppArmor |

Docker stores a profile file as JSON text, usually re-serialised, so the profile
is compared by content. A file name, a label or `Seccomp: 2` alone is never
accepted as proof. On Docker Desktop the daemon offers no AppArmor; the verifier
prints a note and counts nothing for it.

The observed-state rows come from Python probes run in the browser container
as UID 1000. They are started with `python3 -I`, because that user's home is a
writable tmpfs and Python would otherwise run a `.pth` file found there inside
each probe; the numbers and words a probe reports are type- and range-checked
before they are used or shown. In the macOS fixture the interpreter, its
directory on `PATH` and its import path in isolated mode were not writable by
that user. This closes the demonstrated start-up injection path only. A probe
still runs inside the container it examines, so these rows are evidence about a
container that is behaving, not attestation of one that is already compromised.

The existing Firefox checks remain: every observed content process must have a
filter and `NoNewPrivs`. Two things changed. The user-namespace test now makes
Firefox's own two calls rather than running `unshare -Ur true`, which the chosen
profile refuses by design. When that test passes, content processes must also
be in their own user namespaces. When it does not pass, the result is
inconclusive and the message states that the error does not identify the layer.

## AppArmor and user namespaces on Ubuntu 24.04

Nothing in this section has been tested. It is what the primary sources say and
what the verifier will report.

- Docker generates and loads an AppArmor profile named `docker-default` and
  applies it to containers unless told otherwise. From Engine 29.8 the daemon
  can be configured to generate it from a custom template, so its content is a
  property of the host.
- Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor
  (`kernel.apparmor_restrict_unprivileged_userns`). The release notes say:
  "This affects all programs on the system that are unprivileged and unconfined."
  A container process under `docker-default` is confined, not unconfined.
  Whether that profile, on a given kernel and Docker version, lets UID 1000
  create a user namespace and then use it has not been observed here.
- Firefox's start-up test includes the `unshare(CLONE_NEWPID)` step specifically
  to detect policies that allow creating a user namespace but nothing useful
  inside it. The verifier makes the same two calls.

If AppArmor or a kernel setting refuses the namespace on Ubuntu, the launch ends
with exit status 2 (incomplete) and the requested URL is not opened. Do not
relax the host to get past that: no `SYS_ADMIN`, no `--privileged`, no
`apparmor=unconfined`, no sysctl change. Report it; the platform is then not
supported in this configuration.

Read-only commands that separate the layers on a Linux host:

```bash
python3 tests/host_baseline.py                 # host, daemon and kernel settings
docker inspect --format '{{.AppArmorProfile}}' safebrowse
docker exec --user 1000:1000 safebrowse cat /proc/self/attr/current
sudo dmesg | grep -E 'apparmor="DENIED"|audit.*seccomp'   # which layer logged a denial
```

An AppArmor denial is logged with `apparmor="DENIED"` and the profile name.
A seccomp refusal made with `SCMP_ACT_ERRNO`, which is what this profile uses,
is not logged at all, so the absence of a log line is not evidence either way.

## What the baseline check establishes

`python3 tests/host_baseline.py --require-linux-baseline` decides whether a host
is the configuration in the table at the top. The kernel settings it reads
(AppArmor, the user-namespace restriction) are always the local machine's, so
they describe the Docker daemon only if the daemon runs on that machine. The
check therefore has to establish locality before anything else counts, and a
matching distribution name is not accepted as evidence of it: a remote daemon on
the same Ubuntu release reports the same name.

The check accepts a host only when all of these hold:

| Requirement | How it is established |
|---|---|
| Docker is reached through a Unix socket | The Docker CLI is asked which context it is using (`docker context show`) and for that context's address (`docker context inspect`), in the same environment as the `docker version` and `docker info` queries, once before them and once after. The address must use `unix://`. Any path is accepted; none is hard-coded. |
| That socket exists on this machine | The path is examined with `stat` and must be a socket. |
| The answer is unambiguous | If `DOCKER_HOST` and `DOCKER_CONTEXT` are both set they must name the same endpoint. |
| Host and daemon are both Linux | `platform.system()` and the daemon's reported OS. |
| Same kernel | The daemon's kernel release equals the host's, and neither is empty. |
| Same architecture | Compared after mapping `x86_64` to `amd64` and `aarch64` to `arm64`. Any other architecture is refused. |
| Distribution, Engine version, rootful daemon, seccomp, AppArmor, non-root user, user-namespace restriction | As before; kept separate from the locality checks. |

TCP (including `localhost`), SSH, Windows named pipes and anything unrecognised
are refused. If any of these facts is missing, malformed or changes while it is
being collected, the host is refused with the specific reason. The plain
recorder (`python3 tests/host_baseline.py`) stays informational, prints the
transport and context name but never the address, and notes when the local
kernel settings it prints were not shown to belong to the daemon.

On precedence: Docker's CLI reference says `DOCKER_CONTEXT` overrides
`DOCKER_HOST`. Docker CLI 29.9.2, as observed on the test machine, and the
current CLI source do the opposite: with both set, `DOCKER_HOST` wins and the
`default` context is used. The check does not implement either rule. It reports
whatever the CLI itself resolves, which is where the queries actually went, and
refuses the baseline when the two variables disagree.

What remains an assumption. This is an operational check, not cryptographic
proof of the daemon's identity:

- A local Unix socket can be a proxy or a forwarded socket to another machine.
  If that machine reports the same kernel release and architecture, the check
  cannot tell. It does not try to attest the socket, and it uses no privileged
  container, host mount or daemon change to find out.
- Kernel release and architecture are the daemon's own statements. Two machines
  built from the same image report the same values.
- The check reads the daemon through the Docker CLI on `PATH`. A wrapper or
  alias named `docker` is trusted to behave like Docker's CLI.
- A daemon in a virtual machine on the same host (for example Docker Desktop
  for Linux) is refused only because its kernel release differs from the host's.

The tests for this check run offline against a simulated CLI. The check itself
has only been run on macOS, where it correctly refuses. It has not been run on
any Linux host, so improving it does not move the release gate below.

## Unsupported configurations

- **Launching as root or with `sudo`.** `run` and `pin` refuse before creating
  credentials, changing permissions, writing runtime files, building or tearing
  anything down. Files written as root would later be unreadable or unwritable
  for the normal user. `stop`, `logs` and `verify` may be invoked as root, so a
  session's containers can always be inspected and removed. That is not the
  same as `sudo ./stop.sh` succeeding: after removing the containers, `stop`
  cleans up generated VPN secrets under `.runtime`, and that step checks
  ownership for every user. Under `sudo` the directory belongs to someone else,
  so the cleanup is refused and `stop` exits non-zero, in either mode, with the
  containers already gone. Rerun it as your own user. The ownership check is
  deliberately not bypassed for root.
- **Rootless Docker.** `run` refuses when the daemon's own security options
  include `rootless`. This is read from `docker info`, not guessed from socket
  paths. Rootless mode changes networking, port publishing and capability
  handling, and none of SafeBrowse's isolation has been validated with it. That
  is a statement about what has been tested, not a claim that rootless Docker is
  less secure.
- **A daemon without seccomp**, or one whose security options cannot be read:
  `run` refuses. Nothing is installed, reconfigured or elevated automatically.

## Native Linux shares the host kernel

On macOS, Docker Desktop runs containers inside a Linux virtual machine, so a
kernel exploit from the browser container lands in that VM, not on the Mac. On
native Linux there is no such VM: the container's processes run on the host's
own kernel, separated by namespaces, capabilities, the seccomp profile and
AppArmor. The same kernel bug is therefore more serious on native Linux. Keep
the host kernel and Docker updated, and do not treat the two platforms as
equivalent.

## Remaining exceptions and maintenance

- The profile is wider than Docker's default by the three rules above. That is
  a deliberate, documented exception, not parity with the default.
- `chroot` cannot be limited by argument, and `clone3` cannot be filtered by
  flags at all.
- The profile is a copy of Docker's default at one revision. It does not follow
  the Engine's built-in profile when Docker is upgraded. On each Docker or image
  update, repeat the steps in `security/README.md`. `tests/test_security.py`
  fails unless the profile equals the vendored upstream file plus exactly the
  three rules.
- A Firefox update may change the calls it needs. The verifier's namespace and
  content-process checks will show that as a failure or an incomplete result;
  repeat the trace before changing the profile.
- The remote-desktop file-transfer limitation and the other items under *Known
  limitations* in `README.md` are unchanged.

## Release gate for native Linux

Native Linux may be described as supported only after all of the following have
been observed on Ubuntu 24.04, with AppArmor and the user-namespace restriction
left as installed, and recorded here with the output of
`python3 tests/host_baseline.py`:

1. `python3 tests/host_baseline.py --require-linux-baseline` exits 0, with
   Docker reached through this machine's own Unix socket.
2. `python3 -m unittest discover -s tests -v` passes on Python 3.12.
3. `python3 tests/integration.py` and `python3 tests/cli_integration.py` pass,
   including the AppArmor check and Firefox's user-namespace test.
4. Kernel, architecture, Engine and Compose versions, the browser's AppArmor
   profile and the user-namespace settings are written into the table at the
   top of this file.

**Current state: not met.** None of the four has been run.

VPN mode ([VPN_SECURITY.md](VPN_SECURITY.md)) is outside this gate and adds
Linux unknowns of its own: kernel WireGuard from inside a container, reading
the 0600 configuration through a bind mount, named interfaces and the embedded
resolver on the baseline's Docker Engine, and AppArmor's effect on the VPN
container. Meeting the gate above does not verify VPN mode on Linux; that also
needs `python3 tests/integration_vpn.py` to pass there. It has not been run on
any Linux host.

## Sources

Read on 2026-11-12.

- Docker, *Seccomp security profiles for Docker*: https://docs.docker.com/engine/security/seccomp/
- Docker, *AppArmor security profiles for Docker*: https://docs.docker.com/engine/security/apparmor/
- Docker CLI reference, environment variables and `--host`: https://docs.docker.com/reference/cli/docker/
- Docker, *Docker contexts*, and `docker context show` / `inspect`: https://docs.docker.com/engine/manage-resources/contexts/
- docker/cli, `resolveContextName` in `cli/command/cli.go`: https://github.com/docker/cli/blob/master/cli/command/cli.go
- moby/profiles, default seccomp profile and tags: https://github.com/moby/profiles
- moby/moby `go.mod` at `docker-v29.9.2` and `docker-v29.9.3` (seccomp module v0.2.4)
- Ubuntu 24.04 release notes, *Unprivileged user namespace restrictions*: https://documentation.ubuntu.com/release-notes/24.04/
- Ubuntu, *Restricted unprivileged user namespaces are coming to Ubuntu 23.10*: https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces
- Mozilla, `security/sandbox/linux/SandboxInfo.cpp` and `launch/SandboxLaunch.cpp`: https://searchfox.org/mozilla-central/source/security/sandbox/linux/
- Mozilla, *Security/Sandbox*: https://wiki.mozilla.org/Security/Sandbox
