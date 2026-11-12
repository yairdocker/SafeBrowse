# security/

`seccomp-firefox.json` is the syscall filter Docker applies to the browser
container. It is selected in one place, the shared browser service in
`compose.services.yml` (`seccomp=./security/seccomp-firefox.json`), which both
topologies extend: `docker-compose.yml` (direct) and `docker-compose.vpn.yml`
(VPN). Neither topology file names the profile itself. Compose reads the file
when it creates the container. It is not mounted into any container and is not
part of the image build context.

## Provenance

| | |
|---|---|
| Upstream project | [moby/profiles](https://github.com/moby/profiles), Apache License 2.0 |
| Upstream file | `seccomp/default.json` |
| Revision | tag `seccomp/v0.2.4`, commit `245180c51918481c0525424b3ee025d2b435d46c` |
| Why this revision | Docker Engine 29.9.2 and 29.9.3 build their built-in filter from `github.com/moby/profiles/seccomp v0.2.4` (their `go.mod`) |
| Retrieved | 2026-11-12 from `https://raw.githubusercontent.com/moby/profiles/seccomp/v0.2.4/seccomp/default.json` |
| SHA-256 of the upstream file | `785b2429264afba4d594320337cb17f144f3c7d51585f9805eef72e28f4f9334` |

`upstream/moby-seccomp-default.json` is that file, byte for byte, and
`upstream/LICENSE` is the licence it is distributed under. Neither is used at
run time; they exist so the difference can be checked.

## Changes from upstream

`seccomp-firefox.json` is the upstream file with three rules appended to
`syscalls`. Nothing else differs. Each added rule carries a `comment` that
starts with `SafeBrowse:`. This file is therefore a modified copy of an Apache
2.0 work; this section is the notice of those modifications.

| Added rule | Limits | Why |
|---|---|---|
| `clone` | Allowed only when `flags & 0x36020000 == 0x10000000`: a new user namespace is requested, and no new mount, cgroup, UTS or PID namespace. New IPC and network namespaces may accompany it. | Firefox starts every sandboxed child this way. |
| `unshare` | Allowed only when the argument is exactly `CLONE_NEWPID` (`0x20000000`). | Firefox's start-up test for usable user namespaces makes this call inside the namespace it has just created. Without it Firefox turns its namespace sandbox off. |
| `chroot` | No argument limit is possible (the argument is a path). The kernel still requires `CAP_SYS_CHROOT` in the caller's user namespace, which the container itself does not have. | Firefox chroots each sandboxed child into an empty directory. Without it those children exit. |

`clone3`, `setns`, `mount` and every other call keep upstream's treatment.
`LINUX_SECURITY.md` in the repository root records the tests behind each rule
and what the rules cost.

## Updating

1. Find the `github.com/moby/profiles/seccomp` version in the `go.mod` of the
   Docker Engine release you run.
2. Replace `upstream/moby-seccomp-default.json` with that tag's
   `seccomp/default.json`, and update the table above and the hash in
   `tests/test_security.py`.
3. Re-apply the three rules, then run the offline tests and the three container
   suites (`tests/integration.py`, `tests/cli_integration.py` and
   `tests/integration_vpn.py`). `tests/test_security.py` fails if the profile is
   anything other than the vendored upstream file plus exactly these rules.

## gluetun-auth.toml

Used only in VPN mode. Gluetun v3.41.3 always starts a control server and, when
no authorisation file is present, lets any local client change the VPN state
without credentials. This file gives one route a role (`GET /v1/version`, no
authentication) so that every other route has none and answers 401. SafeBrowse
also binds the server to loopback and never calls it. The file contains no
secret. See [VPN_SECURITY.md](../VPN_SECURITY.md).
