#!/usr/bin/env python3
"""Print the host and Docker daemon facts that LINUX_SECURITY.md records. Read-only.

  python3 tests/host_baseline.py
      Print the facts. Nothing is changed and nothing is started.
  python3 tests/host_baseline.py --require-linux-baseline
      Also exit 1 unless this is the Linux configuration SafeBrowse targets: Ubuntu 24.04,
      a rootful Docker Engine 28+ reached through a local Unix socket and reporting this
      host's own kernel and architecture, with seccomp and AppArmor active, Ubuntu's
      restriction on unprivileged user namespaces still on, and not run as root.

The daemon's own answers are used for everything about the daemon. The launcher's
platform says nothing about where the daemon runs: on macOS it is a Linux VM, and
DOCKER_HOST or a Docker context can point at another machine entirely. The kernel
settings printed here are always this machine's, so they describe the daemon only
when the daemon is shown to run here. A matching distribution name does not show that.

Which endpoint is in use is asked of the Docker CLI itself, in the same environment
as every other query, because Docker's documentation and its CLI do not agree on
whether DOCKER_CONTEXT or DOCKER_HOST wins when both are set. This is an operational
check, not cryptographic proof of the daemon's identity: a local Unix socket that
forwards to another machine with the same kernel release and architecture would pass.
"""
import argparse
import json
import os
import platform
import stat
import subprocess
import sys

DOCKER_VERSION = ('{"client": {{json .Client.Version}}, "server": {{json .Server.Version}}, "os": {{json .Server.Os}}, '
                  '"arch": {{json .Server.Arch}}, "kernel": {{json .Server.KernelVersion}}}')
DOCKER_INFO = ('{"system": {{json .OperatingSystem}}, "security": {{json .SecurityOptions}}, '
               '"cgroup": {{json .CgroupVersion}}, "storage": {{json .Driver}}}')
# Only the name and the address of a context: never its TLS material, storage paths or metadata.
CONTEXT_ENDPOINT = '{"name": {{json .Name}}, "host": {{json .Endpoints.docker.Host}}}'
SCHEMES = ("unix", "tcp", "ssh", "npipe", "fd", "http", "https")
ARCHITECTURES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
# Kernel settings that decide whether an unprivileged process may create a user namespace.
SETTINGS = ("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined",
            "/proc/sys/kernel/unprivileged_userns_clone", "/proc/sys/user/max_user_namespaces",
            "/sys/module/apparmor/parameters/enabled", "/sys/kernel/security/lsm")


def docker(env, *args):
    """One read-only Docker CLI query, in the given environment, bounded by a timeout."""
    try:
        result = subprocess.run(("docker",) + args, capture_output=True, text=True, timeout=30, env=env)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def structured(env, *args):
    try:
        data = json.loads(docker(env, *args) or "")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def is_socket(path):
    """True or False for a path on this machine; None if it cannot be examined."""
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        return None


def context_endpoint(env, name=None):
    """(context name, endpoint address) as the CLI itself resolves it, or None."""
    if name is None:
        name = docker(env, "context", "show")
        if not name:
            return None
    data = structured(env, "context", "inspect", name, "--format", CONTEXT_ENDPOINT)
    if data.get("name") != name or not isinstance(data.get("host"), str) or not data["host"]:
        return None
    return name, data["host"]


def scheme_of(address):
    scheme, separator, rest = address.partition("://")
    return scheme.lower() if separator and rest and scheme.lower() in SCHEMES else "unrecognised"


def endpoint_facts(env, before, after):
    """What identifies the endpoint the queries used, without its address.

    `before` and `after` are the CLI's answers on either side of the daemon queries.
    """
    facts = {"context": None, "transport": None, "socket_present": None,
             "docker_host_set": bool(env.get("DOCKER_HOST")), "docker_context_set": bool(env.get("DOCKER_CONTEXT")),
             "variables_agree": None, "resolved": False}
    if before is None or before != after:
        return facts
    name, address = before
    facts.update(context=name, transport=scheme_of(address), resolved=True)
    if facts["transport"] == "unix":
        facts["socket_present"] = is_socket(address.partition("://")[2])
    if facts["docker_host_set"] and facts["docker_context_set"]:
        # Docker's documentation says DOCKER_CONTEXT overrides DOCKER_HOST; its CLI does the
        # opposite. Only when both name the same endpoint is the answer the same either way.
        named = context_endpoint(env, env["DOCKER_CONTEXT"])
        facts["variables_agree"] = named is not None and named[1] == env["DOCKER_HOST"] == address
    return facts


def read(path):
    try:
        with open(path) as file:
            return file.read().strip()
    except OSError:
        return None


def os_release():
    fields = {}
    for line in (read("/etc/os-release") or "").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            fields[key] = value.strip('"')
    return fields


def gather(environ=None):
    # One environment for every query, so the endpoint that is recorded is the one that was asked.
    env = dict(os.environ if environ is None else environ)
    release = os_release()
    before = context_endpoint(env)
    daemon = dict(structured(env, "version", "--format", DOCKER_VERSION), compose=docker(env, "compose", "version", "--short"),
                  **structured(env, "info", "--format", DOCKER_INFO))
    return {
        "host": {"system": platform.system(), "kernel": platform.release(), "machine": platform.machine(),
                 "distribution": release.get("PRETTY_NAME"), "id": release.get("ID"), "version": release.get("VERSION_ID"),
                 "python": platform.python_version(), "euid": getattr(os, "geteuid", lambda: None)()},
        "endpoint": endpoint_facts(env, before, context_endpoint(env)),
        "docker": daemon,
        "settings": {path: read(path) for path in SETTINGS} if platform.system() == "Linux" else {},
    }


def locality_problems(facts):
    """Why the daemon is not shown to be this machine's own. A matching distribution name is not evidence."""
    host, daemon, endpoint = facts.get("host") or {}, facts.get("docker") or {}, facts.get("endpoint") or {}
    problems = []
    if not endpoint.get("resolved") or not endpoint.get("transport") or not endpoint.get("context"):
        problems.append("the Docker endpoint in use could not be determined ('docker context show' or 'docker context "
                        "inspect' failed, gave unusable output, or changed during collection); fix the Docker CLI "
                        "configuration and rerun")
    elif endpoint["transport"] != "unix":
        problems.append(f"Docker is reached over {endpoint['transport']} (context {endpoint.get('context')!r}), not a "
                        "local Unix socket. A TCP address, including localhost, SSH or a named pipe does not show the "
                        "daemon runs here: unset DOCKER_HOST and DOCKER_CONTEXT or select a context that uses this "
                        "machine's Docker socket")
    elif endpoint.get("socket_present") is not True:
        problems.append(f"the Unix socket of Docker context {endpoint.get('context')!r} does not exist on this machine "
                        "or cannot be examined")
    if endpoint.get("docker_host_set") and endpoint.get("docker_context_set") and endpoint.get("variables_agree") is not True:
        problems.append("DOCKER_HOST and DOCKER_CONTEXT are both set and do not name the same endpoint. Docker's "
                        "documentation and its CLI disagree about which of them wins, so unset one")
    if host.get("system") != "Linux" or daemon.get("os") != "linux":
        problems.append("the host and the daemon are not both Linux")
    kernels = (host.get("kernel"), daemon.get("kernel"))
    if not all(isinstance(kernel, str) and kernel.strip() for kernel in kernels):
        problems.append("the host's or the daemon's kernel release is unavailable")
    elif kernels[0] != kernels[1]:
        problems.append(f"the daemon reports kernel {kernels[1]} but this host runs {kernels[0]}: it is another machine "
                        "or a virtual machine, so the kernel settings above are not the daemon's")
    machines = [ARCHITECTURES.get(str(value).lower()) for value in (host.get("machine"), daemon.get("arch"))]
    if None in machines:
        problems.append("the host's or the daemon's architecture is unavailable or not one of amd64 and arm64")
    elif machines[0] != machines[1]:
        problems.append(f"the daemon reports architecture {machines[1]} but this host is {machines[0]}")
    return problems


def baseline_problems(facts):
    """Why this is not the validated Linux configuration; an empty list means it is."""
    host, daemon, settings = facts.get("host") or {}, facts.get("docker") or {}, facts.get("settings") or {}
    security = daemon.get("security") if isinstance(daemon.get("security"), list) else []
    names = {field.partition("=")[2] for option in security for field in str(option).split(",") if field.startswith("name=")}
    major = str(daemon.get("server") or "").split(".")[0]
    problems = locality_problems(facts)
    if (host.get("id"), host.get("version")) != ("ubuntu", "24.04"):
        problems.append("host is not Ubuntu 24.04")
    # A distribution check only: the same name on both sides says nothing about where the daemon runs.
    if not daemon.get("system") or daemon.get("system") != host.get("distribution"):
        problems.append("the daemon reports a different operating system from this host's distribution "
                        "(for example Docker Desktop)")
    if not major.isdigit() or int(major) < 28:
        problems.append("Docker Engine is older than 28 or its version is unreadable")
    if not daemon.get("compose"):
        problems.append("Docker Compose v2 is unavailable")
    for name in ("seccomp", "apparmor"):
        if name not in names:
            problems.append(f"the daemon does not report {name}")
    for name in ("rootless", "userns"):
        if name in names:
            problems.append(f"the daemon reports {name}, which SafeBrowse has not been validated with")
    if host.get("euid") == 0:
        problems.append("running as root")
    if settings.get("/sys/module/apparmor/parameters/enabled") != "Y":
        problems.append("AppArmor is not enabled in the kernel")
    if settings.get("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") != "1":
        problems.append("kernel.apparmor_restrict_unprivileged_userns is not 1, so Ubuntu's user-namespace restriction "
                        "has been relaxed or is unreadable")
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--require-linux-baseline", action="store_true")
    args = parser.parse_args(argv)
    facts = gather()
    if facts["settings"] and locality_problems(facts):
        print("NOTE  the settings.* lines below are this machine's; the daemon was not shown to run on it")
    for section, values in facts.items():
        for key, value in values.items():
            print(f"{section}.{key}: {'unavailable' if value is None else value}")
    if not args.require_linux_baseline:
        return 0
    problems = baseline_problems(facts)
    for problem in problems:
        print(f"NOT THE LINUX BASELINE  {problem}")
    if not problems:
        print("This host matches the Linux baseline described in LINUX_SECURITY.md.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
