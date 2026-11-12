#!/usr/bin/env python3
"""Read-only checks of the running sandbox. Requires Python 3.12+ on the host."""
import argparse
import contextlib
import io
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import NamedTuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
import pin  # the image inventory
import vpn  # the generated firewall rules; nothing here reads a WireGuard configuration
BROWSER = "safebrowse"
GATEWAY = "safebrowse-gw"
NETWORK = "safebrowse_sandbox"
PROXY = "http://gateway:3128"
UBO = "uBlock0@raymondhill.net"
CAPS = {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID", "KILL"}
APPARMOR_PROFILE = "docker-default"
VPN_CAPS = {"NET_ADMIN", "DAC_OVERRIDE"}
VPN_MOUNTS = {"/run/secrets/wg0.conf": vpn.CONFIG, "/iptables/post-rules.txt": vpn.RULES,
              "/gluetun/auth/config.toml": "gluetun-auth.toml"}
# Gluetun's health and control servers (loopback only) and Docker's resolver; Squid is the only other listener.
VPN_LOOPBACK_LISTENERS = {"127.0.0.1:8000", "127.0.0.1:9999"}
AUXILIARY_PORTS = (53, 8000, 8388, 8888, 9999)
SESSION_LABEL = re.compile(r"[a-z0-9]{1,32}")
FINGERPRINT_LABEL = "safebrowse.vpn-config-sha256"
# The only upstream Docker's resolver may hold for the browser: the browser container's own loopback.
BROWSER_DNS = "127.0.0.1"
# Only the two daemon fields the confinement checks need; never the whole of `docker info`.
DAEMON_FORMAT = '{"security": {{json .SecurityOptions}}, "os": {{json .OperatingSystem}}}'


DENIED_URLS = ("http://192.168.1.1/", "http://10.0.0.1/", "http://172.16.0.1/",
               "http://169.254.169.254/", "http://127.0.0.1/", "http://0.0.0.0/",
               "http://100.64.0.1/", "http://[::1]/", "http://[fc00::1]/",
               "http://host.docker.internal/", "http://doubleclick.net/", "http://localtest.me/",
               "http://example.com:8080/")


class Runtime(NamedTuple):
    """Explicit fixture settings for integration tests; CLI uses production defaults."""
    browser: str = BROWSER
    gateway: str = GATEWAY
    ui: str = "safebrowse-ui"
    network: str = NETWORK
    proxy: str = PROXY
    ui_port: str = "3011"
    policy_path: Path = ROOT / "policies/firefox-policies.json"
    allowed_url: str = "https://example.com/"
    denied_urls: tuple = DENIED_URLS
    direct_host: str = "1.1.1.1"
    direct_port: int = 443
    subnet: str = ""
    seccomp_profile: Path = ROOT / "security/seccomp-firefox.json"
    vpn: str = "safebrowse-vpn"
    egress: str = "safebrowse_egress"
    # Networks a fixture adds to the direct-mode gateway. Production has none.
    gateway_networks: tuple = ()
    external_name: str = "example.com"
    # An address outside every local network, used only to ask the kernel which route it would take.
    route_probe: str = "198.51.100.1"


DEFAULT = Runtime()


def run(*args, input=None, timeout=30):
    return subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)


def docker_json(*args):
    result = run("docker", *args)
    if result.returncode:
        raise RuntimeError("Docker inspection failed: " + " ".join(args))
    return json.loads(result.stdout)


def execute(*args, input=None, config=DEFAULT):
    # Match Firefox's unprivileged UID, rather than probing as container root.
    return run("docker", "exec", "-i", "--user", "1000:1000", config.browser,
               *args, input=input)


# Every Python probe below runs in the browser container through this one command. -I is Python's
# isolated mode: no user site directory (the browser user's home is a writable tmpfs, and a .pth
# file there would otherwise run inside each probe), no PYTHON* environment variables, and neither
# the working directory nor the script's directory on the import path. It closes that start-up
# injection path only. It does not make a compromised container's answers trustworthy.
PROBE_PYTHON = ("python3", "-I", "-c")


def run_probe(source, *args, config=DEFAULT):
    """Run one of this file's Python probes as UID 1000 in the browser container, in isolated mode."""
    return execute(*PROBE_PYTHON, source, *args, config=config)


def probe_json(result, kind):
    """What a probe printed, parsed, if it ran and printed JSON of the expected type; otherwise None.

    A probe's output comes from inside the container. It is never trusted to be
    well formed, and nothing below prints a value from it that has not been checked
    against a fixed list or pattern first.
    """
    try:
        value = json.loads(result.stdout) if result.returncode == 0 else None
    except ValueError:
        return None
    return value if isinstance(value, kind) else None


def whole_number(value, low, high):
    """True for a real integer in range; JSON true/false and floats are not numbers here."""
    return type(value) is int and low <= value <= high


class Report:
    def __init__(self):
        self.counts = {"PASS": 0, "FAIL": 0, "INCONCLUSIVE": 0}

    def emit(self, state, message):
        self.counts[state] += 1
        # One result is one line. Anything unprintable is replaced, so no text that reaches a
        # message can move the cursor, start a new line or imitate another result.
        print(f"  {state}  " + "".join(character if character.isprintable() else "?" for character in str(message)))

    def check(self, condition, message):
        self.emit("PASS" if condition else "FAIL", message)

    def finish(self):
        print("\n  " + ", ".join(f"{v} {k.lower()}" for k, v in self.counts.items()))
        print("  These checks do not prove absence of escapes or forensic traces.")
        if self.counts["FAIL"]:
            return 1
        return 2 if self.counts["INCONCLUSIVE"] else 0


def check_isolation(report, browser, ui, network, config=DEFAULT):
    host = browser["HostConfig"]
    report.check(not any(m.get("Type") in ("bind", "volume") for m in browser["Mounts"]),
                 "browser has no bind mounts or persistent volumes")
    opts = host.get("SecurityOpt") or []
    report.check(any(o in ("no-new-privileges", "no-new-privileges:true") for o in opts),
                 "no-new-privileges is enabled")
    added = {c.removeprefix("CAP_") for c in (host.get("CapAdd") or [])}
    report.check("ALL" in (host.get("CapDrop") or []) and added <= CAPS and not host.get("Privileged"),
                 "capabilities are within the startup allowlist; container is not privileged")
    report.check(not host.get("PortBindings"), "browser publishes no ports")
    report.check(set(browser["NetworkSettings"]["Networks"]) == {config.network},
                 "browser belongs only to the expected sandbox network")
    report.check(network.get("Internal") is True and network.get("Driver") == "bridge",
                 "sandbox bridge is internal")
    report.check(network.get("Options", {}).get("com.docker.network.bridge.gateway_mode_ipv4") == "isolated"
                 and not network.get("EnableIPv6"),
                 "sandbox bridge has isolated IPv4 gateway mode and IPv6 is disabled")
    if config.subnet:
        actual = [entry.get("Subnet") for entry in (network.get("IPAM", {}).get("Config") or [])]
        report.check(actual == [config.subnet], "sandbox bridge uses the selected subnet")
    bindings = ui["HostConfig"].get("PortBindings") or {}
    report.check(bindings == {"3001/tcp": [{"HostIp": "127.0.0.1", "HostPort": config.ui_port}]},
                 f"desktop is published only on 127.0.0.1:{config.ui_port}")
    tmpfs = host.get("Tmpfs") or {}
    # Docker supports both HostConfig.Tmpfs and Mounts Type=tmpfs.
    report.check("/config" in tmpfs or any(m.get("Type") == "tmpfs" and m.get("Destination") == "/config"
                                          for m in browser["Mounts"]),
                 "browser profile is on tmpfs (not a guarantee against swap)")
    report.check(0 < host.get("Memory", 0) <= 4 * 1024**3 and
                 0 < host.get("NanoCpus", 0) <= 4 * 10**9 and
                 0 < (host.get("PidsLimit") or 0) <= 1024,
                 "browser memory, CPU, and process limits are enforced")


# Runs as UID 1000 through `docker exec`, so it is outside Firefox and outside the
# filters Firefox installs on its own content processes. Each call happens in a
# throwaway child process; nothing it changes outlives the probe.
OUTER_PROBE = r"""import ctypes, errno, json, os, platform
libc = ctypes.CDLL(None, use_errno=True)
number = {"x86_64": 56, "aarch64": 220}.get(platform.machine())

def attempt(call):
    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            ctypes.set_errno(0)
            value = call()
            os.write(writer, json.dumps([value, ctypes.get_errno()]).encode())
        finally:
            os._exit(0)
    os.close(writer)
    data = os.read(reader, 256)
    os.close(reader)
    os.waitpid(pid, 0)
    if not data:
        return None
    value, code = json.loads(data)
    return "ok" if value != -1 else errno.errorcode.get(code, str(code))

def clone(flags):
    if number is None:
        return None
    pid = libc.syscall(ctypes.c_long(number), ctypes.c_ulong(flags | 17), ctypes.c_long(0), ctypes.c_long(0),
                       ctypes.c_long(0), ctypes.c_long(0))
    if pid == 0:
        os._exit(0)
    if pid > 0:
        os.waitpid(pid, 0)
    return -1 if pid < 0 else 0

status = {}
with open("/proc/self/status") as f:
    for line in f:
        key, _, value = line.partition(":")
        status[key] = value.strip()
label = None
for path in ("/proc/self/attr/apparmor/current", "/proc/self/attr/current"):
    try:
        with open(path) as f:
            label = f.read().strip("\0\n ")
        break
    except OSError:
        continue
print(json.dumps({
    "uid": os.getuid(), "seccomp": int(status.get("Seccomp", "-1")), "nnp": int(status.get("NoNewPrivs", "-1")),
    "apparmor": label,
    "calls": {
        "unshare_none": attempt(lambda: libc.unshare(0)),
        "personality": attempt(lambda: libc.personality(ctypes.c_ulong(0x0040000))),
        "clone3": attempt(lambda: libc.syscall(ctypes.c_long(435), ctypes.c_long(0), ctypes.c_long(0))),
        "unshare_user": attempt(lambda: libc.unshare(0x10000000)),
        "clone_user_mount": attempt(lambda: clone(0x10000000 | 0x00020000)),
    }}))
"""


def security_options(values):
    """Docker's 'name=seccomp,profile=builtin' strings as {name: {key: value}}."""
    parsed = {}
    for value in values:
        fields = dict(part.partition("=")[::2] for part in value.split(","))
        parsed[fields.get("name", "")] = fields
    return parsed


def daemon_security():
    """{'security': [...], 'os': '...'} from the daemon, or None if it cannot be read."""
    try:
        result = run("docker", "info", "--format", DAEMON_FORMAT)
        data = json.loads(result.stdout) if result.returncode == 0 else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if (not isinstance(data, dict) or not isinstance(data.get("os"), str) or not isinstance(data.get("security"), list)
            or not all(isinstance(value, str) for value in data["security"])):
        return None
    return data


def seccomp_choice(options):
    """How the container selects its filter: default, disabled, custom or unreadable.

    Docker stores a profile file as its JSON text, usually re-serialised, so a
    custom profile is returned parsed and is compared by content, not by name.
    """
    values = [re.split("[=:]", option, maxsplit=1)[1] for option in options if re.match(r"seccomp[=:]", option)]
    if not values:
        return "default", None
    if len(values) > 1:
        return "unreadable", None
    if values[0] == "unconfined":
        return "disabled", None
    if values[0] == "builtin":
        return "default", None
    try:
        profile = json.loads(values[0])
    except ValueError:
        return "unreadable", None
    return ("custom", profile) if isinstance(profile, dict) else ("unreadable", None)


def reviewed_option(option):
    """The security options the reviewed Compose file may produce; anything else is an opt-out or unknown."""
    if option in ("no-new-privileges", "no-new-privileges:true", "no-new-privileges=true", "apparmor=" + APPARMOR_PROFILE):
        return True
    return re.match(r"seccomp[=:]", option) is not None and re.split("[=:]", option, maxsplit=1)[1] != "unconfined"


def check_confinement(report, browser, daemon, config=DEFAULT):
    """Docker's own confinement of the browser container, separate from Firefox's sandbox."""
    host = browser["HostConfig"]
    options = host.get("SecurityOpt") or []
    names = security_options(daemon["security"]) if daemon else {}
    if daemon is None:
        report.emit("INCONCLUSIVE", "Docker daemon security options could not be read")
    else:
        report.check("seccomp" in names, "Docker daemon supports seccomp filtering")
    report.check(all(reviewed_option(option) for option in options) and not host.get("Privileged"),
                 "browser does not opt out of confinement: no seccomp=unconfined, apparmor=unconfined or unreviewed option")

    choice, profile = seccomp_choice(options)
    if choice == "custom":
        try:
            approved = json.loads(config.seccomp_profile.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            report.emit("INCONCLUSIVE", "approved seccomp profile could not be read from this checkout")
        else:
            report.check(profile == approved,
                         "browser was created with exactly the approved seccomp profile (compared by content)")
    elif choice == "disabled":
        report.emit("FAIL", "browser was created with seccomp=unconfined: Docker's outer syscall filter is disabled")
    elif choice == "default":
        report.emit("FAIL", "browser uses the daemon's default seccomp profile, not the approved one in security/")
    else:
        report.emit("INCONCLUSIVE", "browser seccomp profile could not be read from Docker")

    probe = probe_json(run_probe(OUTER_PROBE, config=config), dict)
    if probe is None or not whole_number(probe.get("uid"), 1000, 1000) or not isinstance(probe.get("calls"), dict):
        probe = None
        report.emit("INCONCLUSIVE", "outer confinement probe could not run as UID 1000 in the browser container")
    else:
        calls = probe["calls"]
        seccomp, nnp = probe.get("seccomp"), probe.get("nnp")
        if whole_number(seccomp, 0, 0):
            report.emit("FAIL", "a UID 1000 process outside Firefox's sandbox has no seccomp filter")
        elif whole_number(seccomp, 2, 2) and whole_number(nnp, 0, 1):
            report.check(nnp == 1, "a UID 1000 process outside Firefox's sandbox runs with a seccomp filter "
                                            "and no-new-privileges")
        else:
            report.emit("INCONCLUSIVE", "seccomp state of a UID 1000 browser-container process is unreadable")
        # The kernel lets any process make these two calls, so a refusal can only come from a filter.
        permitted = [calls.get("unshare_none"), calls.get("personality")]
        message = "outer filter refuses unshare(0) and personality(ADDR_NO_RANDOMIZE), which the kernel itself always permits"
        report.emit("FAIL" if "ok" in permitted else "PASS" if permitted == ["EPERM", "EPERM"] else "INCONCLUSIVE", message)
        # A refusal here could also come from kernel policy, so it is only consistent with the
        # approved profile; an acceptance proves the profile's argument limits are not in force.
        restricted = [calls.get("clone3"), calls.get("unshare_user"), calls.get("clone_user_mount")]
        message = ("namespace calls outside the approved set are refused: clone3, unshare(CLONE_NEWUSER), "
                   "clone with a new mount namespace")
        if "ok" in restricted or restricted[0] in ("EINVAL", "EFAULT", "E2BIG"):
            report.emit("FAIL", message)
        else:
            report.emit("PASS" if restricted == ["ENOSYS", "EPERM", "EPERM"] else "INCONCLUSIVE", message)

    profile, label = browser.get("AppArmorProfile"), probe.get("apparmor") if probe else None
    if daemon is None:
        report.emit("INCONCLUSIVE", "AppArmor support of the Docker daemon is unknown")
    elif "apparmor" in names:
        if profile == APPARMOR_PROFILE and label is None:
            report.emit("INCONCLUSIVE", "AppArmor label of a browser-container process could not be read")
        else:
            report.check(profile == APPARMOR_PROFILE and label == APPARMOR_PROFILE + " (enforce)",
                         f"browser is confined by AppArmor profile {APPARMOR_PROFILE} in enforce mode")
    elif daemon["os"] == "Docker Desktop":
        print("  NOTE  this Docker Desktop daemon offers no AppArmor; nothing to check (see LINUX_SECURITY.md)")
    else:
        report.emit("INCONCLUSIVE", "daemon reports no AppArmor: outside the validated Linux baseline (LINUX_SECURITY.md)")


def classify_denial(code, returncode, headers=""):
    if returncode:
        return "INCONCLUSIVE"
    if code == "403" and re.search(r"^X-Squid-Error:\s*ERR_ACCESS_DENIED(?:\s|$)", headers, re.I | re.M):
        return "PASS"
    if re.fullmatch(r"[23]\d\d", code):
        return "FAIL"
    return "INCONCLUSIVE"


def check_proxy(report, url, denied=True, config=DEFAULT):
    result = execute("curl", "--disable", "--silent", "--show-error", "--max-time", "10",
                     "--noproxy", "", "--proxy", config.proxy, "--output", "/dev/null",
                     "--dump-header", "-", "--write-out", "\n%{http_code}", url, config=config)
    headers, _, code = result.stdout.strip().rpartition("\n")
    if denied:
        state = classify_denial(code, result.returncode, headers)
    else:
        state = "PASS" if result.returncode == 0 and re.fullmatch(r"2[0-9][0-9]", code) else "FAIL"
    # The status line comes from inside the container: only three digits are ever shown.
    shown = code if re.fullmatch(r"[0-9]{3}", code) else "unreadable" if code else "missing"
    report.emit(state, f"{'proxy denial' if denied else 'proxy web access'}: {url} "
                f"(HTTP {shown}, curl exit {result.returncode})")


DIRECT_PROBE = '''import json, socket, sys
s = socket.socket()
s.settimeout(5)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
except OSError as e:
    print(json.dumps({"connected": False, "errno": e.errno}))
else:
    print(json.dumps({"connected": True}))
finally:
    s.close()
'''


# Linux ENETUNREACH / EHOSTUNREACH / EACCES are explicit routing/firewall failures.
# A TLS failure, timeout, missing binary, or refused TCP connection is not proof.
BLOCKED_ERRORS = {13: "EACCES", 101: "ENETUNREACH", 113: "EHOSTUNREACH"}


def check_direct(report, config=DEFAULT):
    result = run_probe(DIRECT_PROBE, config.direct_host, str(config.direct_port), config=config)
    if result.returncode:
        report.emit("INCONCLUSIVE", "direct TCP probe could not execute")
        return
    probe = probe_json(result, dict)
    message = "direct external TCP connection blocked"
    # Exactly the two shapes the probe prints; the result is described here, never echoed.
    if probe == {"connected": True} and probe["connected"] is True:
        report.emit("FAIL", message + ": the connection succeeded")
    elif (probe is not None and set(probe) == {"connected", "errno"} and probe["connected"] is False
          and (probe["errno"] is None or whole_number(probe["errno"], 0, 4095))):
        code = probe["errno"]
        if code in BLOCKED_ERRORS:
            report.emit("PASS", message + f": refused with {BLOCKED_ERRORS[code]} (errno {code})")
        else:
            report.emit("INCONCLUSIVE", message + ": not connected, " + ("no error code" if code is None else f"errno {code}")
                        + ", which is not an explicit routing or firewall refusal")
    else:
        report.emit("INCONCLUSIVE", message + ": the probe's result could not be read")


PROFILE_PROBE = '''import os, json
results = []
for directory, _, names in os.walk("/config"):
    if "extensions.json" not in names: continue
    path = os.path.join(directory, "extensions.json")
    with open(path) as f:
        for addon in json.load(f).get("addons", []):
            if addon.get("id") == "uBlock0@raymondhill.net":
                results.append({k: addon.get(k) for k in ("active", "userDisabled", "appDisabled", "version")})
print(json.dumps(results))
'''

SANDBOX_PROBE = '''import glob, json
processes = []
def mapping(pid):
    try:
        with open("/proc/%s/uid_map" % pid) as f:
            return f.read().split()
    except OSError:
        return None
container = mapping(1)
for path in glob.glob("/proc/[0-9]*/cmdline"):
    try:
        args = open(path, "rb").read().replace(b"\\0", b" ").split()
        if b"-contentproc" not in args or b"firefox" not in args[0] or b"tab" not in args: continue
        with open(path.replace("cmdline", "status")) as f:
            status = dict(line.split(":", 1) for line in f if ":" in line)
        if not status.get("Name", "").strip().startswith(("Web Content", "Isolated Web")): continue
        own = mapping(path.split("/")[2])
        processes.append({"seccomp": int(status.get("Seccomp", "0").strip()),
                          "nnp": int(status.get("NoNewPrivs", "0").strip()),
                          "userns": None if own is None or container is None else own != container})
    except (FileNotFoundError, ProcessLookupError):
        continue
print(json.dumps(processes))
'''


# The two calls Firefox itself makes to decide whether it can sandbox with namespaces:
# clone(CLONE_NEWUSER), then unshare(CLONE_NEWPID) inside the new namespace.
NAMESPACE_PROBE = r"""import ctypes, errno, json, os, platform
libc = ctypes.CDLL(None, use_errno=True)
number = {"x86_64": 56, "aarch64": 220}.get(platform.machine())
result = {"clone": None, "unshare": None, "settings": {}}
for name in ("user/max_user_namespaces", "kernel/unprivileged_userns_clone",
             "kernel/apparmor_restrict_unprivileged_userns"):
    try:
        with open("/proc/sys/" + name) as f:
            result["settings"][name.replace("/", ".")] = f.read().strip()
    except OSError:
        pass
if number is not None:
    reader, writer = os.pipe()
    ctypes.set_errno(0)
    pid = libc.syscall(ctypes.c_long(number), ctypes.c_ulong(0x10000000 | 17), ctypes.c_long(0), ctypes.c_long(0),
                       ctypes.c_long(0), ctypes.c_long(0))
    if pid == 0:
        try:
            code = 0 if libc.unshare(0x20000000) == 0 else (ctypes.get_errno() or 255)
            os.write(writer, bytes([min(code, 255)]))
        finally:
            os._exit(0)
    if pid < 0:
        result["clone"] = errno.errorcode.get(ctypes.get_errno(), "error")
    else:
        os.close(writer)
        data = os.read(reader, 1)
        os.waitpid(pid, 0)
        result["clone"] = "ok"
        result["unshare"] = "no result" if not data else "ok" if data == b"\0" else errno.errorcode.get(data[0], "error")
print(json.dumps(result))
"""


# The settings the namespace probe may report, and the only words it may use for a call's outcome:
# "ok", "no result", "error", or an errno name such as EPERM.
NAMESPACE_SETTINGS = ("kernel.apparmor_restrict_unprivileged_userns", "kernel.unprivileged_userns_clone",
                      "user.max_user_namespaces")
CALL_OUTCOME = re.compile(r"ok|no result|error|E[A-Z0-9]{1,15}")


def call_outcome(value):
    """A call's outcome as the probe may legitimately report it; anything else is not repeated."""
    if value is None:
        return "not attempted"
    return value if isinstance(value, str) and CALL_OUTCOME.fullmatch(value) else "unreadable"


def namespace_state(result):
    """PASS only when both calls demonstrably succeeded; a denial does not say which layer denied it."""
    probe = probe_json(result, dict)
    if probe is None:
        return "INCONCLUSIVE", "could not be probed"
    if probe.get("clone") == "ok" and probe.get("unshare") == "ok":
        return "PASS", "succeeded (clone with CLONE_NEWUSER, then unshare(CLONE_NEWPID), as Firefox does)"
    settings = probe.get("settings") if isinstance(probe.get("settings"), dict) else {}
    seen = ", ".join(f"{key}={settings[key]}" for key in NAMESPACE_SETTINGS
                     if isinstance(settings.get(key), str) and re.fullmatch(r"[0-9]{1,10}", settings[key]))
    return "INCONCLUSIVE", (f"failed (clone: {call_outcome(probe.get('clone'))}, unshare: "
                            f"{call_outcome(probe.get('unshare'))}); the error alone "
                            f"does not identify seccomp, AppArmor or a kernel setting" + (f" [{seen}]" if seen else ""))


def check_browser(report, config=DEFAULT):
    state, detail = namespace_state(run_probe(NAMESPACE_PROBE, config=config))
    report.emit(state, "user namespace creation as Firefox UID " + detail)
    records = probe_json(run_probe(SANDBOX_PROBE, config=config), list) or []
    readable = all(isinstance(p, dict) and whole_number(p.get("seccomp"), 0, 2) and whole_number(p.get("nnp"), 0, 1)
                   and (p.get("userns") is None or isinstance(p.get("userns"), bool)) for p in records)
    if not records or not readable:
        report.emit("INCONCLUSIVE", "no readable Firefox content processes; open a page and rerun")
    else:
        report.check(all(p["seccomp"] == 2 and p["nnp"] == 1 for p in records),
                     "observed Firefox content processes have seccomp filters and no-new-privileges")
        if state == "PASS":
            # Firefox's own filter is one layer; its namespaces and chroot are the other.
            separated = [p.get("userns") for p in records]
            report.emit("INCONCLUSIVE" if None in separated else "PASS" if all(separated) else "FAIL",
                        "observed Firefox content processes run in their own user namespaces")
    policy = execute("cat", "/etc/firefox/policies/policies.json", config=config)
    expected = json.loads(config.policy_path.read_text())
    report.check(probe_json(policy, dict) == expected,
                 "deployed policy JSON matches repository (check about:policies for application/errors)")
    addons = probe_json(run_probe(PROFILE_PROBE, config=config), list) or []
    if not addons or not all(isinstance(a, dict) for a in addons):
        report.emit("INCONCLUSIVE", "no readable live uBlock registration; open a page and rerun")
    else:
        report.check(all(a.get("active") is True and a.get("userDisabled") is False and
                         a.get("appDisabled") is False for a in addons),
                     "uBlock is active and enabled in every discovered profile registration")


def clipboard_state(logs):
    states = []
    for key in ("clipboard_in_enabled", "clipboard_out_enabled"):
        matches = re.findall(r"'" + key + r"':\s*\((True|False)(?:,|\))", logs)
        states.append(matches[-1] if matches else None)
    if "True" in states:
        return "FAIL"
    return "PASS" if states == ["False", "False"] else "INCONCLUSIVE"


def check_pins(report):
    """Every listed image is pinned by digest, no reference pin.py recognises is unlisted, and PINS.txt agrees."""
    pinned, unlisted = pin.inventory(ROOT)
    for repo, reference in pinned.items():
        report.check(reference is not None, f"{repo} uses an explicit digest")
    report.check(not unlisted, "no recognised image reference is outside the pinned set" +
                 (f" (found {', '.join(unlisted)})" if unlisted else ""))
    recorded = [line for line in (ROOT / "PINS.txt").read_text().splitlines() if line and not line.startswith("#")]
    report.check(None not in pinned.values() and sorted(recorded) == sorted(pinned.values()),
                 "PINS.txt agrees with all image references")


# ---------------------------------------------------------------------------
# Session mode. Labels say what a session claims to be; everything after that
# checks the live containers against the claim.
# ---------------------------------------------------------------------------
def declared_mode(containers):
    """(mode, session) when every container carries the same valid labels, else (None, None)."""
    labels = [(container.get("Config") or {}).get("Labels") or {} for container in containers]
    declared = {(label.get("safebrowse.schema"), label.get("safebrowse.session"), label.get("safebrowse.mode"))
                for label in labels}
    if len(declared) != 1:
        return None, None
    schema, session, mode = declared.pop()
    if schema != "1" or mode not in ("direct", "vpn") or not SESSION_LABEL.fullmatch(session or ""):
        return None, None
    if mode == "direct" and any(label.get(FINGERPRINT_LABEL) for label in labels):
        return None, None  # a direct session has no VPN configuration to have a fingerprint of
    return mode, session


def check_fingerprint(report, containers):
    """A VPN session's containers all say which generated configuration the session was created with.

    The launcher compares a stored configuration with this value before reusing it.
    Nothing here reads that configuration.
    """
    values = {((container.get("Config") or {}).get("Labels") or {}).get(FINGERPRINT_LABEL) or "" for container in containers}
    message = "every VPN session container carries the same fingerprint of the configuration the session was created with"
    if values == {""}:
        report.emit("INCONCLUSIVE", message + ": this session predates fingerprints, so its stored configuration cannot "
                                              "be checked before reuse. Start a new one with "
                                              "./run.sh --fresh --vpn mullvad --vpn-config PATH")
    else:
        report.check(len(values) == 1 and vpn.FINGERPRINT.fullmatch(next(iter(values))) is not None, message)


def optional_container(name):
    """Inspect a container that may legitimately be absent: its JSON, or None when Docker says there is none."""
    result = run("docker", "inspect", "--type", "container", name)
    if result.returncode:
        if "no such" in result.stderr.lower():
            return None
        raise RuntimeError("Docker inspection failed: " + name)
    return json.loads(result.stdout)[0]


# Runs as UID 1000 in the browser container. It reports what the container's resolver
# configuration is and how two lookups ended, as words from a fixed list: never an
# exception's text, and never anything the looked-up server sent back.
RESOLVER_PROBE = r"""import json, os, re, socket, struct, sys, time

def configuration():
    servers, upstream = [], None
    try:
        with open("/etc/resolv.conf") as f:
            for line in f.read(65536).splitlines():
                fields = line.split()
                if len(fields) >= 2 and fields[0] == "nameserver":
                    servers.append(fields[1][:64])
                noted = re.match(r"#\s*ExtServers:\s*\[(.*)\]\s*$", line)
                if noted:
                    upstream = [entry[:64] for entry in noted.group(1).split()]
    except OSError:
        return None, None
    return servers[:8], None if upstream is None else upstream[:8]

def ask(server, name):
    # One A query sent straight to the resolver, so its own answer is seen rather than libc's summary of it.
    try:
        question = b"".join(bytes([len(label)]) + label for label in name.encode("ascii").split(b".") if label)
        ident = os.urandom(2)
        query = ident + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + question + b"\0" + struct.pack("!HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except (OSError, ValueError):
        return "error"
    try:
        deadline = time.monotonic() + 5
        s.settimeout(5)
        s.connect((server, 53))
        s.send(query)
        while True:
            s.settimeout(max(0.05, deadline - time.monotonic()))
            reply = s.recv(4096)
            if len(reply) >= 12 and reply[:2] == ident and reply[2] & 0x80:
                break
            if time.monotonic() >= deadline:
                return "timeout"
    except socket.timeout:
        return "timeout"
    except OSError:
        return "error"
    finally:
        s.close()
    code, answers = reply[3] & 15, struct.unpack("!H", reply[6:8])[0]
    if code == 0:
        return "answer" if answers else "negative"
    return {3: "negative", 2: "failure", 5: "failure"}.get(code, "error")

def lookup(name):
    # What a program in the container gets, including /etc/hosts and search domains.
    try:
        socket.getaddrinfo(name, 80)
        return "resolved"
    except socket.gaierror as error:
        if error.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", None)):
            return "negative"
        return "temporary" if error.errno == socket.EAI_AGAIN else "error"
    except OSError:
        return "error"

servers, upstream = configuration()
result = {"servers": servers, "upstream": upstream}
for key, name in (("internal", sys.argv[1]), ("external", sys.argv[2])):
    result[key] = {"resolver": ask(servers[0], name) if servers else "error", "lookup": lookup(name)}
print(json.dumps(result))
"""

RESOLVER_OUTCOMES = {"answer", "negative", "failure", "timeout", "error"}
LOOKUP_OUTCOMES = {"resolved", "negative", "temporary", "error"}


def resolver_probe(result):
    """The probe's report with every field checked against what the probe can legitimately print, else None."""
    probe = probe_json(result, dict)
    if probe is None:
        return None
    for key in ("servers", "upstream"):
        value = probe.setdefault(key, None)
        if value is not None and not (isinstance(value, list) and all(isinstance(entry, str) for entry in value)):
            return None
    for key in ("internal", "external"):
        outcome = probe.get(key)
        if (not isinstance(outcome, dict) or outcome.get("resolver") not in RESOLVER_OUTCOMES
                or outcome.get("lookup") not in LOOKUP_OUTCOMES):
            return None
    return probe


def check_resolver(report, browser, config=DEFAULT):
    """The browser container's DNS can reach Docker's resolver and nothing beyond the container itself.

    A lookup that fails says little: a resolver somewhere else may have received the
    query and answered that the name does not exist, or simply have been slow. So the
    verdict rests on two things together. Enforcement: Docker was told that the only
    server its resolver may pass a name on to is the browser container's own loopback
    address, and the container's resolver configuration says the same. Behaviour: the
    gateway's name resolves, and an external name gets an explicit refusal from that
    resolver. Either one alone is not a PASS.
    """
    internal = re.sub(r"^[a-z]+://|:[0-9]+$", "", config.proxy)
    probe = resolver_probe(run_probe(RESOLVER_PROBE, internal, config.external_name, config=config))
    declared = (browser.get("HostConfig") or {}).get("Dns")
    message = ("browser DNS forwarding is restricted: Docker's resolver is the browser container's only nameserver "
               f"and may pass a name on only to the container's own loopback address ({BROWSER_DNS})")
    if declared != [BROWSER_DNS]:
        enforced, detail = "FAIL", "the container was not created with that restriction; start a new session with ./run.sh --fresh"
    elif probe is None or probe["servers"] is None:
        enforced, detail = "INCONCLUSIVE", "the container's resolver configuration could not be read"
    elif probe["servers"] != [vpn.DOCKER_RESOLVER]:
        enforced, detail = "FAIL", "the container names another nameserver"
    elif probe["upstream"] is None:
        enforced, detail = "INCONCLUSIVE", "Docker did not record which servers its resolver may forward to"
    elif probe["upstream"] != [BROWSER_DNS]:
        enforced, detail = "FAIL", "Docker's resolver holds a different forwarding target"
    else:
        enforced, detail = "PASS", ""
    report.emit(enforced, message + (f": {detail}" if detail else ""))

    message = (f"browser name resolution: the gateway's name resolves, and an external name ({config.external_name}) "
               "is refused by Docker's resolver without being resolved")
    if probe is None:
        report.emit("INCONCLUSIVE", message + ": the lookups could not be run")
        return
    inside, outside = probe["internal"], probe["external"]
    seen = f" [resolver: {outside['resolver']}, lookup: {outside['lookup']}]"
    if outside["resolver"] == "answer" or outside["lookup"] == "resolved":
        report.emit("FAIL", message + seen)
    elif enforced != "PASS":
        report.emit("INCONCLUSIVE", message + seen + ": without the restriction above, a lookup that did not succeed "
                                                     "does not show that no query left the container")
    elif (inside == {"resolver": "answer", "lookup": "resolved"} and outside["resolver"] == "failure"
          and outside["lookup"] in ("temporary", "negative")):
        report.emit("PASS", message + seen)
    else:
        report.emit("INCONCLUSIVE", message + seen + ": a timeout, an error or a name-does-not-exist answer is not "
                                                     "the explicit refusal the restricted resolver gives")


def check_direct_topology(report, gateway, tunnel, config=DEFAULT):
    report.check(tunnel is None, f"a direct session has no VPN container ({config.vpn}) belonging to this instance")
    mode = gateway["HostConfig"].get("NetworkMode") or ""
    report.check(not mode.startswith(("container:", "service:", "host")) and
                 set(gateway["NetworkSettings"]["Networks"]) == {config.network, config.egress, *config.gateway_networks},
                 "gateway has its own network namespace, on the sandbox and egress networks only")


LISTEN_PROBE = '''import json, select, socket, sys, time
host, ports = sys.argv[1], [int(p) for p in sys.argv[2:]]
pending, results = {}, {}
for port in ports:
    s = socket.socket()
    s.setblocking(False)
    try:
        code = s.connect_ex((host, port))
    except OSError as error:
        results[port], code = "unresolved", None
        s.close()
        continue
    pending[s] = port
deadline = time.monotonic() + 4
while pending and time.monotonic() < deadline:
    _, writable, _ = select.select([], list(pending), [], max(0, deadline - time.monotonic()))
    for s in writable:
        error = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        results[pending.pop(s)] = "connected" if error == 0 else "refused" if error == 111 else "error"
        s.close()
for s, port in pending.items():
    results[port] = "silent"
    s.close()
print(json.dumps(results))
'''

# Everything the VPN checks read from inside the namespace. None of these commands prints key material;
# `wg show` and the configuration files are never touched.
VPN_PROBE = """
echo @namespace; readlink /proc/self/ns/net
echo @addresses; ip -o -4 addr show
echo @addresses6; ip -o -6 addr show scope global
echo @link; ip -d -o link show tun0
echo @rules; ip -4 rule show
echo @table; ip -4 route show table 51820
echo @route; ip -4 route get "$1"
echo @route6; ip -6 route show default
echo @filter; iptables -S
echo @filter6; ip6tables -S
echo @listeners; netstat -tln
"""


def sections(text):
    result, current = {}, None
    for line in text.splitlines():
        if line.startswith("@"):
            current = result.setdefault(line[1:], [])
        elif current is not None and line.strip():
            current.append(line.rstrip())
    return result


def interface_in(addresses, subnet):
    """Names of the interfaces holding an address inside `subnet`, from `ip -o -4 addr show`."""
    names = []
    for line in addresses:
        match = re.match(r"\d+:\s+(\S+)\s+inet\s+([0-9.]+)/\d+", line)
        if match and subnet and ipaddress.ip_address(match[2]) in ipaddress.ip_network(subnet):
            names.append(match[1])
    return names


def chain(rules, name):
    return [rule for rule in rules if rule.startswith(f"-A {name} ")]


def check_firewall(report, rules, rules6, subnet):
    """The live rule set must be the generated one, evaluated before anything Gluetun adds."""
    policies = [rule for rule in rules if rule.startswith("-P ")]
    first = [(chain(rules, name) or [""])[0] for name in ("INPUT", "OUTPUT", "FORWARD")]
    report.check(sorted(policies) == ["-P FORWARD DROP", "-P INPUT DROP", "-P OUTPUT DROP"] and first ==
                 ["-A INPUT -j SAFEBROWSE_INPUT", "-A OUTPUT -j SAFEBROWSE_OUTPUT", "-A FORWARD -j DROP"],
                 "VPN namespace firewall drops by default and evaluates SafeBrowse's chains before every other rule")
    endpoints = [re.fullmatch(rf"-A SAFEBROWSE_OUTPUT -d ([0-9.]+)/32 -o {vpn.EGRESS_INTERFACE} -p udp -m udp "
                              r"--dport ([0-9]+) -j ACCEPT", rule) for rule in chain(rules, "SAFEBROWSE_OUTPUT")]
    endpoints = [match.groups() for match in endpoints if match]
    message = ("SafeBrowse's firewall chains are exactly the generated rules: new connections only to tcp/3128 from "
               "the sandbox subnet, and nothing leaves except WireGuard to one endpoint and the tunnel itself")
    if len(endpoints) != 1 or not subnet:
        report.emit("FAIL", message)
        return
    expected = vpn.chain_rules(subnet, *endpoints[0])
    report.check(all(chain(rules, name) == list(expected[name]) for name in expected), message)
    # Gluetun's own rule for the server it connects to must name the same endpoint.
    own = [rule for rule in chain(rules, "OUTPUT") if "--dport" in rule and f"-o {vpn.EGRESS_INTERFACE}" in rule]
    report.check(own == [f"-A OUTPUT -d {endpoints[0][0]}/32 -o {vpn.EGRESS_INTERFACE} -p udp -m udp --dport "
                         f"{endpoints[0][1]} -j ACCEPT"],
                 "the tunnel connects to the single WireGuard endpoint the firewall allows")
    if not rules6:
        report.emit("INCONCLUSIVE", "IPv6 firewall of the VPN namespace could not be read")
    else:
        report.check(sorted(rule for rule in rules6 if rule.startswith("-P ")) ==
                     ["-P FORWARD DROP", "-P INPUT DROP", "-P OUTPUT DROP"]
                     and not any(rule.startswith("-A INPUT") and "-i lo" not in rule and "ctstate" not in rule for rule in rules6),
                     "IPv6 is dropped by default in the VPN namespace and accepts no new inbound traffic")


def check_vpn_topology(report, browser, gateway, tunnel, session, config=DEFAULT):
    """VPN mode: Squid lives in the VPN container's namespace, whose only way out is the tunnel."""
    host = tunnel["HostConfig"]
    settings = tunnel["NetworkSettings"]
    report.check(gateway["HostConfig"].get("NetworkMode") == "container:" + tunnel["Id"],
                 "gateway's network mode names this VPN container, not an earlier one")
    report.check(not gateway["NetworkSettings"].get("Networks") and not gateway["HostConfig"].get("PortBindings"),
                 "gateway has no network attachment or published port of its own")
    networks = settings.get("Networks") or {}
    aliases = {name: (network.get("Aliases") or []) + (network.get("DNSNames") or []) for name, network in networks.items()}
    report.check(set(networks) == {config.network, config.egress} and "gateway" in aliases.get(config.network, [])
                 and "gateway" not in aliases.get(config.egress, []),
                 "VPN container is attached to exactly the sandbox and egress networks; 'gateway' names it only on the sandbox")
    report.check(not host.get("PortBindings") and not any((settings.get("Ports") or {}).values()),
                 "VPN container publishes no ports")
    added = {c.removeprefix("CAP_") for c in (host.get("CapAdd") or [])}
    options = host.get("SecurityOpt") or []
    report.check("ALL" in (host.get("CapDrop") or []) and added <= VPN_CAPS and not host.get("Privileged")
                 and not host.get("Devices") and all(reviewed_option(option) for option in options)
                 and any(option.startswith("no-new-privileges") for option in options)
                 and host.get("NetworkMode") not in ("host", "none") and host.get("PidMode") in ("", None)
                 and host.get("IpcMode") in ("", "private", "shareable", None) and not host.get("Sysctls")
                 and (host.get("RestartPolicy") or {}).get("Name") in ("", "no", None),
                 "VPN container holds only NET_ADMIN and DAC_OVERRIDE: not privileged, no devices, host namespaces, "
                 "sysctls or restart policy")
    mounts = tunnel.get("Mounts") or []
    sources = {mount.get("Destination"): Path(mount.get("Source") or "") for mount in mounts}
    generated = [destination for destination, name in VPN_MOUNTS.items() if name != "gluetun-auth.toml"]
    report.check(set(sources) == set(VPN_MOUNTS) and len(mounts) == len(VPN_MOUNTS)
                 and all(mount.get("Type") == "bind" and mount.get("RW") is False for mount in mounts)
                 and all(sources[destination].name == VPN_MOUNTS[destination] for destination in VPN_MOUNTS)
                 and all(sources[destination].parts[-4:-1] == (".runtime", "vpn", session) for destination in generated),
                 "VPN container mounts only its three read-only files, the generated ones from this session's private directory")

    result = run("docker", "exec", config.vpn, "sh", "-c", VPN_PROBE, "probe", config.route_probe)
    inside = sections(result.stdout) if result.returncode == 0 else {}
    other = run("docker", "exec", config.gateway, "readlink", "/proc/self/ns/net")
    ours = (inside.get("namespace") or [""])[0]
    theirs = other.stdout.strip() if other.returncode == 0 else ""
    message = "gateway and VPN container share one live network namespace"
    if not re.fullmatch(r"net:\[\d+\]", ours) or not re.fullmatch(r"net:\[\d+\]", theirs):
        report.emit("INCONCLUSIVE", message + " (could not be read)")
    elif ours != theirs:
        report.emit("FAIL", message + ": the gateway is attached to a stale namespace because the VPN container was "
                            "restarted or replaced. A session is not repaired in place; run ./run.sh --fresh")
    else:
        report.emit("PASS", message)
    if not inside:
        report.emit("INCONCLUSIVE", "VPN namespace could not be inspected")
        return

    egress = docker_json("network", "inspect", config.egress)[0]
    subnets = [entry.get("Subnet") for entry in (egress.get("IPAM", {}).get("Config") or []) if entry.get("Subnet")]
    addresses = inside.get("addresses", [])
    report.check(interface_in(addresses, config.subnet) == [vpn.SANDBOX_INTERFACE] and len(subnets) == 1
                 and interface_in(addresses, subnets[0]) == [vpn.EGRESS_INTERFACE],
                 f"the interfaces holding the sandbox and egress subnets are the ones the firewall names "
                 f"({vpn.SANDBOX_INTERFACE}, {vpn.EGRESS_INTERFACE})")
    link = " ".join(inside.get("link", []))
    table = inside.get("table", [])
    report.check("wireguard" in link and "LOWER_UP" in link and len(table) == 1
                 and table[0].startswith(f"default dev {vpn.TUNNEL_INTERFACE}")
                 and any("lookup 51820" in rule for rule in inside.get("rules", []))
                 and f" dev {vpn.TUNNEL_INTERFACE} " in " ".join(inside.get("route", [])) + " ",
                 "a kernel WireGuard interface is up and is the route for traffic that is not local")
    check_firewall(report, inside.get("filter", []), inside.get("filter6", []), config.subnet)
    report.check(not inside.get("addresses6") and not inside.get("route6"),
                 "IPv4 only: the VPN namespace has no global IPv6 address and no IPv6 default route")
    listeners = [line.split()[3] for line in inside.get("listeners", []) if line.startswith("tcp") and "LISTEN" in line]
    report.check(bool(listeners) and all(
        address in VPN_LOOPBACK_LISTENERS or address.startswith(vpn.DOCKER_RESOLVER + ":")
        or address.rsplit(":", 1)[1] == str(vpn.PROXY_PORT) for address in listeners)
        and any(address.rsplit(":", 1)[1] == str(vpn.PROXY_PORT) for address in listeners),
        "the only TCP listener beyond loopback in the VPN namespace is Squid on port 3128")

    host_name = re.sub(r"^[a-z]+://|:[0-9]+$", "", config.proxy)
    probe = probe_json(run_probe(LISTEN_PROBE, host_name, str(vpn.PROXY_PORT), *map(str, AUXILIARY_PORTS), config=config), dict)
    message = (f"from the browser, the gateway accepts connections on port {vpn.PROXY_PORT} only "
               f"(ports {', '.join(map(str, AUXILIARY_PORTS))} do not answer)")
    if probe is None:
        report.emit("INCONCLUSIVE", message)
    else:
        reached = [port for port in AUXILIARY_PORTS if probe.get(str(port)) == "connected"]
        report.emit("FAIL" if reached or probe.get(str(vpn.PROXY_PORT)) != "connected" else
                    "PASS" if all(probe.get(str(port)) in ("silent", "refused") for port in AUXILIARY_PORTS)
                    else "INCONCLUSIVE", message)


def check_browser_ready(report, config=DEFAULT, wait_seconds=0):
    """Allow initial profile registration to settle, without hiding final failures."""
    deadline = time.monotonic() + wait_seconds
    while True:
        attempt = Report()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            check_browser(attempt, config)
        if attempt.counts["FAIL"] or not attempt.counts["INCONCLUSIVE"] or time.monotonic() >= deadline:
            print(output.getvalue(), end="")
            for state, count in attempt.counts.items():
                report.counts[state] += count
            return
        time.sleep(min(2, max(0, deadline - time.monotonic())))


def main(config=DEFAULT, wait_browser=0):
    report = Report()
    try:
        browser, gateway, ui = docker_json("inspect", config.browser, config.gateway, config.ui)
        tunnel = optional_container(config.vpn)
        mode, session = declared_mode([browser, gateway, ui])
        expected = [browser, gateway, ui] + ([tunnel] if mode == "vpn" and tunnel else [])
        if not all(c.get("State", {}).get("Running") for c in expected) or (mode == "vpn" and tunnel is None):
            report.emit("FAIL", "every session container must be running; run ./run.sh first "
                                "(a stopped VPN or gateway container is not restarted: use ./run.sh --fresh)")
            return report.finish()
        if mode == "vpn" and declared_mode([tunnel]) != (mode, session):
            report.emit("FAIL", "the VPN container does not carry this session's labels, so it is not this session's tunnel")
            return report.finish()
        if mode is None:
            # Never pick a topology to check on the session's behalf.
            report.emit("INCONCLUSIVE", "session containers do not declare one consistent session and mode; the session "
                                        "predates mode labels or was changed by hand. Start a new one with "
                                        "./run.sh --fresh --direct or ./run.sh --fresh --vpn mullvad --vpn-config PATH")
            return report.finish()
        report.emit("PASS", f"all session containers declare the same session, in {mode} mode")
        network = docker_json("network", "inspect", config.network)[0]
        check_isolation(report, browser, ui, network, config)
        if mode == "vpn":
            check_fingerprint(report, [browser, gateway, ui, tunnel])
            check_vpn_topology(report, browser, gateway, tunnel, session, config)
        else:
            check_direct_topology(report, gateway, tunnel, config)
        check_confinement(report, browser, daemon_security(), config)
        report.check(gateway["HostConfig"].get("LogConfig", {}).get("Type") == "none"
                     and "/var/log/squid" in (gateway["HostConfig"].get("Tmpfs") or {}),
                     "gateway diagnostics are on tmpfs and Docker log storage is disabled")
        check_direct(report, config)
        check_resolver(report, browser, config)
        check_proxy(report, config.allowed_url, denied=False, config=config)
        for url in config.denied_urls:
            check_proxy(report, url, config=config)
        check_browser_ready(report, config, wait_browser)
        logs = run("docker", "logs", "--since", browser["State"]["StartedAt"], config.browser)
        report.emit(clipboard_state(logs.stdout + logs.stderr) if logs.returncode == 0 else "INCONCLUSIVE",
                    "both clipboard directions explicitly disabled in current-start logs")
        print("  LIMITATION  sidebar file transfer remains available; hidden controls are not enforcement")
        if mode == "vpn":
            print("  LIMITATION  these checks show the gateway can only leave through the tunnel; they do not identify "
                  "the VPN provider, its server or what it logs")
        check_pins(report)
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError, RuntimeError,
            subprocess.SubprocessError) as error:
        # Never dump inspect JSON/environment or logs, which may contain credentials.
        report.emit("INCONCLUSIVE", f"verification could not complete ({type(error).__name__}); inspect Docker/image prerequisites")
    return report.finish()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wait-browser", action="store_true", help="allow up to 30 seconds for Firefox profile initialization")
    args = parser.parse_args()
    try:
        from network import STATE, current
        subnet = str(current()) if STATE.exists() or STATE.is_symlink() else "172.28.0.0/24"
    except (OSError, ValueError, RuntimeError):
        print("  INCONCLUSIVE  selected sandbox subnet is unavailable; run ./run.sh first", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(DEFAULT._replace(subnet=subnet), wait_browser=30 if args.wait_browser else 0))
