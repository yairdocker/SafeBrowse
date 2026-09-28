#!/usr/bin/env python3
"""Read-only checks of the running sandbox. Requires Python 3.9+ on the host."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import NamedTuple

ROOT = Path(__file__).resolve().parent.parent
BROWSER = "safebrowse"
GATEWAY = "safebrowse-gw"
NETWORK = "safebrowse_sandbox"
PROXY = "http://gateway:3128"
UBO = "uBlock0@raymondhill.net"
CAPS = {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID", "KILL"}


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


class Report:
    def __init__(self):
        self.counts = {"PASS": 0, "FAIL": 0, "INCONCLUSIVE": 0}

    def emit(self, state, message):
        self.counts[state] += 1
        print(f"  {state}  {message}")

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
        state = "PASS" if result.returncode == 0 and re.fullmatch(r"2\d\d", code) else "FAIL"
    report.emit(state, f"{'proxy denial' if denied else 'proxy web access'}: {url} "
                f"(HTTP {code or 'missing'}, curl exit {result.returncode})")


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


def check_direct(report, config=DEFAULT):
    result = execute("python3", "-c", DIRECT_PROBE, config.direct_host, str(config.direct_port), config=config)
    if result.returncode:
        report.emit("INCONCLUSIVE", "direct TCP probe could not execute")
        return
    probe = json.loads(result.stdout)
    # Linux ENETUNREACH / EHOSTUNREACH / EACCES are explicit routing/firewall failures.
    # A TLS failure, timeout, missing binary, or refused TCP connection is not proof.
    if probe.get("connected"):
        state = "FAIL"
    elif probe.get("errno") in (13, 101, 113):
        state = "PASS"
    else:
        state = "INCONCLUSIVE"
    report.emit(state, f"direct external TCP connection blocked: {probe}")


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
for path in glob.glob("/proc/[0-9]*/cmdline"):
    try:
        args = open(path, "rb").read().replace(b"\\0", b" ").split()
        if b"-contentproc" not in args or b"firefox" not in args[0] or b"tab" not in args: continue
        with open(path.replace("cmdline", "status")) as f:
            status = dict(line.split(":", 1) for line in f if ":" in line)
        if not status.get("Name", "").strip().startswith(("Web Content", "Isolated Web")): continue
        processes.append({"seccomp": int(status.get("Seccomp", "0").strip()),
                          "nnp": int(status.get("NoNewPrivs", "0").strip())})
    except (FileNotFoundError, ProcessLookupError):
        continue
print(json.dumps(processes))
'''


def check_browser(report, config=DEFAULT):
    ns = execute("unshare", "-Ur", "true", config=config)
    report.emit("PASS" if ns.returncode == 0 else "INCONCLUSIVE",
                "user namespace creation as Firefox UID " + ("succeeded" if ns.returncode == 0 else "failed"))
    process = execute("python3", "-c", SANDBOX_PROBE, config=config)
    records = json.loads(process.stdout) if process.returncode == 0 else []
    if not records:
        report.emit("INCONCLUSIVE", "no readable Firefox content processes; open a page and rerun")
    else:
        report.check(all(p["seccomp"] == 2 and p["nnp"] == 1 for p in records),
                     "observed Firefox content processes have seccomp filters and no-new-privileges")
    policy = execute("cat", "/etc/firefox/policies/policies.json", config=config)
    expected = json.loads(config.policy_path.read_text())
    report.check(policy.returncode == 0 and json.loads(policy.stdout) == expected,
                 "deployed policy JSON matches repository (check about:policies for application/errors)")
    result = execute("python3", "-c", PROFILE_PROBE, config=config)
    addons = json.loads(result.stdout) if result.returncode == 0 else []
    if not addons:
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
    dockerfile = (ROOT / "Dockerfile").read_text()
    compose = (ROOT / "docker-compose.yml").read_text()
    expected = []
    for repo, text in (("lscr.io/linuxserver/firefox", dockerfile), ("ubuntu/squid", compose),
                       ("alpine/socat", compose)):
        refs = re.findall(r"^\s*(?:FROM\s+|image:\s*)" + re.escape(repo) + r"([^\s]+)\s*$", text, re.M)
        valid = len(refs) == 1 and re.fullmatch(r"@sha256:[0-9a-f]{64}", refs[0]) is not None
        report.check(valid, f"{repo} uses an explicit digest")
        if valid:
            expected.append(repo + refs[0])
    recorded = [line for line in (ROOT / "PINS.txt").read_text().splitlines() if line and not line.startswith("#")]
    report.check(len(expected) == 3 and sorted(recorded) == sorted(expected),
                 "PINS.txt agrees with all image references")


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
        if not all(c.get("State", {}).get("Running") for c in (browser, gateway, ui)):
            report.emit("FAIL", "all three containers must be running; run ./run.sh first")
            return report.finish()
        network = docker_json("network", "inspect", config.network)[0]
        check_isolation(report, browser, ui, network, config)
        report.check(gateway["HostConfig"].get("LogConfig", {}).get("Type") == "none"
                     and "/var/log/squid" in (gateway["HostConfig"].get("Tmpfs") or {}),
                     "gateway diagnostics are on tmpfs and Docker log storage is disabled")
        check_direct(report, config)
        check_proxy(report, config.allowed_url, denied=False, config=config)
        for url in config.denied_urls:
            check_proxy(report, url, config=config)
        check_browser_ready(report, config, wait_browser)
        logs = run("docker", "logs", "--since", browser["State"]["StartedAt"], config.browser)
        report.emit(clipboard_state(logs.stdout + logs.stderr) if logs.returncode == 0 else "INCONCLUSIVE",
                    "both clipboard directions explicitly disabled in current-start logs")
        print("  LIMITATION  sidebar file transfer remains available; hidden controls are not enforcement")
        check_pins(report)
    except (OSError, ValueError, KeyError, TypeError, IndexError, RuntimeError, subprocess.SubprocessError) as error:
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
