#!/usr/bin/env python3
"""Drive the real launcher against a disposable fixture: launch, resume, replace, tear down.

Run:  python3 tests/cli_integration.py

The launcher's own code runs unchanged with real Docker, real readiness probes and real
timing. Only the Session it acts on is replaced, in Python, with uniquely named fixture
containers, networks, a temporary localhost port and a temporary state directory. No
command-line flag or environment variable can select a fixture, and the fixture is
checked before use so it cannot name the real session.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "tests")]
from integration import SERVER, command, replace_once, require, wait_for  # noqa: E402
import safebrowse  # noqa: E402
import verify  # noqa: E402

PRODUCTION = safebrowse.Session()

# The fixture's helper scripts. Each loads the production module and runs it with
# explicit fixture settings, as tests/integration.py does for the verifier.
LOAD = '''import importlib.util, json, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
settings = json.loads((HERE / "fixture.json").read_text())
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
arguments = sys.argv[1:]
'''
VERIFY_DRIVER = LOAD + '''verify = load("production_verify", Path(settings["scripts"]) / "verify.py")
network = load("fixture_network", HERE / "network.py")
if arguments not in ([], ["--wait-browser"]):
    sys.exit("unexpected verifier arguments")
try:
    subnet = str(network.current())
except (OSError, ValueError, RuntimeError):
    print("  INCONCLUSIVE  selected sandbox subnet is unavailable", file=sys.stderr)
    sys.exit(2)
runtime = dict(settings["runtime"], subnet=subnet, policy_path=Path(settings["runtime"]["policy_path"]),
               denied_urls=tuple(settings["runtime"]["denied_urls"]),
               gateway_networks=tuple(settings["runtime"]["gateway_networks"]))
sys.exit(verify.main(verify.Runtime(**runtime), wait_browser=30 if arguments else 0))
'''
OPEN_DRIVER = LOAD + '''opener = load("production_open_url", Path(settings["scripts"]) / "open_url.py")
if len(arguments) != 1:
    sys.exit("unexpected opener arguments")
url = "about:blank" if arguments[0] == "--initialize" else opener.validate_url(arguments[0])
sys.exit(1 if opener.open_url(url, settings["runtime"]["browser"]) else 0)
'''


def replace_line(text, old, new):
    """Replace one whole line, keeping its indentation; fail if production changed."""
    lines = text.split("\n")
    matches = [index for index, line in enumerate(lines) if line.strip() == old]
    if len(matches) != 1:
        raise RuntimeError(f"fixture no longer matches production configuration: {old}")
    line = lines[matches[0]]
    lines[matches[0]] = line[:len(line) - len(line.lstrip())] + new
    return "\n".join(lines)


def unused_subnets(env):
    ids = command("docker", "network", "ls", "--quiet", env=env).stdout.split()
    used = []
    if ids:
        for network in json.loads(command("docker", "network", "inspect", *ids, env=env).stdout):
            used += [ipaddress.ip_network(c["Subnet"]) for c in (network.get("IPAM", {}).get("Config") or [])
                     if c.get("Subnet")]

    def unused(*pools):
        for pool in map(ipaddress.ip_network, pools):
            for candidate in pool.subnets(new_prefix=24):
                if not any(candidate.overlaps(other) for other in used if other.version == 4):
                    used.append(candidate)
                    return str(candidate)
        raise RuntimeError("no unused integration subnet")
    return unused


def snapshot(*paths):
    """Size and modification time of files this test must never touch."""
    return {str(path): (path.stat().st_size, path.stat().st_mtime_ns) if path.exists() else None for path in paths}


def main():
    # Keep the test independent of the caller's Compose overrides and credentials.
    env = {k: v for k, v in os.environ.items() if not k.startswith("COMPOSE_")
           and k not in ("SANDBOX_USER", "SANDBOX_PASSWORD", "SANDBOX_SUBNET", "SQUID_CONFIG_PATH")}
    major = int(command("docker", "version", "--format", "{{.Server.Version}}", env=env).stdout.split(".")[0])
    require(major >= 28, "Docker Engine supports isolated bridge mode (28+)")
    token = secrets.token_hex(5)
    project = "safebrowse-cli-" + token
    image = project + ":test"
    unused = unused_subnets(env)
    public_subnet = unused("198.18.0.0/15")
    private_subnet = unused("10.231.0.0/16", "10.0.0.0/8")
    public_ip = public_subnet.split("/")[0][:-1] + "10"
    # Requested only by name: Squid also checks IP-literal requests against the blocklist by
    # reverse lookup, so the blocklisted name must not share the address used for those.
    named_ip = public_subnet.split("/")[0][:-1] + "11"
    private_ip = private_subnet.split("/")[0][:-1] + "10"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    real_state = (ROOT / ".env", ROOT / ".runtime/network.json", ROOT / ".runtime/squid.conf")
    before = snapshot(*real_state)

    with tempfile.TemporaryDirectory(prefix=project + "-") as directory:
        fixture = Path(directory).resolve()
        os.chmod(fixture, 0o755)  # bind-mounted fixture files must be readable by Squid's UID
        for folder in ("policies", "gateway", "scripts", "security"):
            (fixture / folder).mkdir()
        # The seccomp profile sits beside the fixture's Compose file, as it does in the repository;
        # Compose reads it there. It is not mounted and .dockerignore keeps it out of the build.
        for name in ("Dockerfile", ".dockerignore", "policies/firefox-policies.json", "gateway/blocklist.txt",
                     "scripts/network.py", "security/seccomp-firefox.json"):
            shutil.copyfile(ROOT / name, fixture / name)
        squid = (ROOT / "gateway/squid.conf").read_text()
        replace_once(squid, "acl sandbox src 172.28.0.0/24", "")  # the launcher's network.py must still find it
        (fixture / "gateway/squid.conf").write_text(squid + "\nhosts_file /etc/squid/fixture-hosts\n")
        (fixture / "hosts").write_text(f"{private_ip} private.safebrowse.test\n127.0.0.1 localtest.me\n"
                                       f"{named_ip} ads.doubleclick.net\n{named_ip} allowed.safebrowse.test\n")
        (fixture / "server.py").write_text(SERVER)
        command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=SafeBrowse integration", "-addext", "subjectAltName=IP:" + public_ip,
                "-keyout", str(fixture / "key.pem"), "-out", str(fixture / "cert.pem"))
        # The fixture private key is ephemeral and is never used outside this test.
        (fixture / "key.pem").chmod(0o644)

        # The production direct topology and the service definitions it extends, with only
        # names, image tag and port changed, so the launcher still supplies the subnet,
        # Squid configuration, credentials and session labels.
        for name, changes in (("compose.services.yml", (("container_name: safebrowse-gw", f"container_name: {project}-gw"),
                                                        ("container_name: safebrowse-ui", f"container_name: {project}-ui"),
                                                        ("container_name: safebrowse", f"container_name: {project}"),
                                                        ("image: safebrowse:latest", f"image: {image}"),
                                                        ('- "127.0.0.1:3011:3001"', f'- "127.0.0.1:{port}:3001"'))),
                              ("docker-compose.yml", (("name: safebrowse_sandbox", f"name: {project}_sandbox"),
                                                      ("name: safebrowse_egress", f"name: {project}_egress")))):
            compose_text = (ROOT / name).read_text()
            for old, new in changes:
                compose_text = replace_line(compose_text, old, new)
            (fixture / name).write_text(compose_text)
        # Local targets make request outcomes independent of public websites and DNS.
        server = {"image": image, "entrypoint": ["python3", "/fixture/server.py"],
                  "volumes": [{"type": "bind", "source": str(fixture), "target": "/fixture", "read_only": True}],
                  "tmpfs": ["/tmp"], "cap_drop": ["ALL"], "cap_add": ["NET_BIND_SERVICE"],
                  "security_opt": ["no-new-privileges:true"], "mem_limit": "128m", "pids_limit": 64}
        (fixture / "fixture.yml").write_text(json.dumps({
            "services": {
                "named": dict(server, container_name=project + "-named",
                              networks={"egress_net": {"ipv4_address": named_ip}}),
                "gateway": {"networks": {"fixture_private": {}},
                            "volumes": [{"type": "bind", "source": str(fixture / "hosts"),
                                         "target": "/etc/squid/fixture-hosts", "read_only": True}]},
                "fixture": {
                    "image": image, "container_name": project + "-fixture",
                    "entrypoint": ["python3", "/fixture/server.py"],
                    "volumes": [{"type": "bind", "source": str(fixture), "target": "/fixture", "read_only": True}],
                    "networks": {"egress_net": {"ipv4_address": public_ip},
                                 "fixture_private": {"ipv4_address": private_ip}},
                    "tmpfs": ["/tmp"], "cap_drop": ["ALL"], "cap_add": ["NET_BIND_SERVICE"],
                    "security_opt": ["no-new-privileges:true"], "mem_limit": "128m", "pids_limit": 64}},
            "networks": {
                "egress_net": {"ipam": {"config": [{"subnet": public_subnet}]}},
                "fixture_private": {"name": project + "_private", "internal": True,
                                    "ipam": {"config": [{"subnet": private_subnet}]}}}}))

        session = safebrowse.Session(
            root=fixture, compose=("docker", "compose", "-p", project),
            direct_files=(str(fixture / "docker-compose.yml"), str(fixture / "fixture.yml")),
            vpn_files=(str(fixture / "absent-vpn-topology.yml"),),  # this suite never selects VPN mode
            browser=project, gateway=project + "-gw", ui=project + "-ui", vpn=project + "-vpn",
            network=project + "_sandbox", egress=project + "_egress", ui_port=port, fixture_services=("fixture", "named"))
        (fixture / "scripts/fixture.json").write_text(json.dumps({"scripts": str(ROOT / "scripts"), "runtime": {
            "browser": session.browser, "gateway": session.gateway, "ui": session.ui, "network": session.network,
            "vpn": session.vpn, "egress": session.egress, "gateway_networks": [project + "_private"],
            "proxy": "http://gateway:3128", "ui_port": str(port),
            "policy_path": str(fixture / "policies/firefox-policies.json"),
            "allowed_url": f"http://{public_ip}/positive", "direct_host": public_ip, "direct_port": 80,
            "denied_urls": [u for u in verify.DENIED_URLS if "example.com:" not in u] +
                           [f"http://{private_ip}/denied-private", "http://private.safebrowse.test/denied-hostname",
                            f"http://{public_ip}:8080/denied-port", "http://ads.doubleclick.net/denied-blocklist"]}}))
        (fixture / "scripts/verify.py").write_text(VERIFY_DRIVER)
        (fixture / "scripts/open_url.py").write_text(OPEN_DRIVER)

        # Refuse to run unless everything the launcher will touch belongs to this fixture.
        compose = list(session.compose) + [value for name in session.direct_files for value in ("-f", name)]
        names = {session.browser, session.gateway, session.ui, session.vpn, session.network, session.egress}
        require(session.root != ROOT and session.ui_port != PRODUCTION.ui_port and all(n.startswith(project) for n in names)
                and not names & {PRODUCTION.browser, PRODUCTION.gateway, PRODUCTION.ui, PRODUCTION.vpn, PRODUCTION.network,
                                 PRODUCTION.egress},
                "fixture session shares no name, port or state directory with the real session")
        model = json.loads(command(*compose, "config", "--format", "json",
                                   env=dict(env, SANDBOX_PASSWORD="validation-only-not-a-session")).stdout)
        services, networks = model["services"], model["networks"]
        binds = [m["source"] for s in services.values() for m in s.get("volumes", []) if m.get("type") == "bind"]
        require(model["name"] == project
                and all(s["container_name"].startswith(project) for s in services.values())
                and all(n["name"].startswith(project) for n in networks.values())
                and [(p["host_ip"], str(p["published"])) for p in services["uiproxy"]["ports"]] == [("127.0.0.1", str(port))]
                and all(Path(source).resolve().is_relative_to(fixture) for source in binds)
                and Path(services["safebrowse"]["build"]["context"]).resolve() == fixture,
                "effective Compose configuration stays inside the fixture project")
        require(services["safebrowse"]["security_opt"] == ["no-new-privileges:true", "seccomp=./security/seccomp-firefox.json"]
                and not services["safebrowse"].get("volumes")
                and (fixture / "security/seccomp-firefox.json").read_bytes() == (ROOT / "security/seccomp-firefox.json").read_bytes(),
                "fixture browser selects the approved seccomp profile, unmodified and unmounted")

        def cli(*arguments):
            print("\n$ safebrowse.py " + " ".join(arguments), flush=True)
            return safebrowse.main(list(arguments), host=safebrowse.Host(session=session, environ=env))

        def identities():
            result = command("docker", "inspect", "--format", "{{.Id}} {{.State.StartedAt}} {{.State.Running}}",
                             session.browser, session.gateway, session.ui, env=env, check=False)
            return result.stdout.split("\n")[:3] if result.returncode == 0 else None

        def requests(server="fixture"):
            result = command("docker", "exec", f"{project}-{server}", "cat", "/tmp/requests.jsonl", env=env, check=False)
            return [json.loads(line) for line in result.stdout.splitlines()]

        def loaded(marker):
            return lambda: any(r["path"] == marker and "Firefox/" in r["agent"] for r in requests())

        def in_browser(*arguments):
            return command("docker", "exec", "--user", "1000:1000", session.browser, *arguments, env=env, check=False)

        def untouched():
            return (identities() is None and not (fixture / ".env").exists() and not (fixture / ".runtime").exists()
                    and command("docker", "network", "inspect", session.network, env=env, check=False).returncode != 0)

        try:
            print("Refusals that must leave nothing behind...", flush=True)
            as_root = safebrowse.Host(session=session, environ=env, euid=lambda: 0)
            require(safebrowse.main(["run", "--fresh"], host=as_root) == 1 and untouched(),
                    "a root or sudo launch is refused before credentials, build, network or containers exist")
            blocklist = fixture / "gateway/blocklist.txt"
            accepted = blocklist.read_bytes()
            blocklist.write_bytes(accepted.replace(b"\n", b"\r\n"))
            require(cli("run", "--fresh") == 1 and untouched(),
                    "a blocklist with Windows line endings is refused before anything is created")
            blocklist.write_bytes(accepted)
            print("Launching through the real CLI against an isolated fixture...", flush=True)
            # Shell characters must arrive intact; Firefox itself percent-encodes the quotes.
            first = "/cli-first-" + token + "?x=$(id);&q="
            require(cli("run", "--url", f'http://{public_ip}{first}"1"') == 0,
                    "plain launch builds, starts, verifies and opens the requested URL")
            labels = [json.loads(line) for line in command(
                "docker", "inspect", "--format", "{{json .Config.Labels}}", session.browser, session.gateway, session.ui,
                env=env).stdout.splitlines()]
            declared = {(l.get("safebrowse.schema"), l.get("safebrowse.mode"), l.get("safebrowse.session")) for l in labels}
            require(len(declared) == 1 and next(iter(declared))[:2] == ("1", "direct")
                    and re.fullmatch(r"[0-9a-f]{16}", next(iter(declared))[2]) is not None
                    and command("docker", "inspect", "--type", "container", session.vpn, env=env, check=False).returncode != 0,
                    "a first session is a direct session: one session identifier on all three containers, no VPN container")
            require(not (fixture / ".runtime/vpn").exists(), "a direct session stores no VPN configuration")
            credentials = fixture / ".env"
            user, password = safebrowse.parse_credentials(credentials.read_text())
            require(stat.S_IMODE(credentials.stat().st_mode) == 0o600 and user == "sandbox" and len(password) == 32,
                    "launcher generated private credentials in the fixture directory")
            subnet = json.loads((fixture / ".runtime/network.json").read_text())["subnet"]
            live = json.loads(command("docker", "network", "inspect", session.network, env=env).stdout)[0]
            require([c["Subnet"] for c in live["IPAM"]["Config"]] == [subnet],
                    "running bridge uses the subnet the launcher selected and recorded")
            require(safebrowse.desktop_ready(safebrowse.desktop_status, port, user, password)
                    and not safebrowse.desktop_ready(safebrowse.desktop_status, port, user, password + "x"),
                    "desktop requires authentication and accepts only the generated credentials")
            first += "%221%22"
            wait_for("Firefox loads the requested URL, shell characters intact", loaded(first), 30)
            paths = [r["path"] for r in requests()]
            require("/positive" in paths and paths.index("/positive") < paths.index(first),
                    "requested URL was opened only after verification ran")
            original = identities()
            require(original and all(line.endswith(" true") for line in original), "all three session containers are running")
            options = json.loads(command("docker", "inspect", "--format", "{{json .HostConfig.SecurityOpt}}",
                                         session.browser, env=env).stdout)
            require(len(options) == 2 and options[0] == "no-new-privileges:true" and options[1].startswith("seccomp={")
                    and json.loads(options[1].split("=", 1)[1]) == json.loads((ROOT / "security/seccomp-firefox.json").read_text()),
                    "the launched browser carries the approved seccomp profile, not seccomp=unconfined")
            control = in_browser("curl", "--disable", "--silent", "--fail", "--max-time", "10", "--noproxy", "",
                                 "--proxy", "http://gateway:3128", "http://allowed.safebrowse.test/allowed-hostname")
            require(control.returncode == 0 and [r["path"] for r in requests("named")] == ["/allowed-hostname"],
                    "the gateway reaches a live local target by name, and its blocklisted name never reached it")
            require(not any(r["path"].startswith("/denied-") for r in requests()),
                    "no other denied request reached a local target")

            require(cli("run") == 1 and identities() == original,
                    "plain launch refuses the existing session and changes nothing")
            sentinel = "/config/cli-session-sentinel"
            in_browser("touch", sentinel).check_returncode()
            second = "/cli-second-" + token
            require(cli("run", "--resume", "--url", f"http://{public_ip}{second}") == 0 and identities() == original,
                    "resume verifies the session without rebuilding, restarting or recreating a container")
            require(in_browser("test", "-e", sentinel).returncode == 0, "resume keeps the existing profile")
            wait_for("Firefox loads the page requested on resume", loaded(second), 30)
            require(cli("verify") == 0 and cli("logs", "5") == 0, "verify and logs commands work on the running session")

            command("docker", "stop", session.gateway, env=env)
            stopped = identities()
            require(cli("run", "--resume") == 1 and identities() == stopped and stopped[1].endswith(" false"),
                    "resume refuses a stopped session and does not restart it")

            third = "/cli-third-" + token
            require(cli("run", "--fresh", "--url", f"http://{public_ip}{third}") == 0,
                    "fresh launch replaces the session and passes verification")
            replaced = identities()
            require(replaced and not {line.split()[0] for line in replaced} & {line.split()[0] for line in original},
                    "fresh launch recreated every session container")
            require(in_browser("test", "!", "-e", sentinel).returncode == 0, "fresh launch discards the previous profile")
            require(safebrowse.parse_credentials(credentials.read_text()) == (user, password),
                    "existing credentials are preserved across sessions")
            wait_for("Firefox loads the page requested on the fresh session", loaded(third), 30)

            require(cli("stop") == 0 and not command(*compose, "ps", "--all", "--quiet", env=dict(
                        env, SANDBOX_PASSWORD="validation-only-not-a-session")).stdout.strip(),
                    "stop removes every session container")
            require(command("docker", "network", "inspect", session.network, env=env, check=False).returncode != 0,
                    "stop removes the sandbox bridge")
            credentials.unlink()
            shutil.rmtree(fixture / ".runtime")
            require(cli("stop") == 0 and not credentials.exists() and not (fixture / ".runtime").exists(),
                    "teardown works without credentials or runtime state and creates neither")
            require(cli("run", "--resume") == 1 and not credentials.exists() and identities() is None,
                    "resume without credentials starts nothing")
            require(snapshot(*real_state) == before, "the real session's credentials and runtime state were not touched")
        finally:
            print("Cleaning up CLI integration containers, networks and image...", flush=True)
            command(*compose, "down", "--volumes", "--remove-orphans", timeout=120, check=False,
                    env=dict(env, SANDBOX_PASSWORD="validation-only-not-a-session"))
            command("docker", "image", "rm", image, env=env, timeout=60, check=False)
    print("CLI integration checks passed.", flush=True)
    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"FAIL  {error}", file=sys.stderr)
        sys.exit(1)
