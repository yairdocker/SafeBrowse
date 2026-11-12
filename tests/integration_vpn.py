#!/usr/bin/env python3
"""Drive the real launcher in VPN mode against a disposable WireGuard peer.

Run:  python3 tests/integration_vpn.py

Production code runs unchanged: the same parser and configuration generator
(scripts/vpn.py), the same pinned Gluetun image, the same Compose topology and
firewall rules, and the same verifier. What is replaced, in Python only, is the
Session: uniquely named containers and networks, a temporary state directory and
port, and a WireGuard peer that is another container, holding keys generated for
this run. Everything "on the internet" lives inside that peer, so a request that
arrives there came through the tunnel, and a packet capture on the VPN
container's egress interface shows what, if anything, went round it.

Faults are injected only here, from a helper container inside this fixture's VPN
namespace. Nothing in this file starts, stops or changes the real session, writes
to its .env or .runtime, or changes this computer's routing.

One read is not avoided. To compare the fixture with the production topology, the
suite asks Compose for the effective model of the checkout's own Compose files.
Compose loads the checkout's .env when it does that, if there is one, so the real
file is read by Compose. The password is overridden for those calls, the output
is parsed in memory and never printed, and nothing is written. The suite checks
that the real .env and .runtime files have the same size and modification time
afterwards; it does not establish more isolation from them than that.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "tests")]
from integration import command, require, wait_for  # noqa: E402
from cli_integration import LOAD, OPEN_DRIVER, replace_line, snapshot, unused_subnets  # noqa: E402
import safebrowse  # noqa: E402
import verify  # noqa: E402
import vpn  # noqa: E402

PRODUCTION = safebrowse.Session()
WEB, NAMED = "203.0.113.10", "203.0.113.11"          # exist only inside the peer, behind the tunnel
RESOLVERS = ("94.140.14.14", "94.140.15.15")         # Squid's production resolvers, answered by the peer
HEALTH_RESOLVER = "1.1.1.1"                          # Gluetun's once-a-minute DNS health check
TUNNEL_CLIENT, TUNNEL_PEER = "10.64.0.2", "10.64.0.1"

PEER_IMAGE = """FROM {image}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends wireguard-tools iptables iproute2 tcpdump \\
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT []
"""

# The far end of the tunnel and every destination behind it. Each request and DNS query is logged
# with the address it came from: the tunnel address means it crossed the tunnel.
PEER = r'''
import json, socket, socketserver, ssl, struct, subprocess, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
settings = json.load(open('/fixture/peer.json'))
def sh(*args): subprocess.run(args, check=True)
def log(name, record):
    with open('/tmp/%s.jsonl' % name, 'a') as f: f.write(json.dumps(record) + '\n')
sh('ip', 'link', 'add', 'wg0', 'type', 'wireguard')
sh('wg', 'setconf', 'wg0', '/fixture/peer.conf')
sh('ip', 'addr', 'add', settings['tunnel'], 'dev', 'wg0')
sh('ip', 'link', 'set', 'wg0', 'up')
sh('ip', 'link', 'add', 'inet0', 'type', 'dummy')
sh('ip', 'link', 'set', 'inet0', 'up')
for address in settings['addresses']: sh('ip', 'addr', 'add', address + '/32', 'dev', 'inet0')
class Web(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        log('requests', {'path': self.path, 'agent': self.headers.get('User-Agent', ''),
                         'client': self.client_address[0], 'address': self.connection.getsockname()[0]})
        if self.path.startswith('/stream'):
            self.send_response(200); self.send_header('Content-Type', 'text/plain'); self.end_headers()
            try:
                for index in range(120):
                    self.wfile.write(b'chunk %d\n' % index); self.wfile.flush(); time.sleep(0.5)
            except OSError: pass
            return
        body = b'<!doctype html><title>SafeBrowse VPN fixture</title><p>Local test page</p>'
        self.send_response(200); self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
def answer(query, client, transport):
    identifier = struct.unpack('!H', query[:2])[0]
    offset, labels = 12, []
    while query[offset]:
        labels.append(query[offset + 1:offset + 1 + query[offset]].decode('ascii', 'replace')); offset += query[offset] + 1
    qtype = struct.unpack('!H', query[offset + 1:offset + 3])[0]
    name = '.'.join(labels).lower()
    log('dns', {'name': name, 'type': qtype, 'client': client, 'transport': transport})
    question, address = query[12:offset + 5], settings['names'].get(name)
    if address is None: return struct.pack('!HHHHHH', identifier, 0x8183, 1, 0, 0, 0) + question
    if qtype != 1: return struct.pack('!HHHHHH', identifier, 0x8180, 1, 0, 0, 0) + question
    record = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4) + socket.inet_aton(address)
    return struct.pack('!HHHHHH', identifier, 0x8180, 1, 1, 0, 0) + question + record
class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try: sock.sendto(answer(data, self.client_address[0], 'udp'), self.client_address)
        except (IndexError, struct.error): pass
class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        log('dns', {'name': None, 'type': None, 'client': self.client_address[0], 'transport': 'tcp-connect'})
        try:
            self.request.settimeout(5); size = self.request.recv(2)
            if len(size) == 2:
                reply = answer(self.request.recv(struct.unpack('!H', size)[0]), self.client_address[0], 'tcp')
                self.request.sendall(struct.pack('!H', len(reply)) + reply)
        except (OSError, IndexError, struct.error): pass
class ThreadingUDP(socketserver.ThreadingMixIn, socketserver.UDPServer): allow_reuse_address = True
class ThreadingTCP(socketserver.ThreadingMixIn, socketserver.TCPServer): allow_reuse_address = True
servers = [ThreadingHTTPServer((settings['egress'], 80), Web)]
for address in settings['web']:
    servers.append(ThreadingHTTPServer((address, 80), Web))
    secure = ThreadingHTTPServer((address, 443), Web)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/fixture/cert.pem', '/fixture/key.pem')
    secure.socket = context.wrap_socket(secure.socket, server_side=True)
    servers.append(secure)
for address in settings['resolvers']:
    servers += [ThreadingUDP((address, 53), UDP), ThreadingTCP((address, 53), TCP)]
for server in servers: threading.Thread(target=server.serve_forever, daemon=True).start()
print('peer ready', flush=True)
threading.Event().wait()
'''

# A plain web server on the egress bridge: reachable by the ordinary route, never through the tunnel.
OBSERVER = r'''
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        with open('/tmp/requests.jsonl', 'a') as f:
            f.write(json.dumps({'path': self.path, 'client': self.client_address[0]}) + '\n')
        body = b'<!doctype html><title>SafeBrowse observer</title><p>Local test page</p>'
        self.send_response(200); self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
ThreadingHTTPServer(('0.0.0.0', 80), Handler).serve_forever()
'''

VERIFY_DRIVER = LOAD + '''import subprocess
verify = load("production_verify", Path(settings["scripts"]) / "verify.py")
network = load("fixture_network", HERE / "network.py")
if arguments not in ([], ["--wait-browser"]):
    sys.exit("unexpected verifier arguments")
try:
    subnet = str(network.current())
except (OSError, ValueError, RuntimeError):
    print("  INCONCLUSIVE  selected sandbox subnet is unavailable", file=sys.stderr)
    sys.exit(2)
# The fixture's destinations differ by mode; which checks run is still decided by verify.py itself.
label = subprocess.run(["docker", "inspect", "--format", '{{index .Config.Labels "safebrowse.mode"}}',
                        settings["common"]["browser"]], capture_output=True, text=True).stdout.strip()
runtime = dict(settings["common"], **settings["vpn" if label == "vpn" else "direct"], subnet=subnet)
runtime.update(policy_path=Path(runtime["policy_path"]), denied_urls=tuple(runtime["denied_urls"]))
sys.exit(verify.main(verify.Runtime(**runtime), wait_browser=30 if arguments else 0))
'''


@contextlib.contextmanager
def all_output(secret_values):
    """Collect everything written to stdout and stderr, by this process and its children, then replay it.

    Whatever the launcher and Docker print passes through here, so it can be searched for key material.
    """
    sys.stdout.flush()
    sys.stderr.flush()
    saved = os.dup(1), os.dup(2)
    collected = {}
    with tempfile.TemporaryFile(mode="w+b") as sink:
        os.dup2(sink.fileno(), 1)
        os.dup2(sink.fileno(), 2)
        try:
            yield collected
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
            os.dup2(saved[0], 1)
            os.dup2(saved[1], 2)
            os.close(saved[0])
            os.close(saved[1])
            sink.seek(0)
            collected["text"] = sink.read().decode("utf-8", "replace")
            leaked = any(value in collected["text"] for value in secret_values)
            # Never replay output that contains a key.
            print("<output withheld: it contained key material>" if leaked else collected["text"], end="", flush=True)
            collected["leaked"] = leaked


def default_route(env):
    """This computer's own default route, as text. It must be the same before, during and after."""
    if platform.system() == "Linux":
        return command("ip", "-4", "route", "show", "default", env=env).stdout.strip()
    lines = command("route", "-n", "get", "default", env=env).stdout.splitlines()
    return " ".join(line.strip() for line in lines if line.strip().startswith(("gateway:", "interface:")))


def main():
    env = {k: v for k, v in os.environ.items() if not k.startswith("COMPOSE_") and k not in safebrowse.OWNED
           and k not in ("SANDBOX_USER", "SANDBOX_PASSWORD")}
    major = int(command("docker", "version", "--format", "{{.Server.Version}}", env=env).stdout.split(".")[0])
    require(major >= 28, "Docker Engine supports isolated bridge mode and named interfaces (28+)")
    gluetun = verify.pin.inventory(ROOT)[0]["qmcgaw/gluetun"]
    require(gluetun is not None and gluetun in (ROOT / "docker-compose.vpn.yml").read_text(),
            "the VPN topology uses the pinned Gluetun image")
    token = secrets.token_hex(5)
    project = "safebrowse-vpn-" + token
    image, peer_image = project + ":test", project + "-peer:test"
    unused = unused_subnets(env)
    egress_subnet = unused("198.18.0.0/15")
    base = egress_subnet.split("/")[0][:-1]
    peer_ip, observer_ip = base + "20", base + "30"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    real_state = (ROOT / ".env", ROOT / ".runtime/network.json", ROOT / ".runtime/squid.conf")
    real_before = snapshot(*real_state), sorted(p.name for p in (ROOT / ".runtime").glob("vpn/*"))
    route_before = default_route(env)
    print(f"INFO  this computer's default route: {route_before}", flush=True)

    with tempfile.TemporaryDirectory(prefix=project + "-") as directory:
        fixture = Path(directory).resolve()
        os.chmod(fixture, 0o755)  # bind-mounted fixture files must be readable inside containers
        for folder in ("policies", "gateway", "scripts", "security", "user"):
            (fixture / folder).mkdir()
        for name in ("Dockerfile", ".dockerignore", "policies/firefox-policies.json", "gateway/blocklist.txt",
                     "scripts/network.py", "security/seccomp-firefox.json", "security/gluetun-auth.toml"):
            shutil.copyfile(ROOT / name, fixture / name)
        # Production Squid configuration plus one line: a hosts file naming only the direct-mode target, so the
        # direct sessions in this suite never consult public DNS. In VPN mode every other name is resolved by
        # Squid's production resolvers, whose addresses exist only behind the tunnel here.
        (fixture / "gateway/squid.conf").write_text((ROOT / "gateway/squid.conf").read_text() +
                                                    "\nhosts_file /etc/squid/fixture-hosts\n")
        (fixture / "hosts").write_text(f"{observer_ip} direct.safebrowse.test\n")
        (fixture / "peer.py").write_text(PEER)
        (fixture / "observer.py").write_text(OBSERVER)
        (fixture / "Dockerfile.peer").write_text(PEER_IMAGE.format(image=image))
        command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=SafeBrowse VPN integration", "-addext", "subjectAltName=IP:" + WEB,
                "-keyout", str(fixture / "key.pem"), "-out", str(fixture / "cert.pem"))
        (fixture / "key.pem").chmod(0o644)  # ephemeral TLS key for the fixture web server only

        # The three production Compose files with only names, image tag and port changed.
        replacements = {
            "compose.services.yml": (("container_name: safebrowse-gw", f"container_name: {project}-gw"),
                                     ("container_name: safebrowse-ui", f"container_name: {project}-ui"),
                                     ("container_name: safebrowse", f"container_name: {project}"),
                                     ("image: safebrowse:latest", f"image: {image}"),
                                     ('- "127.0.0.1:3011:3001"', f'- "127.0.0.1:{port}:3001"')),
            "docker-compose.yml": (("name: safebrowse_sandbox", f"name: {project}_sandbox"),
                                   ("name: safebrowse_egress", f"name: {project}_egress")),
            "docker-compose.vpn.yml": (("container_name: safebrowse-vpn", f"container_name: {project}-vpn"),
                                       ("name: safebrowse_sandbox", f"name: {project}_sandbox"),
                                       ("name: safebrowse_egress", f"name: {project}_egress")),
        }
        for name, changes in replacements.items():
            text = (ROOT / name).read_text()
            for old, new in changes:
                text = replace_line(text, old, new)
            (fixture / name).write_text(text)
        hardened = {"cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "mem_limit": "128m", "pids_limit": 64}
        observer = dict(hardened, image=image, container_name=project + "-observer", cap_add=["NET_BIND_SERVICE"],
                        entrypoint=["python3", "/fixture/observer.py"], tmpfs=["/tmp"],
                        networks={"egress_net": {"ipv4_address": observer_ip}},
                        volumes=[{"type": "bind", "source": str(fixture), "target": "/fixture", "read_only": True}])
        shared = {"services": {"observer": observer,
                               "gateway": {"volumes": [{"type": "bind", "source": str(fixture / "hosts"),
                                                        "target": "/etc/squid/fixture-hosts", "read_only": True}]}},
                  "networks": {"egress_net": {"ipam": {"config": [{"subnet": egress_subnet}]}}}}
        (fixture / "fixture.yml").write_text(json.dumps(shared))
        with_peer = json.loads(json.dumps(shared))
        with_peer["services"]["peer"] = dict(
            hardened, image=peer_image, container_name=project + "-peer", cap_add=["NET_ADMIN", "NET_BIND_SERVICE"],
            entrypoint=["python3", "/fixture/peer.py"], tmpfs=["/tmp"], networks={"egress_net": {"ipv4_address": peer_ip}},
            volumes=[{"type": "bind", "source": str(fixture), "target": "/fixture", "read_only": True}])
        with_peer["services"]["vpn"] = {"depends_on": ["peer"]}
        (fixture / "fixture-vpn.yml").write_text(json.dumps(with_peer))

        session = safebrowse.Session(
            root=fixture, compose=("docker", "compose", "-p", project),
            direct_files=(str(fixture / "docker-compose.yml"), str(fixture / "fixture.yml")),
            vpn_files=(str(fixture / "docker-compose.vpn.yml"), str(fixture / "fixture-vpn.yml")),
            browser=project, gateway=project + "-gw", ui=project + "-ui", vpn=project + "-vpn",
            network=project + "_sandbox", egress=project + "_egress", ui_port=port,
            fixture_services=("observer", "peer"), private_vpn_endpoint=True)
        literal_denials = [u for u in verify.DENIED_URLS if "example.com:" not in u and "localtest" not in u]
        (fixture / "scripts/fixture.json").write_text(json.dumps({"scripts": str(ROOT / "scripts"), "common": {
            "browser": session.browser, "gateway": session.gateway, "ui": session.ui, "vpn": session.vpn,
            "network": session.network, "egress": session.egress, "proxy": "http://gateway:3128", "ui_port": str(port),
            "policy_path": str(fixture / "policies/firefox-policies.json")},
            "vpn": {"allowed_url": f"http://{WEB}/positive", "direct_host": WEB, "direct_port": 80,
                    "denied_urls": [u for u in verify.DENIED_URLS if "example.com:" not in u] +
                    ["http://private.safebrowse.test/denied-hostname", f"http://{WEB}:8080/denied-port",
                     "http://ads.doubleclick.net/denied-blocklist"]},
            "direct": {"allowed_url": f"http://{observer_ip}/positive", "direct_host": observer_ip, "direct_port": 80,
                       "denied_urls": literal_denials + [f"http://{observer_ip}:8080/denied-port"]}}))
        (fixture / "scripts/verify.py").write_text(VERIFY_DRIVER)
        (fixture / "scripts/open_url.py").write_text(OPEN_DRIVER.replace('settings["runtime"]["browser"]',
                                                                         'settings["common"]["browser"]'))

        names = {session.browser, session.gateway, session.ui, session.vpn, session.network, session.egress}
        require(session.root != ROOT and session.ui_port != PRODUCTION.ui_port and all(n.startswith(project) for n in names)
                and not names & {PRODUCTION.browser, PRODUCTION.gateway, PRODUCTION.ui, PRODUCTION.vpn,
                                 PRODUCTION.network, PRODUCTION.egress},
                "fixture session shares no name, port or state directory with the real session")
        validation = dict(env, SANDBOX_PASSWORD="validation-only-not-a-session")
        vpn_compose = ["docker", "compose", "-p", project] + [v for f in session.vpn_files for v in ("-f", f)]
        direct_compose = ["docker", "compose", "-p", project] + [v for f in session.direct_files for v in ("-f", f)]

        # ------------------------------------------------------------------ effective models
        production = json.loads(command("docker", "compose", "-f", str(ROOT / "docker-compose.vpn.yml"), "config",
                                        "--format", "json", env=validation).stdout)
        direct_model = json.loads(command("docker", "compose", "-f", str(ROOT / "docker-compose.yml"), "config",
                                          "--format", "json", env=validation).stdout)
        services = production["services"]
        tunnel_service, gw, browser = services["vpn"], services["gateway"], services["safebrowse"]
        require(set(services) == {"vpn", "gateway", "uiproxy", "safebrowse"} and set(direct_model["services"]) ==
                {"gateway", "uiproxy", "safebrowse"}, "each topology defines exactly its own services")
        require(gw.get("network_mode") == "service:vpn" and not gw.get("networks") and not gw.get("hostname")
                and not gw.get("ports"), "VPN-mode gateway has no network, hostname or port of its own")
        require(set(tunnel_service["networks"]) == {"sandbox_net", "egress_net"}
                and tunnel_service["networks"]["sandbox_net"].get("aliases") == ["gateway"]
                and not tunnel_service["networks"]["egress_net"].get("aliases"),
                "the VPN service owns the sandbox and egress interfaces and is 'gateway' on the sandbox only")
        require(not any(s.get("ports") for name, s in services.items() if name != "uiproxy")
                and [(p["host_ip"], p["published"], p["target"]) for p in services["uiproxy"]["ports"]] ==
                [("127.0.0.1", "3011", 3001)] and set(services["uiproxy"]["networks"]) == {"sandbox_net", "egress_net"},
                "only the desktop relay publishes a port, on localhost, from outside the VPN namespace")
        require(sorted(tunnel_service["cap_add"]) == ["DAC_OVERRIDE", "NET_ADMIN"] and tunnel_service["cap_drop"] == ["ALL"]
                and not tunnel_service.get("privileged") and not tunnel_service.get("devices")
                and not tunnel_service.get("sysctls") and tunnel_service.get("network_mode") is None,
                "the VPN service has NET_ADMIN and DAC_OVERRIDE only: no device, privilege, sysctl or host network")
        require(all(s.get("restart") == "no" for s in services.values()), "no service has a restart policy")
        for key in ("image", "volumes", "tmpfs", "cap_add", "cap_drop", "security_opt", "logging", "mem_limit", "pids_limit"):
            require(gw.get(key) == direct_model["services"]["gateway"].get(key), f"gateway {key} is identical in both modes")
        for key in ("build", "image", "environment", "tmpfs", "cap_add", "cap_drop", "security_opt", "networks", "hostname",
                    "mem_limit", "cpus", "pids_limit", "shm_size"):
            require(browser.get(key) == direct_model["services"]["safebrowse"].get(key),
                    f"browser {key} is identical in both modes")
        require(not browser.get("volumes") and browser["security_opt"] == ["no-new-privileges:true",
                                                                           "seccomp=./security/seccomp-firefox.json"]
                and browser["environment"]["TZ"] == "Etc/UTC", "browser keeps its confinement, has no mounts and uses UTC")
        require(production["networks"] == direct_model["networks"], "both topologies define the same two networks")
        settings = tunnel_service["environment"]
        require(settings["HTTP_CONTROL_SERVER_ADDRESS"].startswith("127.0.0.1:") and settings["HEALTH_SERVER_ADDRESS"]
                .startswith("127.0.0.1:") and settings["DNS_SERVER"] == "off" and settings["HTTPPROXY"] == "off"
                and settings["SHADOWSOCKS"] == "off" and settings["PUBLICIP_ENABLED"] == "off"
                and settings["VERSION_INFORMATION"] == "off" and settings["UPDATER_PERIOD"] == "0"
                and settings["WIREGUARD_ALLOWED_IPS"] == "0.0.0.0/0" and settings["LOG_LEVEL"] == "warn"
                and not any("KEY" in name and value for name, value in settings.items()),
                "Gluetun's listeners are loopback-only, its extras are off and no key is passed in the environment")

        try:
            print("Building the browser and peer images...", flush=True)
            command(*direct_compose, "build", env=validation, timeout=900)
            command("docker", "build", "--quiet", "--tag", peer_image, "--file", str(fixture / "Dockerfile.peer"),
                    str(fixture / "user"), env=env, timeout=600)

            def wg(*arguments, input=None):
                return command("docker", "run", "--rm", "-i", "--network", "none", peer_image, "wg", *arguments,
                               input=input, env=env).stdout.strip()
            client_key, peer_key, wrong_key = wg("genkey"), wg("genkey"), wg("genkey")
            client_public, peer_public = wg("pubkey", input=client_key), wg("pubkey", input=peer_key)
            keys = [client_key, peer_key, client_key[:3] + "..." + client_key[-3:]]
            (fixture / "peer.conf").write_text(f"[Interface]\nPrivateKey = {peer_key}\nListenPort = 51820\n\n"
                                               f"[Peer]\nPublicKey = {client_public}\nAllowedIPs = {TUNNEL_CLIENT}/32\n")
            (fixture / "peer.json").write_text(json.dumps({
                "tunnel": TUNNEL_PEER + "/24", "egress": peer_ip, "web": [WEB, NAMED],
                "resolvers": list(RESOLVERS) + [HEALTH_RESOLVER],
                "addresses": [WEB, NAMED, HEALTH_RESOLVER, *RESOLVERS],
                "names": {"allowed.safebrowse.test": NAMED, "ads.doubleclick.net": NAMED, "web.safebrowse.test": WEB,
                          "private.safebrowse.test": "10.231.99.10", "localtest.me": "127.0.0.1", "github.com": WEB}}))

            # What a user would hold: a provider export, with the extras a Mullvad file carries.
            def export(public, endpoint=f"{peer_ip}:51820", extra=""):
                return (f"[Interface]\n# Device: Fixture Device\nPrivateKey = {client_key}\n"
                        f"Address = {TUNNEL_CLIENT}/32,fc00:bbbb:bbbb:bb01::2/128\nDNS = 10.64.0.1\n{extra}\n"
                        f"[Peer]\nPublicKey = {public}\nAllowedIPs = 0.0.0.0/0,::0/0\nEndpoint = {endpoint}\n")
            good, bad = fixture / "user/mullvad.conf", fixture / "user/wrong-peer.conf"
            good.write_text(export(peer_public))
            bad.write_text(export(wg("pubkey", input=wrong_key)))
            for path in (good, bad):
                path.chmod(0o600)
            hooked, linked = fixture / "user/hooked.conf", fixture / "user/link.conf"
            hooked.write_text(export(peer_public, extra="PostUp = iptables -I OUTPUT -j REJECT\n"))
            linked.symlink_to(good)
            source_before = (good.read_bytes(), good.stat().st_mode, good.stat().st_mtime_ns)
            store = fixture / ".runtime/vpn"

            def cli(*arguments, host_session=session, expect_secret_free=True):
                print("\n$ safebrowse.py " + " ".join(arguments), flush=True)
                with all_output(keys) as output:
                    code = safebrowse.main(list(arguments), host=safebrowse.Host(session=host_session, environ=env))
                if expect_secret_free and output["leaked"]:
                    raise RuntimeError("launcher or Docker output contained key material")
                return code, output["text"]

            def identities():
                found = {}
                for role in ("browser", "gateway", "ui", "vpn"):
                    result = command("docker", "inspect", "--type", "container", "--format",
                                     "{{.Id}} {{.State.StartedAt}} {{.State.Running}}", getattr(session, role),
                                     env=env, check=False)
                    if result.returncode == 0:
                        found[role] = result.stdout.strip()
                return found

            def log_of(container, name):
                result = command("docker", "exec", container, "cat", f"/tmp/{name}.jsonl", env=env, check=False)
                return [json.loads(line) for line in result.stdout.splitlines()]

            def peer_paths():
                return [r["path"] for r in log_of(project + "-peer", "requests")]

            def observed():
                return [r["path"] for r in log_of(project + "-observer", "requests")]

            def proxied(url, seconds=6):
                result = command("docker", "exec", "--user", "1000:1000", session.browser, "curl", "--disable", "--silent",
                                 "--max-time", str(seconds), "--noproxy", "", "--proxy", "http://gateway:3128",
                                 "--output", "/dev/null", "--write-out", "%{http_code}", url, env=env, check=False)
                return result.stdout.strip() if result.returncode == 0 else f"curl-exit-{result.returncode}"

            def in_namespace(*arguments, check=True):
                """Fixture-only fault injection and inspection inside this fixture's VPN namespace."""
                return command("docker", "run", "--rm", "--network", "container:" + session.vpn, "--cap-drop", "ALL",
                               "--cap-add", "NET_ADMIN", "--user", "0", "--entrypoint", arguments[0], peer_image,
                               *arguments[1:], env=env, check=check)

            def rules():
                return command("docker", "exec", session.vpn, "iptables", "-S", env=env).stdout

            def dropped():
                """Packets counted by the final DROP of SafeBrowse's output chain."""
                listing = command("docker", "exec", session.vpn, "iptables", "-L", "SAFEBROWSE_OUTPUT", "-v", "-n", "-x",
                                  env=env).stdout.splitlines()
                return int([line for line in listing if " DROP " in line][-1].split()[0])

            sniffer = project + "-sniff"

            def capture_start():
                command("docker", "rm", "--force", sniffer, env=env, check=False)
                command("docker", "run", "--detach", "--name", sniffer, "--network", "container:" + session.vpn,
                        "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN", "--user", "0",
                        "--entrypoint", "tcpdump", peer_image, "-Z", "root", "-i", vpn.EGRESS_INTERFACE, "-nn", "-U",
                        "-w", "/tmp/egress.pcap", "not", "arp", env=env)
                wait_for("packet capture on the VPN container's egress interface is running", lambda: command(
                    "docker", "exec", sniffer, "test", "-s", "/tmp/egress.pcap", env=env, check=False).returncode == 0, 20)

            def captured():
                """Every non-ARP packet seen on the egress interface since capture_start, minus WireGuard."""
                time.sleep(1)
                text = command("docker", "exec", sniffer, "tcpdump", "-Z", "root", "-nn", "-q", "-r", "/tmp/egress.pcap",
                               env=env).stdout
                vpn_ip = json.loads(command("docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}",
                                            session.vpn, env=env).stdout)[session.egress]["IPAddress"]
                tunnel = re.compile(rf"IP ({re.escape(vpn_ip)}\.\d+ > {re.escape(peer_ip)}\.51820|"
                                    rf"{re.escape(peer_ip)}\.51820 > {re.escape(vpn_ip)}\.\d+): UDP")
                lines = [line for line in text.splitlines() if line.strip()]
                return len(lines), [line for line in lines if not tunnel.search(line)]

            def only_tunnel_traffic(description, quiet=False):
                total, other = captured()
                require((total > 0 or quiet) and not other, f"{description}: all {total} packets on the egress interface "
                                                           "were WireGuard to or from the peer")

            def own_rules(text=None):
                """Policies, SafeBrowse's chains and the first rule of each built-in chain."""
                lines = (rules() if text is None else text).splitlines()
                first = [next((l for l in lines if l.startswith(f"-A {chain} ")), "") for chain in ("INPUT", "OUTPUT", "FORWARD")]
                return [l for l in lines if l.startswith("-P ") or "SAFEBROWSE" in l] + first

            def untouched():
                return (not identities() and not (fixture / ".env").exists() and not (fixture / ".runtime").exists()
                        and command("docker", "network", "inspect", session.network, env=env, check=False).returncode != 0)

            def verify_now():
                with all_output(keys) as output:
                    code = safebrowse.main(["verify"], host=safebrowse.Host(session=session, environ=env))
                return code, output["text"]

            def secret_free(description):
                """No key in any container's configuration, labels, environment or logs."""
                for role, container in identities().items():
                    name = getattr(session, role)
                    inspected = command("docker", "inspect", name, env=env).stdout
                    logs = command("docker", "logs", name, env=env, check=False)
                    if any(value in inspected + logs.stdout + logs.stderr for value in keys):
                        raise RuntimeError(f"{description}: key material found in {role} container metadata or logs")
                print(f"PASS  {description}: no key in any container's metadata, environment, labels or logs", flush=True)

            def generated():
                return sorted(p.name for p in store.iterdir()) if store.is_dir() else []

            # ------------------------------------------------------------------ refusals that change nothing
            print("\nRefusals that must leave nothing behind...", flush=True)
            for arguments, phrase in (
                    (("run", "--vpn", "mullvad"), "needs a configuration"),
                    (("run", "--direct", "--vpn", "mullvad"), "once"),
                    (("run", "--vpn", "other", "--vpn-config", str(good)), "supported provider"),
                    (("run", "--vpn-config", str(good)), "only meaningful with --vpn"),
                    (("run", "--resume", "--vpn", "mullvad", "--vpn-config", str(good)), "cannot replace it"),
                    (("run", "--vpn", "mullvad", "--vpn-config", str(hooked)), "command hook"),
                    (("run", "--vpn", "mullvad", "--vpn-config", str(linked)), "symbolic link"),
                    (("run", "--vpn", "mullvad", "--vpn-config", str(fixture / "user")), "regular file"),
                    (("run", "--vpn", "mullvad", "--vpn-config", str(fixture / "user/absent.conf")), "could not be opened")):
                code, output = cli(*arguments)
                require(code == 1 and phrase in output and untouched(), f"refused without creating anything: {' '.join(arguments[1:4])}")
            code, output = cli("run", "--vpn", "mullvad", "--vpn-config", str(good),
                               host_session=session._replace(private_vpn_endpoint=False))
            require(code == 1 and "not a public internet address" in output and untouched(),
                    "a private endpoint is refused unless a fixture enables it in Python")

            # ------------------------------------------------------------------ failed initial connection
            print("\nA tunnel that cannot connect...", flush=True)
            code, output = cli("run", "--vpn", "mullvad", "--vpn-config", str(bad))
            failed = identities()
            require(code == 1 and "did not fall back" in output and "vpn" in failed and failed["vpn"].endswith(" true"),
                    "a launch whose tunnel never connects fails, and leaves the VPN container for diagnosis")
            states = command("docker", "inspect", "--format", "{{.State.Status}}", session.gateway, session.browser,
                             env=env, check=False).stdout.split()
            require(all(state == "created" for state in states) and not peer_paths() and not observed(),
                    "the gateway and browser were never started and nothing reached any destination")
            require(command("docker", "inspect", "--format", '{{index .Config.Labels "safebrowse.mode"}}', session.vpn,
                            env=env).stdout.strip() == "vpn" and len(generated()) == 1,
                    "the failed session is labelled as a VPN session and keeps its generated configuration")
            code, output = cli("run", "--resume")
            require(code == 1 and identities() == failed, "resume refuses the failed session and restarts nothing")
            code, output = cli("logs", "20")
            secret_free("failed session")

            # ------------------------------------------------------------------ a working VPN session
            print("\nLaunching a VPN session through the real CLI...", flush=True)
            first = "/vpn-first-" + token
            code, output = cli("run", "--fresh", "--vpn", "mullvad", "--vpn-config", str(good), "--url", f"http://{WEB}{first}")
            require(code == 0 and "VPN: the gateway's only route out is the WireGuard tunnel" in output,
                    "fresh VPN launch replaces the failed session, verifies and reports VPN mode")
            for expected in ("IPv6 interface address was left out", "IPv6 route (::/0) was left out", "DNS setting was not used"):
                require(expected in output, f"the launcher says what it left out of the import: {expected}")
            for line in ("in vpn mode", "share one live network namespace", "exactly the generated rules",
                         "accepts connections on port 3128 only", "browser DNS forwarding is restricted",
                         "is refused by Docker's resolver without being resolved", "carries the same fingerprint",
                         "a kernel WireGuard interface is up", "IPv4 only", "publishes no ports"):
                require(re.search(r"PASS  [^\n]*" + re.escape(line), output) is not None, f"verifier passed: {line}")
            require(" FAIL " not in output and "INCONCLUSIVE  " not in output, "no check failed or was inconclusive")
            original = identities()
            require(len(original) == 4 and all(v.endswith(" true") for v in original.values()), "all four containers run")
            capture_start()
            wait_for("Firefox loads the requested page through the tunnel", lambda: any(
                r["path"] == first and "Firefox/" in r["agent"] and r["client"] == TUNNEL_CLIENT
                for r in log_of(project + "-peer", "requests")), 30)
            paths = peer_paths()
            require("/positive" in paths and paths.index("/positive") < paths.index(first),
                    "the requested URL was opened only after verification ran")
            require(proxied(f"http://{WEB}/http-literal") == "200" and proxied("http://web.safebrowse.test/http-name") == "200"
                    and proxied("http://allowed.safebrowse.test/allowed-name") == "200", "HTTP through the tunnel works")
            tls = command("docker", "exec", "-i", "--user", "1000:1000", session.browser, "curl", "--disable", "--silent",
                          "--fail", "--max-time", "10", "--noproxy", "", "--proxy", "http://gateway:3128", "--cacert",
                          "/dev/stdin", f"https://{WEB}/tls-connect", input=(fixture / "cert.pem").read_text(), env=env,
                          check=False)
            require(tls.returncode == 0 and "Local test page" in tls.stdout,
                    "HTTPS CONNECT through the tunnel reaches the TLS fixture with certificate verification")
            requests = log_of(project + "-peer", "requests")
            require(requests and all(r["client"] == TUNNEL_CLIENT for r in requests),
                    f"every request at the destination came from the tunnel address {TUNNEL_CLIENT}")
            queries = log_of(project + "-peer", "dns")
            names = {q["name"] for q in queries if q["transport"] == "udp"}
            require({"web.safebrowse.test", "allowed.safebrowse.test"} <= names and all(q["client"] == TUNNEL_CLIENT for q in queries),
                    "Squid's DNS queries to its production resolvers arrived through the tunnel")
            require(proxied("http://ads.doubleclick.net/blocked") == "403" and "/blocked" not in peer_paths()
                    and "/denied-blocklist" not in peer_paths(), "the blocklist still applies in VPN mode")
            require(not any(p.startswith("/denied-") for p in peer_paths()) and not observed(),
                    "no denied request reached a destination, and nothing reached the egress-bridge observer")
            require(proxied(f"http://{observer_ip}/local-bypass") != "200" and proxied("http://[2001:db8::1]/ipv6") != "200"
                    and not observed(), "a host on the egress bridge and an IPv6 destination are both unreachable")
            direct = command("docker", "exec", "--user", "1000:1000", session.browser, *verify.PROBE_PYTHON, verify.DIRECT_PROBE,
                             peer_ip, "80", env=env).stdout
            require(json.loads(direct) == {"connected": False, "errno": 101},
                    "the browser has no route to the WireGuard peer or anything else off its bridge")
            inside = command("docker", "exec", session.vpn, "sh", "-c",
                             f"nslookup -timeout=3 example.com {vpn.DOCKER_RESOLVER} >/dev/null 2>&1; echo $?", env=env)
            require(inside.stdout.strip() != "0", "Docker's resolver inside the VPN namespace cannot be used to resolve "
                                                  "external names outside the tunnel")
            only_tunnel_traffic("normal operation")

            print("\nSecret handling...", flush=True)
            current = generated()
            require(len(current) == 1 and stat.S_IMODE(store.stat().st_mode) == 0o700
                    and stat.S_IMODE((store / current[0]).stat().st_mode) == 0o700
                    and all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in (store / current[0]).iterdir())
                    and sorted(p.name for p in (store / current[0]).iterdir()) == ["post-rules.txt", "wg0.conf"],
                    "one generated configuration exists, in a 0700 directory, as two 0600 files")
            minimal = (store / current[0] / "wg0.conf").read_text()
            require("DNS" not in minimal and "fc00" not in minimal and "::" not in minimal and "Device" not in minimal
                    and vpn.parse(minimal, True) == vpn.parse(good.read_text(), True)._replace(notices=()),
                    "the generated configuration is the reduced IPv4-only form of the import")
            digest = hashlib.sha256((store / current[0] / "wg0.conf").read_bytes()).hexdigest()
            carried = {command("docker", "inspect", "--format", '{{index .Config.Labels "safebrowse.vpn-config-sha256"}}',
                               getattr(session, role), env=env).stdout.strip() for role in identities()}
            require(carried == {digest} and digest == vpn.fingerprint(vpn.parse(good.read_text(), True)),
                    "all four containers are labelled with the SHA-256 of the generated configuration, and nothing else of it")
            dns = command("docker", "inspect", "--format", "{{json .HostConfig.Dns}}", session.browser, env=env).stdout.strip()
            require(json.loads(dns) == ["127.0.0.1"], "in VPN mode too, the browser's only DNS forwarding target is its own loopback")
            require((good.read_bytes(), good.stat().st_mode, good.stat().st_mtime_ns) == source_before,
                    "the imported file was not modified")
            mounts = [json.loads(line) for line in command(
                "docker", "inspect", "--format", "{{json .Mounts}}", session.vpn, session.gateway, session.browser,
                session.ui, env=env).stdout.splitlines()]
            from_store = [[m["Destination"] for m in group if ".runtime/vpn/" in m["Source"]] for group in mounts]
            print("INFO  mounts (destination, writable): " + json.dumps([[(m["Destination"], m["RW"]) for m in group]
                                                                         for group in mounts]), flush=True)
            require(sorted(from_store[0]) == ["/iptables/post-rules.txt", "/run/secrets/wg0.conf"] and from_store[1:] == [[], [], []]
                    and len(mounts[0]) == 3 and all(not m["RW"] for group in mounts for m in group if m["Type"] == "bind"),
                    "the generated configuration is mounted read-only into the VPN container and nowhere else")
            readable = command("docker", "exec", session.vpn, "sh", "-c", "test -r /run/secrets/wg0.conf && "
                               "grep CapEff /proc/1/status", env=env).stdout.split()[-1]
            require(int(readable, 16) == (1 << 12) | (1 << 1), "Gluetun reads its 0600 configuration holding exactly "
                                                               "NET_ADMIN and DAC_OVERRIDE")
            secret_free("running VPN session")

            # ------------------------------------------------------------------ resume
            print("\nResume...", flush=True)
            code, output = cli("run", "--resume", "--direct")
            require(code == 1 and "never changes the mode" in output and identities() == original,
                    "resume refuses a conflicting mode and changes nothing")
            second = "/vpn-second-" + token
            code, output = cli("run", "--resume", "--vpn", "mullvad", "--url", f"http://{WEB}{second}")
            require(code == 0 and identities() == original and generated() == current,
                    "resume detects VPN mode, verifies, and recreates or restarts nothing")
            wait_for("Firefox loads the page requested on resume", lambda: second in peer_paths(), 30)
            code, output = cli("run", "--direct")
            require(code == 1 and identities() == original, "a plain launch refuses the existing session")

            # ------------------------------------------------------------------ tunnel failures in a live namespace
            print("\nFailures inside the running session (fixture-only fault injection)...", flush=True)
            baseline_rules = rules()
            command("docker", "exec", "--detach", "--user", "1000:1000", session.browser, "sh", "-c",
                    f"curl --disable --silent --no-buffer --max-time 90 --noproxy '' --proxy http://gateway:3128 "
                    f"http://{WEB}/stream > /tmp/stream.txt 2>/dev/null", env=env)

            def stream_lines():
                return int(command("docker", "exec", session.browser, "sh", "-c", "wc -l < /tmp/stream.txt", env=env,
                                   check=False).stdout.strip() or 0)
            wait_for("an established connection is carrying data", lambda: stream_lines() >= 3, 30)
            before = dropped()
            in_namespace("ip", "route", "del", "default", "dev", vpn.TUNNEL_INTERFACE, "table", "51820")
            route = command("docker", "exec", session.vpn, "ip", "-4", "route", "get", WEB, env=env).stdout
            require(f"dev {vpn.EGRESS_INTERFACE}" in route, "route loss: the kernel now selects the ordinary egress route")
            require(proxied(f"http://{WEB}/route-loss-new", 4) != "200" and proxied("http://web.safebrowse.test/route-loss-name", 4) != "200",
                    "route loss: new connections fail")
            time.sleep(3)
            require("/route-loss-new" not in peer_paths() and "/route-loss-name" not in peer_paths(),
                    "route loss: the new requests never arrive anywhere")
            require(dropped() > before, "route loss: the firewall's DROP rule counted the packets, from the established "
                                        "connection and the new ones, that the kernel sent towards the ordinary route")
            only_tunnel_traffic("route loss")
            require(rules() == baseline_rules, "route loss: the firewall rules are unchanged")
            print(f"INFO  established connection had delivered {stream_lines()} chunks; inbound data already in the tunnel "
                  "may still arrive, nothing goes out", flush=True)
            in_namespace("ip", "route", "add", "default", "dev", vpn.TUNNEL_INTERFACE, "table", "51820")
            wait_for("route restored: new connections work again", lambda: proxied(f"http://{WEB}/route-restored") == "200", 30)

            before = dropped()
            in_namespace("ip", "link", "del", vpn.TUNNEL_INTERFACE)
            first_try = proxied(f"http://{WEB}/interface-removed", 3)
            wait_for("interface removal: Gluetun rebuilds the tunnel in the same namespace and traffic resumes",
                     lambda: proxied(f"http://{WEB}/interface-back") == "200", 120)
            require(own_rules() == own_rules(baseline_rules),
                    "interface removal and reconnect: SafeBrowse's chains are unchanged and still evaluated first")
            print(f"INFO  request sent while the interface was absent returned {first_try}", flush=True)
            only_tunnel_traffic("interface removal and reconnect")

            before = dropped()
            command("docker", "stop", "--time", "1", project + "-peer", env=env)
            require(proxied(f"http://{WEB}/peer-down", 4) != "200" and proxied("http://web.safebrowse.test/peer-down-name", 4) != "200",
                    "peer outage: new connections fail")
            only_tunnel_traffic("peer outage")
            require(not observed(), "peer outage: nothing reached the egress-bridge observer")
            command("docker", "start", project + "-peer", env=env)
            wait_for("peer back: the tunnel reconnects without any container being restarted",
                     lambda: proxied(f"http://{WEB}/peer-back") == "200", 180)
            require({role: value for role, value in identities().items()} == original,
                    "tunnel recovery restarted and recreated no session container")
            code, output = verify_now()
            require(code == 0, "the recovered session passes full verification")

            # ------------------------------------------------------------------ VPN container restart
            print("\nVPN container restart...", flush=True)
            command("docker", "rm", "--force", sniffer, env=env, check=False)
            command("docker", "restart", "--time", "2", session.vpn, env=env)
            wait_for("restarted VPN container is healthy again", lambda: command(
                "docker", "inspect", "--format", "{{.State.Health.Status}}", session.vpn, env=env).stdout.strip() == "healthy", 120)
            capture_start()
            require(own_rules() == own_rules(baseline_rules), "restart: the rebuilt firewall has the same SafeBrowse chains, first")
            require(proxied(f"http://{WEB}/after-restart", 4) != "200" and "/after-restart" not in peer_paths(),
                    "restart: the gateway is in the old, empty namespace, so browsing fails closed")
            code, output = verify_now()
            require(code == 1 and "stale namespace" in output and "run ./run.sh --fresh" in output,
                    "restart: verification rejects the stale namespace and says to start fresh")
            restarted = identities()
            code, output = cli("run", "--resume")
            require(code == 1 and identities() == restarted, "restart: resume refuses and repairs nothing")
            only_tunnel_traffic("after restart", quiet=True)
            code, output = cli("run", "--fresh")
            fresh = identities()
            require(code == 0 and "VPN: the gateway's only route out" in output
                    and not {v.split()[0] for v in fresh.values()} & {v.split()[0] for v in original.values()},
                    "--fresh without a mode keeps VPN mode, reusing the stored configuration, and replaces every container")
            require(len(generated()) == 1 and generated() != current, "the replaced session's generated secrets were removed")
            current = generated()

            # ------------------------------------------------------------------ stop and start
            print("\nVPN container stop and start...", flush=True)
            command("docker", "stop", "--time", "2", session.vpn, env=env)
            require(proxied(f"http://{WEB}/vpn-stopped", 4) != "200", "stopped VPN container: browsing fails")
            code, output = verify_now()
            require(code == 1 and "PASS" not in output, "stopped VPN container: verification fails without passing checks")
            command("docker", "start", session.vpn, env=env)
            wait_for("started VPN container is healthy", lambda: command(
                "docker", "inspect", "--format", "{{.State.Health.Status}}", session.vpn, env=env).stdout.strip() == "healthy", 120)
            code, output = verify_now()
            require(code == 1 and "stale namespace" in output and proxied(f"http://{WEB}/vpn-started", 4) != "200",
                    "stop/start: the gateway stays in the stale namespace; verification rejects it and browsing fails")
            code, output = cli("run", "--fresh", "--direct", "--url", f"http://{observer_ip}/direct-first")
            require(code == 0 and "direct: the gateway uses this computer's own connection" in output
                    and "vpn" not in identities() and generated() == [],
                    "an explicit --fresh --direct switches mode: no VPN container and no stored VPN secrets remain")
            require(re.search(r"PASS  [^\n]*a direct session has no VPN container", output) is not None,
                    "the direct session's verification includes the absence of a VPN container")
            wait_for("the direct session browses by the ordinary route", lambda: "/direct-first" in observed(), 30)

            # ------------------------------------------------------------------ direct session with a stray VPN container
            print("\nDirect session, then back to VPN...", flush=True)
            direct_ids = identities()
            command("docker", "run", "--detach", "--name", session.vpn, "--network", "none", "--entrypoint", "sleep",
                    image, "300", env=env)
            code, output = verify_now()
            require(code != 0 and "FAIL  a direct session has no VPN container" in output,
                    "direct mode rejects a VPN container under this instance's name")
            code, output = cli("run", "--resume")
            require(code == 1 and "cannot be established" in output, "resume refuses the contradictory session")
            command("docker", "rm", "--force", session.vpn, env=env)
            code, output = cli("run", "--fresh", "--vpn", "mullvad")
            require(code == 1 and "needs a configuration" in output and identities() == direct_ids,
                    "switching to VPN without a configuration is refused before teardown")
            code, output = cli("run", "--fresh", "--vpn", "mullvad", "--vpn-config", str(hooked))
            require(code == 1 and identities() == direct_ids and generated() == [],
                    "a rejected configuration leaves the direct session running and stages nothing")
            code, output = cli("run", "--fresh", "--vpn", "mullvad", "--vpn-config", str(good))
            require(code == 0 and len(identities()) == 4, "an explicit --fresh --vpn mullvad switches back to VPN mode")
            current = generated()

            # ------------------------------------------------------------------ recreation
            print("\nVPN container recreation...", flush=True)
            before_ids = identities()
            recreate = dict(env, SANDBOX_PASSWORD="validation-only-not-a-session", SAFEBROWSE_VPN_DIR=str(store / current[0]),
                            SAFEBROWSE_VPN_FINGERPRINT=hashlib.sha256((store / current[0] / "wg0.conf").read_bytes()).hexdigest(),
                            SAFEBROWSE_SESSION=current[0], SANDBOX_SUBNET=json.loads((fixture / ".runtime/network.json").read_text())["subnet"],
                            SQUID_CONFIG_PATH=str(fixture / ".runtime/squid.conf"))
            command(*vpn_compose, "up", "--detach", "--force-recreate", "--no-deps", "vpn", env=recreate, timeout=180)
            wait_for("recreated VPN container is healthy", lambda: command(
                "docker", "inspect", "--format", "{{.State.Health.Status}}", session.vpn, env=env).stdout.strip() == "healthy", 120)
            require(identities()["vpn"].split()[0] != before_ids["vpn"].split()[0]
                    and identities()["gateway"] == before_ids["gateway"], "the VPN container was replaced; the gateway was not")
            code, output = verify_now()
            require(code == 1 and "FAIL  gateway's network mode names this VPN container" in output
                    and proxied(f"http://{WEB}/recreated", 4) != "200",
                    "recreation: the gateway still refers to the removed container; verification rejects it and browsing fails")

            # ------------------------------------------------------------------ missing and damaged state
            print("\nMissing and damaged state...", flush=True)
            stale = identities()
            saved = (store / current[0] / "wg0.conf").read_text()
            # Unsafe storage: the store reached through a link is refused, never read as "no VPN session".
            moved = fixture / ".runtime/vpn-moved"
            store.rename(moved)
            store.symlink_to(moved)
            for arguments in (("run", "--resume"), ("run", "--fresh"), ("run", "--fresh", "--direct")):
                code, output = cli(*arguments)
                require(code == 1 and ".runtime/vpn is a symbolic link" in output and "direct:" not in output
                        and identities() == stale and (moved / current[0] / "wg0.conf").read_text() == saved,
                        f"{' '.join(arguments[1:])} refuses VPN storage reached through a link and changes nothing")
            store.unlink()
            moved.rename(store)
            # A canonical edit: still a perfectly formed configuration, but not the one this session was created with.
            edited = re.sub(r"Endpoint = ([0-9.]+):([0-9]+)", lambda m: f"Endpoint = {m[1]}:{int(m[2]) + 1}", saved)
            require(edited != saved and vpn.render(vpn.parse(edited, True)) == edited, "the edited configuration is canonical")
            (store / current[0] / "wg0.conf").write_text(edited)
            for arguments in (("run", "--fresh"), ("run", "--resume")):
                code, output = cli(*arguments)
                require(code == 1 and "not the one this session was started with" in output and identities() == stale
                        and generated() == current,
                        f"{arguments[1]} refuses a canonically edited Endpoint before touching the session")
            (store / current[0] / "wg0.conf").write_text(saved.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 10.0.0.0/8"))
            code, output = cli("run", "--fresh")
            require(code == 1 and "cannot be reused" in output and "--fresh --direct" in output and identities() == stale,
                    "--fresh refuses a damaged stored configuration before teardown and explains the explicit choices")
            shutil.rmtree(store / current[0])
            code, output = cli("run", "--fresh")
            require(code == 1 and "cannot be reused" in output and identities() == stale,
                    "--fresh refuses a missing stored configuration before teardown; it never downgrades to direct")
            code, output = cli("run", "--resume")
            require(code == 1 and identities() == stale, "resume of the damaged session fails and repairs nothing")

            # ------------------------------------------------------------------ the capture can see a leak
            print("\nPositive control: with the firewall opened by hand, the ordinary route is observable...", flush=True)
            capture_start()
            before = len(observed())
            in_namespace("iptables", "-I", "OUTPUT", "1", "-d", observer_ip, "-j", "ACCEPT")
            in_namespace("iptables", "-I", "INPUT", "1", "-s", observer_ip, "-j", "ACCEPT")
            in_namespace("python3", "-c", "import urllib.request,sys; urllib.request.urlopen('http://%s/control' % sys.argv[1], timeout=5)",
                         observer_ip)
            total, other = captured()
            require("/control" in observed()[before:] and any(observer_ip in line for line in other),
                    "once rules are opened by hand, both the observer and the capture see traffic on the ordinary route")

            # ------------------------------------------------------------------ teardown
            print("\nTeardown...", flush=True)
            command("docker", "rm", "--force", sniffer, env=env, check=False)
            require(default_route(env) == route_before, "this computer's default route is unchanged while a VPN session exists")
            bystander = command("docker", "exec", project + "-observer", "python3", "-c",
                                "import urllib.request,sys; urllib.request.urlopen('http://%s/bystander' % sys.argv[1], timeout=5)",
                                peer_ip, env=env, check=False)
            arrivals = [r for r in log_of(project + "-peer", "requests") if r["path"] == "/bystander"]
            require(bystander.returncode == 0 and [r["client"] for r in arrivals] == [observer_ip],
                    "an unrelated container's traffic keeps its own address: it is not routed through the tunnel")
            (fixture / ".env").unlink()
            shutil.rmtree(fixture / ".runtime")
            code, output = cli("stop")
            require(code == 0 and not identities() and not (fixture / ".env").exists() and not (fixture / ".runtime").exists(),
                    "stop removes a VPN session without credentials, runtime state or the VPN configuration, and creates nothing")
            require(command("docker", "network", "inspect", session.network, session.egress, env=env, check=False).returncode != 0,
                    "stop removes both networks")
            code, output = cli("run", "--vpn", "mullvad", "--vpn-config", str(good), "--url", f"http://{WEB}/final")
            require(code == 0, "a new VPN session starts from nothing")
            last = generated()
            (store / last[0] / "notes.txt").write_text("not created by SafeBrowse")
            code, output = cli("stop")
            require(code == 1 and not identities() and "was not removed completely" in output and "Sandbox destroyed" not in output
                    and sorted(p.name for p in (store / last[0]).iterdir()) == ["notes.txt"],
                    "stop removes the containers and its own generated files, leaves a file it did not create, and exits non-zero")
            shutil.rmtree(store / last[0])
            code, output = cli("stop")
            require(code == 0 and not identities() and generated() == [] and len(last) == 1 and "Sandbox destroyed" in output,
                    "stop reports success only once nothing generated is left")
            require((good.read_bytes(), good.stat().st_mode, good.stat().st_mtime_ns) == source_before and bad.exists(),
                    "imported source files were never modified or deleted")
            code, output = cli("run", "--resume")
            require(code == 1 and not identities(), "resume with no session starts nothing")
            require((snapshot(*real_state), sorted(p.name for p in (ROOT / ".runtime").glob("vpn/*"))) == real_before,
                    "the real session's credentials, runtime state and VPN store were not touched")
        finally:
            print("Cleaning up VPN integration containers, networks and images...", flush=True)
            cleanup = dict(env, SANDBOX_PASSWORD="validation-only-not-a-session")
            command("docker", "rm", "--force", project + "-sniff", env=env, check=False)
            command(*vpn_compose, "down", "--volumes", "--remove-orphans", timeout=180, check=False, env=cleanup)
            command("docker", "rm", "--force", project + "-vpn", env=env, check=False)
            command("docker", "image", "rm", peer_image, image, env=env, timeout=60, check=False)
        require(default_route(env) == route_before, "this computer's default route is the same after the suite as before it")
    print("VPN integration checks passed.", flush=True)
    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, IndexError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"FAIL  {error}", file=sys.stderr)
        sys.exit(1)
