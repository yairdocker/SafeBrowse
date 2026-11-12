#!/usr/bin/env python3
"""Run the real stack against local fixtures. No production containers are touched."""
import contextlib
import io
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import open_url
import safebrowse
import verify


def command(*args, env=None, input=None, timeout=60, check=True):
    result = subprocess.run(args, env=env, input=input, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        # Commands/config output can contain credentials; never print them.
        raise RuntimeError(f"{args[0]} operation failed (exit {result.returncode})")
    return result


def wait_for(description, check, seconds=180):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            print(f"PASS  {description}", flush=True)
            return
        time.sleep(2)
    raise RuntimeError(f"timed out: {description}")


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError(f"fixture no longer matches production configuration: {old}")
    return text.replace(old, new)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)
    print(f"PASS  {message}", flush=True)


SERVER = r'''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json, ssl, threading
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        with open('/tmp/requests.jsonl', 'a') as f:
            f.write(json.dumps({'path': self.path, 'agent': self.headers.get('User-Agent', ''),
                                'address': self.connection.getsockname()[0]}) + '\n')
        body = b'<!doctype html><title>SafeBrowse integration fixture</title><p>Local test page</p>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
plain = ThreadingHTTPServer(('0.0.0.0', 80), Handler)
secure = ThreadingHTTPServer(('0.0.0.0', 443), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/fixture/cert.pem', '/fixture/key.pem')
secure.socket = ctx.wrap_socket(secure.socket, server_side=True)
threading.Thread(target=plain.serve_forever, daemon=True).start()
secure.serve_forever()
'''


# A resolver that records every query it receives. It answers names beginning with "observed" and
# says that every other name does not exist, so a failed lookup and an unseen query are different things.
DNS_OBSERVER = r'''
import json, socket, socketserver, struct, sys, threading
def answer(query, client, transport):
    labels, index = [], 12
    while query[index]:
        labels.append(query[index + 1:index + 1 + query[index]].decode('ascii', 'replace'))
        index += 1 + query[index]
    name, kind = '.'.join(labels).lower(), struct.unpack('!H', query[index + 1:index + 3])[0]
    with open('/tmp/queries.jsonl', 'a') as f:
        f.write(json.dumps({'name': name, 'type': kind, 'client': client, 'transport': transport}) + '\n')
    question = query[12:index + 5]
    if not name.startswith('observed'):
        return query[:2] + b'\x85\x83\x00\x01\x00\x00\x00\x00\x00\x00' + question
    if kind != 1:
        return query[:2] + b'\x85\x80\x00\x01\x00\x00\x00\x00\x00\x00' + question
    return (query[:2] + b'\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00' + question +
            b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04' + socket.inet_aton('203.0.113.53'))
class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(answer(data, self.client_address[0], 'udp'), self.client_address)
class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        size = struct.unpack('!H', self.request.recv(2))[0]
        reply = answer(self.request.recv(size), self.client_address[0], 'tcp')
        self.request.sendall(struct.pack('!H', len(reply)) + reply)
class ThreadingUDP(socketserver.ThreadingMixIn, socketserver.UDPServer): allow_reuse_address = True
class ThreadingTCP(socketserver.ThreadingMixIn, socketserver.TCPServer): allow_reuse_address = True
address = sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0'
udp, tcp = ThreadingUDP((address, 53), UDP), ThreadingTCP((address, 53), TCP)
open('/tmp/queries.jsonl', 'a').close()
threading.Thread(target=udp.serve_forever, daemon=True).start()
tcp.serve_forever()
'''

# Runs inside another container's network namespace and records, with the interface it was seen on,
# every DNS packet (port 53 either way) and every new connection to the proxy port.
DNS_SNIFFER = r'''
import json, socket, struct
# ETH_P_ALL: a socket bound to one protocol is only shown packets arriving, never those being sent.
capture = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
log = open('/tmp/packets.jsonl', 'a', buffering=1)
log.write(json.dumps({'ready': True}) + '\n')
while True:
    data, meta = capture.recvfrom(65535)
    if meta[1] != 0x0800 or len(data) < 20 or data[0] >> 4 != 4 or data[9] not in (6, 17):
        continue
    header = (data[0] & 15) * 4
    if struct.unpack('!H', data[6:8])[0] & 0x1fff or len(data) < header + 14:
        continue
    source, target = struct.unpack('!HH', data[header:header + 4])
    opening = data[9] == 6 and data[header + 13] & 0x12 == 0x02
    if 53 in (source, target) or (target == 3128 and opening):
        log.write(json.dumps({'interface': meta[0], 'protocol': 'udp' if data[9] == 17 else 'tcp',
                              'source': socket.inet_ntoa(data[12:16]), 'sport': source,
                              'target': socket.inet_ntoa(data[16:20]), 'dport': target}) + '\n')
'''


def main():
    # Keep the test independent of the caller's Compose overrides and credentials.
    env = {k: v for k, v in os.environ.items() if not k.startswith('COMPOSE_')
           and k not in ('SANDBOX_USER', 'SANDBOX_PASSWORD', 'SANDBOX_SUBNET', 'SQUID_CONFIG_PATH')}
    env.update(SANDBOX_USER='integration', SANDBOX_PASSWORD=secrets.token_hex(24))
    major = int(command('docker', 'version', '--format', '{{.Server.Version}}', env=env).stdout.split('.')[0])
    require(major >= 28, 'Docker Engine supports isolated bridge mode (28+)')
    daemon = verify.daemon_security()
    require(daemon is not None, 'Docker daemon reports its security options')
    print(f"INFO  daemon: {daemon['os']}; security options: {', '.join(sorted(daemon['security']))}", flush=True)
    token = secrets.token_hex(5)
    project = 'safebrowse-test-' + token
    # These addresses exist only on local Docker bridges. Pick unused /24s and
    # let Docker reject any concurrent collision; never remove another network.
    existing_ids = command('docker', 'network', 'ls', '--quiet', env=env).stdout.split()
    used = []
    if existing_ids:
        for network in json.loads(command('docker', 'network', 'inspect', *existing_ids, env=env).stdout):
            used += [ipaddress.ip_network(c['Subnet']) for c in (network.get('IPAM', {}).get('Config') or []) if c.get('Subnet')]
    def unused(*pools):
        for pool in map(ipaddress.ip_network, pools):
            for net in pool.subnets(new_prefix=24):
                if not any(net.overlaps(other) for other in used if other.version == 4):
                    used.append(net)
                    return str(net)
        raise RuntimeError('no unused integration subnet')
    sandbox_subnet = unused('172.31.0.0/16', '172.16.0.0/12')
    public_subnet = unused('198.18.0.0/15')
    private_subnet = unused('10.231.0.0/16', '10.0.0.0/8')
    gateway_ip = sandbox_subnet.split('/')[0][:-1] + '2'
    public_ip = public_subnet.split('/')[0][:-1] + '10'
    # A second live server that is only ever requested by name. Squid also checks an IP-literal
    # request against the blocklist by reverse lookup, so the blocklisted name gets its own address.
    named_ip = public_subnet.split('/')[0][:-1] + '11'
    private_ip = private_subnet.split('/')[0][:-1] + '10'
    # The observing resolver sits on the browser's own internal network and on the outside one.
    observer_sandbox_ip = sandbox_subnet.split('/')[0][:-1] + '53'
    observer_public_ip = public_subnet.split('/')[0][:-1] + '53'
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = str(listener.getsockname()[1])
    image = project + ':test'
    with tempfile.TemporaryDirectory(prefix=project + '-') as directory:
        fixture = Path(directory)
        os.chmod(fixture, 0o755)  # bind-mounted fixture files must be readable by Squid's UID
        (fixture / 'policies').mkdir()
        (fixture / 'gateway').mkdir()
        for name in ('Dockerfile', '.dockerignore'):
            shutil.copyfile(ROOT / name, fixture / name)
        policy = json.loads((ROOT / 'policies/firefox-policies.json').read_text())
        for key in ('HTTPProxy', 'SSLProxy'):
            require(policy['policies']['Proxy'][key] == 'gateway:3128', f'fixture recognizes {key}')
        policy_path = fixture / 'policies/firefox-policies.json'
        policy_path.write_text(json.dumps(policy))
        squid = replace_once((ROOT / 'gateway/squid.conf').read_text(), 'acl sandbox src 172.28.0.0/24',
                             'acl sandbox src ' + sandbox_subnet)
        (fixture / 'gateway/squid.conf').write_text(squid + '\nhosts_file /etc/squid/fixture-hosts\n')
        shutil.copyfile(ROOT / 'gateway/blocklist.txt', fixture / 'gateway/blocklist.txt')
        # The same line-ending check the launcher applies before it starts anything.
        safebrowse.check_security_inputs(safebrowse.Host(session=safebrowse.Session(root=fixture), environ={}))
        require((fixture / 'gateway/blocklist.txt').read_bytes() == (ROOT / 'gateway/blocklist.txt').read_bytes()
                and b'\n.doubleclick.net\n' in (ROOT / 'gateway/blocklist.txt').read_bytes(),
                'fixture gateway uses the repository blocklist unchanged, with LF line endings')
        # Two names for the same live local server: one on the blocklist, one not.
        (fixture / 'hosts').write_text(f'{private_ip} private.safebrowse.test\n127.0.0.1 localtest.me\n'
                                       f'{named_ip} ads.doubleclick.net\n{named_ip} allowed.safebrowse.test\n')
        (fixture / 'server.py').write_text(SERVER)
        (fixture / 'dns_observer.py').write_text(DNS_OBSERVER)
        (fixture / 'dns_sniff.py').write_text(DNS_SNIFFER)
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=SafeBrowse integration', '-addext', 'subjectAltName=IP:' + public_ip,
                '-keyout', str(fixture / 'key.pem'), '-out', str(fixture / 'cert.pem'))
        # The fixture private key is ephemeral and is never used outside this test.
        (fixture / 'key.pem').chmod(0o644)
        model = json.loads(command('docker', 'compose', '--env-file', os.devnull, '-f', str(ROOT / 'docker-compose.yml'),
                                   '-p', project, 'config', '--format', 'json', env=env).stdout)
        model['name'] = project
        for key, network in model['networks'].items():
            network['name'] = project + '_' + key
        model['networks']['sandbox_net']['ipam']['config'] = [{'subnet': sandbox_subnet}]
        model['networks']['egress_net']['ipam'] = {'config': [{'subnet': public_subnet}]}
        model['networks']['fixture_private'] = {'name': project + '_private', 'internal': True,
                                               'ipam': {'config': [{'subnet': private_subnet}]}}
        services = model['services']
        for key, service in services.items():
            service['container_name'] = project + '-' + key
        browser = services['safebrowse']
        browser['image'] = image
        browser['build']['context'] = str(fixture)
        # Compose reads the profile from the repository when it creates the container;
        # nothing is mounted into the browser and the build context is unchanged.
        profile = ROOT / 'security/seccomp-firefox.json'
        require(browser['security_opt'] == ['no-new-privileges:true', 'seccomp=./security/seccomp-firefox.json'],
                'production browser selects the approved seccomp profile and nothing else')
        browser['security_opt'] = ['no-new-privileges:true', 'seccomp=' + str(profile)]
        require(not browser.get('volumes') and not (fixture / 'security').exists(),
                'the profile is neither mounted into the browser nor part of the build context')
        require(browser.get('dns') == ['127.0.0.1'] and not any(s.get('dns') for k, s in services.items() if k != 'safebrowse'),
                "production browser's only DNS forwarding target is its own loopback address; no other service sets one")
        gw = services['gateway']
        gw['networks']['sandbox_net'] = {'ipv4_address': gateway_ip}
        gw['networks']['fixture_private'] = {}
        for mount in gw['volumes']:
            mount['source'] = str(fixture / 'gateway' / Path(mount['source']).name)
        gw['volumes'].append({'type': 'bind', 'source': str(fixture / 'hosts'),
                              'target': '/etc/squid/fixture-hosts', 'read_only': True})
        services['uiproxy']['ports'][0]['published'] = port
        services['fixture'] = {
            'image': image, 'container_name': project + '-fixture',
            'entrypoint': ['python3', '/fixture/server.py'],
            'volumes': [{'type': 'bind', 'source': str(fixture), 'target': '/fixture', 'read_only': True}],
            'networks': {'egress_net': {'ipv4_address': public_ip}, 'fixture_private': {'ipv4_address': private_ip}},
            'tmpfs': ['/tmp'], 'cap_drop': ['ALL'], 'cap_add': ['NET_BIND_SERVICE'],
            'security_opt': ['no-new-privileges:true'], 'mem_limit': '128m', 'pids_limit': 64,
        }
        services['named'] = dict(services['fixture'], container_name=project + '-named',
                                 networks={'egress_net': {'ipv4_address': named_ip}})
        services['dnsobserver'] = dict(services['fixture'], container_name=project + '-dnsobserver',
                                       entrypoint=['python3', '/fixture/dns_observer.py'],
                                       networks={'sandbox_net': {'ipv4_address': observer_sandbox_ip},
                                                 'egress_net': {'ipv4_address': observer_public_ip}})
        config_path = fixture / 'compose.json'
        config_path.write_text(json.dumps(model))
        config_path.chmod(0o600)
        compose = ['docker', 'compose', '-f', str(config_path), '-p', project]
        require(set(services) == {'gateway', 'uiproxy', 'safebrowse', 'fixture', 'named', 'dnsobserver'} and not gw.get('network_mode')
                and all(services[name]['labels'] == {'safebrowse.schema': '1', 'safebrowse.session': 'manual',
                                                     'safebrowse.mode': 'direct'} for name in ('gateway', 'uiproxy', 'safebrowse')),
                'the direct topology resolves to its three services, labelled as a direct session')
        config = verify.Runtime(browser=browser['container_name'], gateway=gw['container_name'],
                                ui=services['uiproxy']['container_name'], network=model['networks']['sandbox_net']['name'],
                                vpn=project + '-vpn', egress=model['networks']['egress_net']['name'],
                                gateway_networks=(project + '_private',),
                                proxy='http://gateway:3128', ui_port=port, policy_path=policy_path,
                                subnet=sandbox_subnet,
                                allowed_url=f'http://{public_ip}/positive', direct_host=public_ip, direct_port=80,
                                denied_urls=tuple(u for u in verify.DENIED_URLS if 'example.com:' not in u) +
                                (f'http://{private_ip}/denied-private', 'http://private.safebrowse.test/denied-hostname',
                                 f'http://{public_ip}:8080/denied-port', 'http://ads.doubleclick.net/denied-blocklist'))
        def desktop_ready():
            url = f'https://127.0.0.1:{port}/'
            anon = command('curl', '--disable', '-ks', '--noproxy', '*', '--max-time', '3', '-o', '/dev/null',
                           '-w', '%{http_code}', url, check=False)
            auth = command('curl', '--disable', '--config', '-', '-ks', '--noproxy', '*', '--max-time', '3',
                           '-o', '/dev/null', '-w', '%{http_code}', url,
                           input=f'user = "{env["SANDBOX_USER"]}:{env["SANDBOX_PASSWORD"]}"\n', check=False)
            return anon.returncode == auth.returncode == 0 and anon.stdout == '401' and auth.stdout == '200'
        def requests(server='fixture'):
            result = command('docker', 'exec', f'{project}-{server}', 'cat', '/tmp/requests.jsonl', check=False)
            return [json.loads(line) for line in result.stdout.splitlines()]
        def confinement(name):
            """The verifier's Docker-confinement checks against one container: (counts, output)."""
            report, output = verify.Report(), io.StringIO()
            inspected = json.loads(command('docker', 'inspect', name, env=env).stdout)[0]
            with contextlib.redirect_stdout(output):
                verify.check_confinement(report, inspected, daemon, config._replace(browser=name))
            return report.counts, output.getvalue()
        extras = []
        def unapproved(label, *options):
            """A throwaway container from the same image whose confinement differs from the approved one."""
            name = f'{project}-{label}'
            extras.append(name)
            command('docker', 'run', '--detach', '--name', name, '--network', 'none', '--cap-drop', 'ALL',
                    '--security-opt', 'no-new-privileges:true', *[v for o in options for v in ('--security-opt', o)],
                    '--memory', '256m', '--pids-limit', '64', '--entrypoint', 'sleep', image, '300', env=env)
            return name
        def control(label, network, *options):
            """A throwaway container from the browser image on one of the fixture networks, for DNS comparisons."""
            name = f'{project}-{label}'
            extras.append(name)
            command('docker', 'run', '--detach', '--name', name, '--network', network, '--cap-drop', 'ALL',
                    '--security-opt', 'no-new-privileges:true', *options, '--memory', '256m', '--pids-limit', '64',
                    '--volume', f'{fixture}:/fixture:ro', '--entrypoint', 'sleep', image, '600', env=env)
            return name
        def lines(container, path):
            result = command('docker', 'exec', container, 'cat', path, env=env, check=False)
            return [json.loads(line) for line in result.stdout.splitlines()]
        def sniff(target):
            """Capture inside `target`'s network namespace; returns a function giving the packets recorded so far."""
            name = f'{project}-sniff-{len(extras)}'
            extras.append(name)
            command('docker', 'run', '--detach', '--name', name, '--network', 'container:' + target, '--user', '0:0',
                    '--cap-drop', 'ALL', '--cap-add', 'NET_RAW', '--security-opt', 'no-new-privileges:true',
                    '--memory', '128m', '--pids-limit', '32', '--volume', f'{fixture}:/fixture:ro',
                    '--entrypoint', 'python3', image, '/fixture/dns_sniff.py', env=env)
            wait_for(f'packet capture is running in the network namespace of {target.removeprefix(project + "-") or "the browser"}',
                     lambda: {'ready': True} in lines(name, '/tmp/packets.jsonl'), 30)
            return lambda: [packet for packet in lines(name, '/tmp/packets.jsonl') if 'interface' in packet]
        def lookup(container, external):
            """The verifier's own probe run in `container`, and the verifier's two verdicts on that container."""
            target = config._replace(browser=container, external_name=external)
            probe = verify.resolver_probe(verify.run_probe(verify.RESOLVER_PROBE, 'gateway', external, config=target))
            report, output = verify.Report(), io.StringIO()
            inspected = json.loads(command('docker', 'inspect', container, env=env).stdout)[0]
            with contextlib.redirect_stdout(output):
                verify.check_resolver(report, inspected, target)
            if probe is None:
                raise RuntimeError(f'the resolver probe could not run in {container}')
            return probe, [line.split()[0] for line in output.getvalue().splitlines()]
        def observed_queries(name):
            return [query for query in lines(project + '-dnsobserver', '/tmp/queries.jsonl') if query['name'] == name]
        try:
            print('Building the pinned image and starting the isolated integration stack...', flush=True)
            command(*compose, 'build', env=env, timeout=900)
            command(*compose, 'up', '-d', env=env, timeout=180)
            wait_for('desktop requires authentication and accepts fixture credentials', desktop_ready)
            wait_for('Firefox accepts a blank initialization tab', lambda: open_url.open_url('about:blank', config.browser) == 0, 60)
            # Prove that a private target is actually listening from the gateway.
            command('docker', 'exec', config.gateway, 'bash', '-c', f'exec 3<>/dev/tcp/{private_ip}/80')
            transcript = io.StringIO()
            with contextlib.redirect_stdout(transcript):
                passed = verify.main(config, wait_browser=30)
            checked = transcript.getvalue()
            print(checked, end='', flush=True)
            require(passed == 0, 'all runtime checks pass against deterministic local targets')
            counts, output = confinement(config.browser)
            require(counts['FAIL'] == counts['INCONCLUSIVE'] == 0 and 'exactly the approved seccomp profile' in output
                    and 'outer filter refuses' in output, 'browser container runs under the approved outer filter')
            if 'name=apparmor' in daemon['security']:
                require(f'PASS  browser is confined by AppArmor profile {verify.APPARMOR_PROFILE} in enforce mode' in output,
                        'browser container is confined by the expected AppArmor profile')
            else:
                print('INFO  this daemon reports no AppArmor; AppArmor confinement was not exercised', flush=True)
            # The verifier must tell the approved configuration from weaker or merely different ones.
            counts, output = confinement(unapproved('unconfined', 'seccomp=unconfined'))
            require(counts['FAIL'] >= 5 and "seccomp=unconfined: Docker's outer syscall filter is disabled" in output
                    and 'FAIL  a UID 1000 process outside Firefox' in output and 'FAIL  outer filter refuses' in output,
                    'a container without the outer filter fails the confinement checks')
            counts, output = confinement(unapproved('builtin'))
            require(counts['FAIL'] == 1 and "daemon's default seccomp profile" in output and 'PASS  outer filter refuses' in output,
                    "Docker's built-in profile is reported as different from the approved one, though it does filter")
            builtin = verify.namespace_state(verify.run_probe(verify.NAMESPACE_PROBE,
                                                              config=config._replace(browser=f'{project}-builtin')))
            require(builtin[0] == 'INCONCLUSIVE' and 'clone: EPERM' in builtin[1],
                    "Firefox's namespace test is refused under the built-in profile and passes nothing")
            counts, output = confinement(unapproved('apparmor', 'seccomp=' + str(profile), 'apparmor=unconfined'))
            require(counts['FAIL'] >= 1 and 'FAIL  browser does not opt out of confinement' in output,
                    'a container that opts out of AppArmor fails the confinement checks')
            for name in extras:
                command('docker', 'rm', '--force', name, env=env)
            del extras[:]

            # ---------------------------------------------------------------- probe isolation
            # The browser user's home is a writable tmpfs, and Python reads start-up files from it. Each
            # injection below is shown to run under ordinary Python (so the payload is live) and not under
            # the command the verifier's probes actually use.
            print('Probe isolation: Python start-up injection as the browser user, with and without isolated mode...', flush=True)
            marker = f'/tmp/injected-{token}'
            # Acts only in a `python3 ... -c` process, so nothing else that starts Python in the container is affected.
            payload = f"import sys; '-c' in getattr(sys, 'orig_argv', ()) and open({marker!r}, 'a').write('ran')"
            def browser_user(*args, options=(), input=None):
                return command('docker', 'exec', '-i', *options, '--user', '1000:1000', config.browser, *args,
                               env=env, input=input, check=False)
            def plant(directory, name, text):
                browser_user('sh', '-c', 'mkdir -p "$1" && cat > "$1/$2"', 'sh', directory, name, input=text).check_returncode()
            def executes(*args, options=()):
                """Whether running this command in the browser container executes the planted payload."""
                browser_user('rm', '-f', marker).check_returncode()
                browser_user(*args, options=options)
                return browser_user('test', '-e', marker).returncode == 0
            home, enabled, user_site = browser_user('python3', '-c', 'import os, site; print(os.environ.get("HOME")); '
                                                    'print(site.ENABLE_USER_SITE); print(site.getusersitepackages())').stdout.split()
            require(home == '/config' and enabled == 'True' and user_site.startswith('/config/'),
                    "the browser user's Python user site is enabled and lies under its own writable home")
            writable = browser_user(*verify.PROBE_PYTHON, 'import json, os, shutil, sys\n'
                                    'found = [os.path.dirname(shutil.which("python3")), os.path.realpath(sys.executable)] + sys.path\n'
                                    'print(json.dumps(sorted({p for p in found if os.path.exists(p) and os.access(p, os.W_OK)})))')
            require(writable.returncode == 0 and json.loads(writable.stdout) == [],
                    'the interpreter the probes start, its directory on PATH and every directory on its isolated import path '
                    'are not writable by the browser user')
            ordinary, isolated = ('python3', '-c'), verify.PROBE_PYTHON
            shadow, working = f'/tmp/shadow-{token}', f'/tmp/working-{token}'
            plant(user_site, f'zz-{token}.pth', f'import os; exec({payload!r})\n')
            require(executes(*ordinary, 'pass') and not executes(*isolated, 'pass'),
                    'a .pth file in the browser user site runs under ordinary Python and does not run in isolated mode')
            plant(shadow, 'json.py', payload + '\n')
            browser_user('rm', '-f', f'{user_site}/zz-{token}.pth').check_returncode()
            require(executes(*ordinary, 'import json', options=('--env', 'PYTHONPATH=' + shadow))
                    and not executes(*isolated, 'import json', options=('--env', 'PYTHONPATH=' + shadow)),
                    'a module on PYTHONPATH that shadows the standard library is imported by ordinary Python and ignored in isolated mode')
            plant(working, 'json.py', payload + '\n')
            require(executes(*ordinary, 'import json', options=('--workdir', working))
                    and not executes(*isolated, 'import json', options=('--workdir', working)),
                    'a module in a writable working directory is imported by ordinary Python and ignored in isolated mode')
            # The verifier itself, with the user-site payload in place: the one injection a process in the
            # container can arrange for a probe it does not start (it controls neither the environment nor
            # the working directory of `docker exec`).
            plant(user_site, f'zz-{token}.pth', f'import os; exec({payload!r})\n')
            require(executes(*ordinary, 'pass'), 'the user-site payload is live again before the verifier runs')
            browser_user('rm', '-f', marker).check_returncode()
            started = []
            for name in ('OUTER_PROBE', 'DIRECT_PROBE', 'NAMESPACE_PROBE', 'SANDBOX_PROBE', 'PROFILE_PROBE', 'RESOLVER_PROBE',
                         'LISTEN_PROBE'):
                arguments = {'DIRECT_PROBE': (config.direct_host, str(config.direct_port)), 'RESOLVER_PROBE': ('gateway', 'example.com'),
                             'LISTEN_PROBE': ('gateway', '3128')}.get(name, ())
                outcome = verify.run_probe(getattr(verify, name), *arguments, config=config)
                started.append(outcome.returncode == 0 and bool(outcome.stdout.strip()))
            require(all(started) and browser_user('test', '-e', marker).returncode != 0,
                    "each of the verifier's seven Python probes runs and prints its result without executing the payload")
            again = io.StringIO()
            with contextlib.redirect_stdout(again):
                passed = verify.main(config, wait_browser=30)
            require(passed == 0 and browser_user('test', '-e', marker).returncode != 0,
                    'a complete verification with the payload in place passes every check and never executes it')
            require(executes(*ordinary, 'pass'), 'the payload was still live after that run: ordinary Python executes it')
            browser_user('rm', '-rf', f'{user_site}/zz-{token}.pth', shadow, working, marker).check_returncode()
            require(not executes(*ordinary, 'pass'), 'the planted files are removed from the fixture again')

            # ---------------------------------------------------------------- DNS forwarding
            print('DNS forwarding: an observing resolver, positive controls, then the restricted browser...', flush=True)
            resolved, refused = {'resolver': 'answer', 'lookup': 'resolved'}, {'resolver': 'failure', 'lookup': 'temporary'}
            nonexistent = {'resolver': 'negative', 'lookup': 'negative'}
            name_for = lambda kind, who: f'{kind}-{who}-{token}.safebrowse.test'
            require('PASS  browser DNS forwarding is restricted' in checked and 'PASS  browser name resolution' in checked,
                    'the full verification passed both DNS checks: enforcement and behaviour')
            # Control 1. Forwarding allowed, to a resolver elsewhere on the browser's own internal network.
            forward = control('dnsforward', config.network, '--dns', observer_sandbox_ip)
            packets = sniff(forward)
            probe, states = lookup(forward, name_for('observed', 'forward'))
            require(probe['internal'] == resolved and probe['external'] == resolved and observed_queries(name_for('observed', 'forward')),
                    'positive control: with forwarding allowed, the observing resolver receives the query and the name resolves '
                    '(an internal network alone does not prevent this)')
            require(states == ['FAIL', 'FAIL'], 'the verifier fails that container on both DNS checks')
            probe, states = lookup(forward, name_for('absent', 'forward'))
            require(probe['external'] == nonexistent and observed_queries(name_for('absent', 'forward')),
                    'a name the observer says does not exist fails to resolve, although the query demonstrably reached the observer')
            require(states == ['FAIL', 'INCONCLUSIVE'], 'that NXDOMAIN is not taken as proof that no query left: the verifier does not pass it')
            leaving = [p for p in packets() if 53 in (p['sport'], p['dport']) and p['interface'] != 'lo']
            require(any(p['target'] == observer_sandbox_ip and p['dport'] == 53 for p in leaving),
                    "the capture in that container's namespace sees the forwarded queries leave on its network interface")
            # Control 2. No restriction at all, on a network with external access: Docker forwards through the host.
            unrestricted = control('dnshost', config.egress)
            canary = next((name for name in ('host.docker.internal', 'example.com')
                           if lookup(unrestricted, name)[0]['external'] == resolved), None)
            require(canary is not None, "positive control: an unrestricted container resolves a name through this computer's own "
                                        'DNS (tried host.docker.internal, then example.com)')
            print(f'INFO  name answered by the host DNS path: {canary}', flush=True)
            require(lookup(unrestricted, canary)[1] == ['FAIL', 'FAIL'] and not observed_queries(canary),
                    'the verifier fails that container; the host path bypasses the observer, so only its answer reveals it')
            # The restriction, on that same externally connected network, with a listener on the container's own loopback.
            local = control('dnslocal', config.egress, '--dns', '127.0.0.1', '--cap-add', 'NET_BIND_SERVICE')
            command('docker', 'exec', '--detach', '--user', '0:0', local, 'python3', '/fixture/dns_observer.py', '127.0.0.1', env=env)
            wait_for("a listener is running on that container's own loopback address",
                     lambda: command('docker', 'exec', local, 'test', '-e', '/tmp/queries.jsonl', env=env, check=False).returncode == 0, 30)
            probe, states = lookup(local, canary)
            received = [query for query in lines(local, '/tmp/queries.jsonl') if query['name'] == canary]
            require(probe['servers'] == ['127.0.0.11'] and probe['upstream'] == ['127.0.0.1'] and received
                    and {query['client'] for query in received} == {'127.0.0.1'},
                    "with dns 127.0.0.1, Docker hands an unknown name to the container's own loopback: the listener there receives it")
            require(probe['external'] == nonexistent and not observed_queries(canary) and states == ['PASS', 'INCONCLUSIVE'],
                    "Docker does not fall back to the host's DNS, which answers that name; a does-not-exist answer still does not pass")
            quiet = control('dnsquiet', config.egress, '--dns', '127.0.0.1')
            probe, states = lookup(quiet, canary)
            require(probe['internal'] == resolved and probe['external'] == refused and states == ['PASS', 'PASS'],
                    'with nothing listening there, service names still resolve and the external name is refused, '
                    'even on a network with external access')
            # The browser itself, as the launcher's own Compose definition created it.
            packets = sniff(config.browser)
            browser_state = json.loads(command('docker', 'inspect', config.browser, env=env).stdout)[0]
            browser_ip = browser_state['NetworkSettings']['Networks'][config.network]['IPAddress']
            results = [lookup(config.browser, name) for name in
                       (name_for('observed', 'browser'), name_for('absent', 'browser'), canary)]
            verify.execute('curl', '--disable', '--silent', '--max-time', '10', '--noproxy', '', '--proxy', config.proxy,
                           '--output', '/dev/null', config.allowed_url, config=config).check_returncode()
            require(browser_state['HostConfig'].get('Dns') == ['127.0.0.1']
                    and all(probe['servers'] == ['127.0.0.11'] and probe['upstream'] == ['127.0.0.1'] for probe, _ in results),
                    "the browser was created with the restriction: Docker's resolver is its only nameserver and its own "
                    'loopback the only forwarding target')
            require(all(probe['internal'] == resolved for probe, _ in results), 'the restricted browser still resolves the gateway by name')
            require(all(probe['external'] == refused and states == ['PASS', 'PASS'] for probe, states in results),
                    "three external names (one the observer would answer, one it would deny, one the host's DNS answers) are "
                    "all refused by Docker's resolver, and the verifier passes on enforcement plus that refusal")
            from_browser = [query for query in lines(project + '-dnsobserver', '/tmp/queries.jsonl')
                            if query['client'] == browser_ip or '-browser-' in query['name']]
            require(not from_browser and not observed_queries(canary),
                    "the observing resolver on the browser's own network received none of the browser's queries")
            captured = packets()
            dns = [p for p in captured if 53 in (p['sport'], p['dport'])]
            require(any(p['dport'] == 3128 and p['interface'] != 'lo' for p in captured),
                    "the capture in the browser's namespace is live: it sees the proxy connection leave on the sandbox interface")
            require(dns and all(p['interface'] == 'lo' and p['source'].startswith('127.') and p['target'].startswith('127.') for p in dns),
                    "the capture saw the browser's DNS traffic, and none of it left the namespace: every packet stayed on the "
                    'loopback interface, between loopback addresses')
            print(f"INFO  DNS packets seen on the browser's loopback interface during those lookups: {len(dns)}", flush=True)
            for name in extras:
                command('docker', 'rm', '--force', name, env=env)
            del extras[:]

            reached = verify.execute('curl', '--disable', '--silent', '--show-error', '--fail', '--max-time', '10', '--noproxy', '',
                                     '--proxy', config.proxy, 'http://allowed.safebrowse.test/allowed-hostname', config=config)
            require(reached.returncode == 0 and 'Local test page' in reached.stdout
                    and [r['path'] for r in requests('named')] == ['/allowed-hostname'],
                    'a hostname that is not blocklisted reaches the live local target through the gateway')
            require('proxy denial: http://ads.doubleclick.net/denied-blocklist (HTTP 403' in checked,
                    'the blocklisted hostname for that same target was refused by the gateway and never reached it')
            tls = verify.execute('curl', '--disable', '--silent', '--show-error', '--fail', '--max-time', '10',
                                 '--noproxy', '', '--proxy', config.proxy, '--cacert', '/dev/stdin',
                                 f'https://{public_ip}/tls-connect', input=(fixture / 'cert.pem').read_text(), config=config)
            require(tls.returncode == 0 and 'Local test page' in tls.stdout, 'HTTPS CONNECT reaches the local TLS fixture with certificate verification')
            marker = '/browser-' + token
            require(open_url.open_url('http://' + public_ip + marker, config.browser) == 0, 'URL opener sends a tab to Firefox')
            wait_for('Firefox loads the requested local page', lambda: any(r['path'] == marker and 'Firefox/' in r['agent'] for r in requests()), 30)
            require(not any(r['path'].startswith('/denied-') for r in requests()), 'denied requests never reach the live private target')
            sentinel = '/config/integration-session-sentinel'
            verify.execute('touch', sentinel, config=config).check_returncode()
            command(*compose, 'stop', 'gateway', env=env)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                failed = verify.main(config)
            require(failed == 1 and 'PASS' not in output.getvalue(), 'stopped gateway fails verification without passing checks')
            bypass = verify.execute('curl', '--disable', '--silent', '--max-time', '5', '--noproxy', '',
                                    '--proxy', config.proxy, config.allowed_url, config=config)
            require(bypass.returncode != 0, 'browsing through a stopped gateway fails')
            command(*compose, 'down', '--volumes', '--remove-orphans', env=env)
            command(*compose, 'up', '-d', env=env, timeout=180)
            wait_for('recreated desktop authenticates', desktop_ready)
            verify.execute('test', '!', '-e', sentinel, config=config).check_returncode()
            require(True, 'recreating the session discards the previous profile sentinel')
        finally:
            print('Cleaning up integration containers, networks and image...', flush=True)
            for name in extras:
                command('docker', 'rm', '--force', name, env=env, check=False)
            command(*compose, 'down', '--volumes', '--remove-orphans', env=env, timeout=120)
            command('docker', 'image', 'rm', image, env=env, timeout=60, check=False)
    print('Integration checks passed.', flush=True)
    return 0


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'FAIL  {error}', file=sys.stderr)
        sys.exit(1)
