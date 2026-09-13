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


def main():
    # Keep the test independent of the caller's Compose overrides and credentials.
    env = {k: v for k, v in os.environ.items() if not k.startswith('COMPOSE_')
           and k not in ('SANDBOX_USER', 'SANDBOX_PASSWORD')}
    env.update(SANDBOX_USER='integration', SANDBOX_PASSWORD=secrets.token_hex(24))
    major = int(command('docker', 'version', '--format', '{{.Server.Version}}', env=env).stdout.split('.')[0])
    require(major >= 28, 'Docker Engine supports isolated bridge mode (28+)')
    token = secrets.token_hex(5)
    project = 'safebrowse-test-' + token
    # These addresses exist only on local Docker bridges. Pick unused /24s and
    # let Docker reject any concurrent collision; never remove another network.
    existing_ids = command('docker', 'network', 'ls', '--quiet', env=env).stdout.split()
    used = []
    if existing_ids:
        for network in json.loads(command('docker', 'network', 'inspect', *existing_ids, env=env).stdout):
            used += [ipaddress.ip_network(c['Subnet']) for c in (network.get('IPAM', {}).get('Config') or []) if c.get('Subnet')]
    def unused(prefix):
        for octet in range(40, 240):
            net = ipaddress.ip_network(f'{prefix}.{octet}.0/24')
            if not any(net.overlaps(other) for other in used if other.version == 4):
                used.append(net)
                return str(net)
        raise RuntimeError('no unused integration subnet')
    sandbox_subnet, public_subnet, private_subnet = unused('172.29'), unused('198.18'), unused('10.231')
    gateway_ip = sandbox_subnet.split('/')[0][:-1] + '2'
    public_ip = public_subnet.split('/')[0][:-1] + '10'
    private_ip = private_subnet.split('/')[0][:-1] + '10'
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
            require(policy['policies']['Proxy'][key] == '172.28.0.2:3128', f'fixture recognizes {key}')
            policy['policies']['Proxy'][key] = gateway_ip + ':3128'
        policy_path = fixture / 'policies/firefox-policies.json'
        policy_path.write_text(json.dumps(policy))
        squid = replace_once((ROOT / 'gateway/squid.conf').read_text(), 'acl sandbox src 172.28.0.0/24',
                             'acl sandbox src ' + sandbox_subnet)
        (fixture / 'gateway/squid.conf').write_text(squid + '\nhosts_file /etc/squid/fixture-hosts\n')
        shutil.copyfile(ROOT / 'gateway/blocklist.txt', fixture / 'gateway/blocklist.txt')
        (fixture / 'hosts').write_text(f'{private_ip} private.safebrowse.test\n127.0.0.1 localtest.me\n')
        (fixture / 'server.py').write_text(SERVER)
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
        gw = services['gateway']
        gw['networks']['sandbox_net']['ipv4_address'] = gateway_ip
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
        config_path = fixture / 'compose.json'
        config_path.write_text(json.dumps(model))
        config_path.chmod(0o600)
        compose = ['docker', 'compose', '-f', str(config_path), '-p', project]
        config = verify.Runtime(browser=browser['container_name'], gateway=gw['container_name'],
                                ui=services['uiproxy']['container_name'], network=model['networks']['sandbox_net']['name'],
                                proxy='http://' + gateway_ip + ':3128', ui_port=port, policy_path=policy_path,
                                allowed_url=f'http://{public_ip}/positive', direct_host=public_ip, direct_port=80,
                                denied_urls=tuple(u for u in verify.DENIED_URLS if 'example.com:' not in u) +
                                (f'http://{private_ip}/denied-private', 'http://private.safebrowse.test/denied-hostname',
                                 f'http://{public_ip}:8080/denied-port'))
        def desktop_ready():
            url = f'https://127.0.0.1:{port}/'
            anon = command('curl', '--disable', '-ks', '--noproxy', '*', '--max-time', '3', '-o', '/dev/null',
                           '-w', '%{http_code}', url, check=False)
            auth = command('curl', '--disable', '--config', '-', '-ks', '--noproxy', '*', '--max-time', '3',
                           '-o', '/dev/null', '-w', '%{http_code}', url,
                           input=f'user = "{env["SANDBOX_USER"]}:{env["SANDBOX_PASSWORD"]}"\n', check=False)
            return anon.returncode == auth.returncode == 0 and anon.stdout == '401' and auth.stdout == '200'
        def requests():
            result = command('docker', 'exec', project + '-fixture', 'cat', '/tmp/requests.jsonl', check=False)
            return [json.loads(line) for line in result.stdout.splitlines()]
        try:
            print('Building the pinned image and starting the isolated integration stack...', flush=True)
            command(*compose, 'build', env=env, timeout=900)
            command(*compose, 'up', '-d', env=env, timeout=180)
            wait_for('desktop requires authentication and accepts fixture credentials', desktop_ready)
            wait_for('Firefox accepts a blank initialization tab', lambda: open_url.open_url('about:blank', config.browser) == 0, 60)
            # Prove that a private target is actually listening from the gateway.
            command('docker', 'exec', config.gateway, 'bash', '-c', f'exec 3<>/dev/tcp/{private_ip}/80')
            require(verify.main(config, wait_browser=30) == 0, 'all runtime checks pass against deterministic local targets')
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
