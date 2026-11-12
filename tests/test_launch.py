"""Launcher lifecycle, credential, readiness and URL safety regressions, without Docker."""
import argparse
import base64
import contextlib
import gc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import warnings

ROOT = Path(__file__).resolve().parent.parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


open_url = module('open_url')
safebrowse = module('safebrowse')
CREDENTIALS = 'SANDBOX_USER=test\nSANDBOX_PASSWORD=test-password\n'
COMPOSE = ['docker', 'compose']
DOWN = COMPOSE + ['down', '--volumes', '--remove-orphans']
SESSION_ID = '0123456789abcdef'
NAMES = {'safebrowse': 'browser', 'safebrowse-gw': 'gateway', 'safebrowse-ui': 'ui', 'safebrowse-vpn': 'vpn'}


def discovery(name):
    """The one read-only inspection the launcher makes of each possible session container."""
    return ['docker', 'inspect', '--type', 'container', '--format', safebrowse.DISCOVER, name]


def compose_model(mode, env, root, port=3011):
    """What `docker compose config --format json` reports for the reviewed topology of `mode`."""
    labels = {'safebrowse.schema': '1', 'safebrowse.session': env.get('SAFEBROWSE_SESSION', 'manual'),
              'safebrowse.mode': mode}
    if mode == 'vpn':
        labels[safebrowse.FINGERPRINT_LABEL] = env.get('SAFEBROWSE_VPN_FINGERPRINT', '')
    base = {'cap_drop': ['ALL'], 'restart': 'no', 'labels': labels}
    both = {'sandbox_net': None, 'egress_net': None}
    services = {
        'gateway': dict(base, image='ubuntu/squid@sha256:' + '1' * 64, networks=dict(both), hostname='gateway'),
        'uiproxy': dict(base, image='alpine/socat@sha256:' + '2' * 64, networks=dict(both),
                        ports=[{'host_ip': '127.0.0.1', 'published': str(port), 'target': 3001}]),
        'safebrowse': dict(base, image='safebrowse:latest', build={'context': str(root)}, networks={'sandbox_net': None},
                           dns=['127.0.0.1'], environment={'PASSWORD': env.get('SANDBOX_PASSWORD', '')}),
    }
    if mode == 'vpn':
        directory = env.get('SAFEBROWSE_VPN_DIR', str(Path(root) / '.runtime/vpn/none'))
        services['gateway'] = dict(base, image=services['gateway']['image'], network_mode='service:vpn')
        services['vpn'] = dict(
            base, image='qmcgaw/gluetun@sha256:' + '3' * 64, cap_add=['NET_ADMIN', 'DAC_OVERRIDE'],
            networks={'sandbox_net': {'aliases': ['gateway'], 'driver_opts': {'com.docker.network.endpoint.ifname': 'sbx0'}},
                      'egress_net': {'driver_opts': {'com.docker.network.endpoint.ifname': 'egr0'}}},
            volumes=[{'type': 'bind', 'source': directory + '/wg0.conf', 'target': '/run/secrets/wg0.conf', 'read_only': True},
                     {'type': 'bind', 'source': directory + '/post-rules.txt', 'target': '/iptables/post-rules.txt', 'read_only': True},
                     {'type': 'bind', 'source': str(Path(root) / 'security/gluetun-auth.toml'),
                      'target': '/gluetun/auth/config.toml', 'read_only': True}])
    return {'name': 'safebrowse', 'services': services,
            'networks': {'sandbox_net': {'name': 'safebrowse_sandbox'}, 'egress_net': {'name': 'safebrowse_egress'}}}


class URLTests(unittest.TestCase):
    def test_reject_unsafe_or_ambiguous_urls(self):
        for value in ('file:///etc/passwd', 'javascript:alert(1)', 'data:text/html,hi', '--help',
                      'https://', '//example.com', 'https://user:pass@example.com/',
                      'https://example.com:99999/', 'https://example.com:0/',
                      'https://[::1', 'https://exa mple.com', 'https://example.com/\n--arg',
                      ' https://example.com', 'https://example.com\\@localhost'):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                open_url.validate_url(value)

    def test_shell_metacharacters_remain_one_argument(self):
        url = 'https://example.com/?x=$(id);&quote="hello"&backtick=`id`'
        self.assertEqual(open_url.validate_url(url), url)
        with patch.object(open_url.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertEqual(open_url.open_url(url), 0)
        args = run.call_args.args[0]
        self.assertEqual(args[-1], url)
        self.assertNotIn(url, open_url.OPEN_PROBE)
        self.assertNotIn('shell', run.call_args.kwargs)
        self.assertEqual(args[args.index('--user') + 1], '1000:1000')


class Recorder:
    """Stands in for every process the launcher starts, and records each one.

    Helper scripts appear as ['network.py', ...]; everything else as its argv.
    """

    def __init__(self, **settings):
        self.settings = settings
        self.calls, self.envs, self.cwds, self.files, self.seen = [], [], [], [], {}

    def nth(self, key):
        self.seen[key] = self.seen.get(key, 0) + 1
        return self.seen[key]

    def __call__(self, args, env=None, cwd=None, capture=False, merge=False, timeout=None):
        call = [Path(args[1]).name] + list(args[2:]) if args[0] == sys.executable else list(args)
        # Compose calls are recorded without their '-f FILE' selection, which is kept beside them.
        files = []
        while call[:2] == COMPOSE and call[2:3] == ['-f']:
            files.append(call[3])
            del call[2:4]
        self.calls.append(call)
        self.envs.append(env)
        self.cwds.append(cwd)
        self.files.append(tuple(files) if call[:2] == COMPOSE else None)
        self.env, self.selected = env or {}, tuple(files)
        code, output, *error = self.answer(call)
        return subprocess.CompletedProcess(args, code, output if capture else None,
                                           (error[0] if error else '') if capture and not merge else None)

    def containers(self):
        """role -> running, for the session the settings describe."""
        s = self.settings
        if 'containers' in s:
            return s['containers']
        if not s.get('existing'):
            return {}
        roles = ('browser', 'gateway', 'ui') + (('vpn',) if s.get('mode') == 'vpn' else ())
        return {role: True for role in roles}

    def discover(self, name):
        s, role = self.settings, NAMES[name]
        # After a successful teardown nothing is left, unless a test says otherwise.
        removed = any(call[:3] == COMPOSE + ['down'] for call in self.calls) and not s.get('down_exit')
        if s.get('inspect_exit') or (removed and s.get('inspect_exit_after_down')):
            return 1, '', 'Cannot connect to the Docker daemon'
        present = s.get('leftover', {}) if removed else self.containers()
        if role not in present:
            return 1, '', 'Error response from daemon: No such container: ' + name
        mode = s.get('labels', {}).get(role, s.get('mode', 'direct'))
        # A label the container does not have comes back from `docker inspect --format` as this placeholder.
        absent = '<no value>'
        labels = '|'.join([absent] * 3) if mode == 'legacy' else '1|%s|%s' % (s.get('session', SESSION_ID), mode)
        # The configuration fingerprint a VPN session's containers carry: one value, or one per role.
        fingerprint = s.get('fingerprint', absent)
        if isinstance(fingerprint, dict):
            fingerprint = fingerprint.get(role, absent)
        return 0, 'id-%s|%s|%s|%s\n' % (role, 'true' if present[role] else 'false', labels, fingerprint or s.get('empty', absent))

    def answer(self, call):
        s = self.settings
        if call[:-1] == discovery('')[:-1]:
            return self.discover(call[-1])
        if call[:3] == COMPOSE + ['config']:
            mode = 'vpn' if any('vpn' in name for name in self.selected) else 'direct'
            model = compose_model(mode, self.env, s.get('root', ''))
            if s.get('model'):
                s['model'](model)
            return s.get('config_exit', 0), json.dumps(model)
        if call[:3] == ['docker', 'image', 'inspect']:
            return s.get('image_exit', 0), 'sha256:local\n'
        if call[:2] == ['docker', 'pull']:
            return s.get('pull_exit', 0), ''
        if call[:2] == ['docker', 'logs']:
            return 0, ''
        if call[0] == 'network.py':
            if call[1] == 'current':
                return (0, '172.31.9.0/24\n') if s.get('state', True) else (1, '')
            return (s['select_exit'], '') if s.get('select_exit') else (0, '172.31.%d.0/24\n' % call.count('--skip'))
        if call[0] == 'open_url.py':
            if call[1:] == ['--initialize']:
                return int(self.nth('initialize') <= s.get('init_failures', 0)), ''
            return s.get('open_exit', 0), ''
        if call[0] == 'verify.py':
            return s.get('verify_exit', 0), ''
        if call[0] == 'pin.py':
            return s.get('pin_exit', 0), ''
        if call[:2] == ['docker', 'info'] and '{{json .SecurityOptions}}' in call:
            return s.get('security_exit', 0), s.get('security', '["name=seccomp,profile=builtin","name=cgroupns"]') + '\n'
        if call[:2] == ['docker', 'info']:
            return s.get('daemon_exit', 0), s.get('memory', '8000000000') + '\n'
        if call[:2] == ['docker', 'version']:
            return 0, s.get('engine', '29.0.0') + '\n'
        if call[:3] == ['docker', 'network', 'inspect']:
            return (1, '') if s.get('bridge', 'isolated') is None else (0, s.get('bridge', 'isolated') + '\n')
        if call[:3] == COMPOSE + ['build']:
            return s.get('build_exit', 0), ''
        if call[:3] == COMPOSE + ['down']:
            return s.get('down_exit', 0), ''
        if call[:3] == COMPOSE + ['up']:
            if self.nth('up') <= s.get('overlaps', 0):
                return 1, s.get('overlap_text', 'invalid pool request: Pool overlaps with other one on this address space\n')
            return s.get('up_exit', 0), s.get('up_text', 'started\n')
        if call[:2] == ['docker', 'inspect'] and call[-1] == 'safebrowse-vpn':
            return (0, 'running\n') if s.get('mode') == 'vpn' else (1, '', 'No such container')
        if call[:2] == ['docker', 'inspect']:
            return (1, '') if s.get('gateway') is None and 'gateway' in s else (0, s.get('gateway', 'running') + '\n')
        if call[:2] == ['docker', 'exec'] and call[-1].endswith('access.log'):
            return s.get('access_exit', 1), 'access line\n'
        return 0, ''

    def compose(self, action):
        return [call for call in self.calls if call[:3] == COMPOSE + [action]]

    def env_of(self, call):
        return self.envs[self.calls.index(call)]


class Clock:
    def __init__(self):
        self.now = 0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class Desktop:
    """A desktop that demands authentication and then accepts it."""

    def __init__(self, anonymous=401, authenticated=200):
        self.anonymous, self.authenticated, self.requests = anonymous, authenticated, []

    def __call__(self, port, authorization=None):
        self.requests.append((port, authorization))
        status = self.authenticated if authorization else self.anonymous
        if isinstance(status, BaseException):
            raise status
        return status


class Outcome:
    def __init__(self, code, stdout, stderr, recorder, clock, desktop):
        self.code, self.stdout, self.stderr = code, stdout, stderr
        self.recorder, self.calls, self.clock, self.desktop = recorder, recorder.calls, clock, desktop


class LauncherCase(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='safebrowse-unit-'))
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / '.env').write_text(CREDENTIALS)
        (self.root / 'gateway').mkdir()
        for name in safebrowse.SECURITY_INPUTS:
            shutil.copyfile(ROOT / name, self.root / name)

    def runtime_state(self):
        (self.root / '.runtime').mkdir(exist_ok=True)
        (self.root / '.runtime/network.json').write_text('{"subnet": "172.31.9.0/24"}\n')

    def invoke(self, *argv, environ=None, desktop=None, run=None, euid=1000, **settings):
        recorder, clock, desktop = Recorder(root=str(self.root), **settings), Clock(), desktop or Desktop()
        host = safebrowse.Host(session=safebrowse.Session(root=self.root), run=run or recorder, fetch=desktop,
                               environ=environ or {}, monotonic=clock.monotonic, sleep=clock.sleep, euid=lambda: euid)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = safebrowse.main(list(argv), host=host)
        return Outcome(code, stdout.getvalue(), stderr.getvalue(), recorder, clock, desktop)

    def launch(self, *args, **settings):
        return self.invoke('run', *args, **settings)

    def assertSessionUntouched(self, outcome):
        """No build, start, teardown, restart or recreation of any kind."""
        used = {call[2] for call in outcome.calls if call[:2] == COMPOSE}
        self.assertLessEqual(used, {'version', 'logs'})
        self.assertLessEqual({call[1] for call in outcome.calls if call[0] == 'docker'},
                             {'info', 'version', 'network', 'compose', 'inspect'})
        self.assertNotIn(['network.py', 'select'], [call[:2] for call in outcome.calls])
        self.assertEqual(sorted(p.name for p in (self.root / '.runtime').glob('vpn/*')) if (self.root / '.runtime').exists()
                         else [], getattr(self, 'stored', []))

    def assertNotDiscovered(self, outcome):
        """The launcher stopped before it even looked for an existing session."""
        self.assertEqual([call for call in outcome.calls if call[:2] == ['docker', 'inspect']], [])
        self.assertEqual([call for call in outcome.calls if call[:2] == COMPOSE and call[2] != 'version'], [])

    def others(self, outcome):
        """Every call except the read-only discovery of session containers."""
        return [call for call in outcome.calls if call[:-1] != discovery('')[:-1]]


class LauncherTests(LauncherCase):
    def test_existing_session_requires_explicit_choice(self):
        outcome = self.launch(existing=True)
        self.assertEqual(outcome.code, 1)
        self.assertIn('Use --resume', outcome.stderr)
        self.assertSessionUntouched(outcome)

    def test_resume_does_not_rebuild_restart_or_discard(self):
        outcome = self.launch('--resume', existing=True)
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertSessionUntouched(outcome)
        self.assertIn(['network.py', 'current'], outcome.calls)
        self.assertIn(['verify.py', '--wait-browser'], outcome.calls)

    def test_fresh_builds_before_destroying_and_starting(self):
        outcome = self.launch('--fresh', existing=True)
        self.assertEqual(outcome.code, 0, outcome.stderr)
        build, down, up = [next(i for i, call in enumerate(outcome.calls) if call[:3] == COMPOSE + [action])
                           for action in ('build', 'down', 'up')]
        self.assertLess(build, down)
        self.assertLess(down, up)

    def test_build_failure_preserves_session(self):
        outcome = self.launch('--fresh', existing=True, build_exit=1)
        self.assertEqual(outcome.code, 1)
        self.assertIn('existing session was not discarded', outcome.stderr)
        self.assertNotIn(DOWN, outcome.calls)
        self.assertEqual(outcome.recorder.compose('up'), [])

    def test_overlapping_pool_retries_with_another_subnet(self):
        outcome = self.launch(overlaps=1)
        self.assertEqual(outcome.code, 0, outcome.stderr)
        selections = [call for call in outcome.calls if call[:2] == ['network.py', 'select']]
        self.assertEqual(selections, [['network.py', 'select'], ['network.py', 'select', '--skip', '172.31.0.0/24']])
        self.assertEqual(len(outcome.recorder.compose('up')), 2)
        self.assertIn('trying another subnet', outcome.stdout)
        attempts = [env['SANDBOX_SUBNET'] for call, env in zip(outcome.calls, outcome.recorder.envs)
                    if call == COMPOSE + ['up', '-d']]
        self.assertEqual(attempts, ['172.31.0.0/24', '172.31.1.0/24'])

    def test_pool_collision_match_is_case_insensitive(self):
        for text in ('INVALID POOL REQUEST\n', 'Error: Pool Overlaps with other one\n'):
            with self.subTest(text=text):
                outcome = self.launch(overlaps=1, overlap_text=text)
                self.assertEqual(outcome.code, 0, outcome.stderr)
                self.assertEqual(len(outcome.recorder.compose('up')), 2)

    def test_subnet_retries_stop_after_three_attempts(self):
        outcome = self.launch(overlaps=3)
        self.assertEqual(outcome.code, 1)
        selections = [call for call in outcome.calls if call[:2] == ['network.py', 'select']]
        self.assertEqual(len(selections), 3)
        self.assertEqual(selections[2][2:], ['--skip', '172.31.0.0/24', '--skip', '172.31.1.0/24'])
        self.assertEqual(len(outcome.recorder.compose('up')), 3)
        self.assertIn('containers failed to start', outcome.stderr)
        self.assertEqual(outcome.calls[-1], COMPOSE + ['logs', '--tail', '40'])
        self.assertEqual(outcome.desktop.requests, [])

    def test_other_start_failures_are_not_retried(self):
        outcome = self.launch(up_exit=1, up_text='Error: port is already allocated\n')
        self.assertEqual(outcome.code, 1)
        self.assertEqual(len(outcome.recorder.compose('up')), 1)
        self.assertIn('port is already allocated', outcome.stdout)
        # The failed containers stay for diagnosis: nothing is torn down after the attempt.
        self.assertLess(outcome.calls.index(DOWN), outcome.calls.index(COMPOSE + ['up', '-d']))
        self.assertEqual(outcome.calls.count(DOWN), 1)

    def test_firefox_startup_race_is_retried(self):
        outcome = self.launch(init_failures=1)
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual(outcome.calls.count(['open_url.py', '--initialize']), 2)
        self.assertEqual(outcome.clock.now, 2)

    def test_firefox_initialization_gives_up_after_60_seconds(self):
        outcome = self.launch('--url', 'https://example.com/', init_failures=10 ** 6)
        self.assertEqual(outcome.code, 1)
        self.assertIn('Firefox could not initialize', outcome.stderr)
        self.assertEqual(outcome.calls.count(['open_url.py', '--initialize']), 30)
        self.assertEqual(outcome.clock.now, 60)
        self.assertNotIn(['verify.py', '--wait-browser'], outcome.calls)
        self.assertNotIn(['open_url.py', 'https://example.com/'], outcome.calls)
        self.assertEqual(outcome.calls.count(DOWN), 1)  # only the pre-start cleanup

    def test_desktop_readiness_times_out_after_180_seconds(self):
        for desktop in (Desktop(anonymous=500), Desktop(authenticated=401), Desktop(anonymous=ConnectionRefusedError())):
            with self.subTest(anonymous=desktop.anonymous, authenticated=desktop.authenticated):
                outcome = self.launch('--url', 'https://example.com/', desktop=desktop)
                self.assertEqual(outcome.code, 1)
                self.assertIn('not ready in time', outcome.stderr)
                self.assertEqual(outcome.clock.now, 180)
                self.assertEqual(len([r for r in desktop.requests if r[1] is None]), 90)  # every 2 seconds
                self.assertEqual(outcome.calls[-1], COMPOSE + ['logs', '--tail', '40'])
                self.assertFalse(any(call[0] in ('open_url.py', 'verify.py') for call in outcome.calls))
                self.assertEqual(outcome.calls.count(DOWN), 1)  # containers remain for diagnosis

    def test_target_is_opened_only_after_successful_verification(self):
        url = 'https://example.com/?x=$(id);&y=1'
        for code in (0, 1, 2):
            with self.subTest(code=code):
                outcome = self.launch('--url', url, verify_exit=code)
                self.assertEqual(outcome.code, code, outcome.stderr)
                navigation = ['open_url.py', url]
                verification = outcome.calls.index(['verify.py', '--wait-browser'])
                self.assertLess(outcome.calls.index(['open_url.py', '--initialize']), verification)
                if code == 0:
                    self.assertLess(verification, outcome.calls.index(navigation))
                    self.assertIn('automated checks passed.', outcome.stdout)
                else:
                    self.assertNotIn(navigation, outcome.calls)
                    self.assertNotIn('automated checks passed.', outcome.stdout)
                    self.assertEqual(outcome.calls.count(DOWN), 1)  # containers remain for diagnosis

    def test_verification_failure_and_inconclusive_are_distinguished(self):
        self.assertIn('verification failed', self.launch(verify_exit=1).stderr)
        self.assertIn('Verification incomplete', self.launch(verify_exit=2).stderr)
        self.assertEqual(self.launch(verify_exit=7).code, 1)

    def test_navigation_failure_is_reported_after_passing_checks(self):
        outcome = self.launch('--url', 'https://example.com/', open_exit=1)
        self.assertEqual(outcome.code, 1)
        self.assertIn('could not open the requested URL', outcome.stderr)

    def test_url_with_shell_characters_stays_one_argument(self):
        url = 'https://example.com/?x=$(id);&quote="hello"&backtick=`id`&a=\'b\'|c>d'
        outcome = self.launch('--url', url)
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual(outcome.calls[-1], ['open_url.py', url])
        self.assertEqual(sum(url in arg for call in outcome.calls for arg in call), 1)

    def test_bad_arguments_and_url_do_not_mutate_session(self):
        ok = 'https://example.com/'
        for args in (('--fresh', '--resume'), ('--resume', '--fresh'), ('--fresh', '--fresh'), ('--url',),
                     ('--url', ''), ('--url', ok, '--url', ok), ('--url', 'file:///etc/passwd'),
                     ('--url', 'https://user:pass@example.com/'), ('--unknown',), ('--fre',), ('--res',),
                     ('--url=' + ok,), ('-f',), (ok,), ('--fresh', 'extra')):
            with self.subTest(args=args):
                outcome = self.launch(*args, existing=True)
                self.assertEqual(outcome.code, 1)  # not argparse's 2, which means "inconclusive" here
                self.assertEqual(outcome.calls, [])
                self.assertEqual(outcome.desktop.requests, [])

    def test_resume_requires_existing_session(self):
        outcome = self.launch('--resume')
        self.assertEqual(outcome.code, 1)
        self.assertIn('no session exists', outcome.stderr)
        self.assertSessionUntouched(outcome)

    def test_resume_rejects_incomplete_or_stopped_sessions(self):
        for containers, message in (({'browser': True, 'ui': True}, 'session is incomplete'),
                                    ({'browser': True, 'gateway': False, 'ui': True}, 'session is not running'),
                                    ({'browser': True, 'gateway': True}, 'session is incomplete')):
            with self.subTest(containers=containers):
                outcome = self.launch('--resume', '--url', 'https://example.com/', containers=containers)
                self.assertEqual(outcome.code, 1)
                self.assertIn(message, outcome.stderr)
                self.assertSessionUntouched(outcome)
                self.assertEqual(outcome.desktop.requests, [])
                self.assertFalse(any(call[0] in ('open_url.py', 'verify.py') for call in outcome.calls))

    def test_resume_requires_valid_runtime_network_state(self):
        outcome = self.launch('--resume', existing=True, state=False)
        self.assertEqual(outcome.code, 1)
        self.assertIn('could not prepare the isolated sandbox network', outcome.stderr)
        self.assertSessionUntouched(outcome)
        self.assertFalse(any('{{.State.Running}}' in call for call in outcome.calls))

    def test_resume_requires_original_credentials(self):
        (self.root / '.env').unlink()
        outcome = self.launch('--resume', existing=True)
        self.assertEqual(outcome.code, 1)
        self.assertIn('cannot resume without the original .env', outcome.stderr)
        self.assertFalse((self.root / '.env').exists())
        self.assertNotDiscovered(outcome)

    def test_fresh_uses_saved_network_for_build_and_teardown(self):
        self.runtime_state()
        outcome = self.launch('--fresh', existing=True)
        self.assertEqual(outcome.code, 0, outcome.stderr)
        for call in (COMPOSE + ['build'], DOWN):
            self.assertEqual(outcome.recorder.env_of(call)['SANDBOX_SUBNET'], '172.31.9.0/24')
            self.assertEqual(outcome.recorder.env_of(call)['SQUID_CONFIG_PATH'], str(self.root / '.runtime/squid.conf'))
        self.assertEqual(outcome.recorder.env_of(COMPOSE + ['up', '-d'])['SANDBOX_SUBNET'], '172.31.0.0/24')

    def test_fresh_recovers_from_missing_or_damaged_runtime_state(self):
        for damaged in (False, True):
            with self.subTest(damaged=damaged):
                if damaged:
                    self.runtime_state()
                outcome = self.launch('--fresh', existing=True, state=False)
                self.assertEqual(outcome.code, 0, outcome.stderr)
                # Compose's own fallback configuration applies until a new subnet is selected.
                for call in (COMPOSE + ['build'], DOWN):
                    self.assertNotIn('SANDBOX_SUBNET', outcome.recorder.env_of(call))
                    self.assertNotIn('SQUID_CONFIG_PATH', outcome.recorder.env_of(call))
                self.assertEqual(outcome.recorder.env_of(COMPOSE + ['up', '-d'])['SANDBOX_SUBNET'], '172.31.0.0/24')

    def test_launcher_owns_network_configuration(self):
        outcome = self.launch(environ={'SANDBOX_SUBNET': '10.0.0.0/8', 'SQUID_CONFIG_PATH': '/tmp/other.conf', 'KEEP': '1'})
        self.assertEqual(outcome.code, 0, outcome.stderr)
        for env in outcome.recorder.envs:
            self.assertNotEqual(env.get('SANDBOX_SUBNET'), '10.0.0.0/8')
            self.assertNotEqual(env.get('SQUID_CONFIG_PATH'), '/tmp/other.conf')
            self.assertEqual(env['KEEP'], '1')
        up = outcome.recorder.env_of(COMPOSE + ['up', '-d'])
        self.assertEqual((up['SANDBOX_SUBNET'], up['SQUID_CONFIG_PATH']),
                         ('172.31.0.0/24', str(self.root / '.runtime/squid.conf')))

    def test_every_command_runs_from_the_repository_root(self):
        outcome = self.launch('--fresh', '--url', 'https://example.com/', existing=True)
        self.assertEqual(set(outcome.recorder.cwds), {str(self.root)})

    def test_engine_and_compose_requirements(self):
        for settings, message in (({'engine': '27.5.1'}, 'Docker Engine 28+'), ({'engine': 'unknown'}, 'Docker Engine 28+'),
                                  ({'engine': ''}, 'Docker Engine 28+'), ({'daemon_exit': 1}, "daemon isn't answering")):
            with self.subTest(settings=settings):
                outcome = self.launch('--fresh', existing=True, **settings)
                self.assertEqual(outcome.code, 1)
                self.assertIn(message, outcome.stderr)
                self.assertEqual([call for call in outcome.calls if call[:2] == COMPOSE and call[2] != 'version'], [])

    def test_missing_docker_is_reported_without_a_traceback(self):
        def missing(args, **options):
            raise FileNotFoundError(args[0])
        outcome = self.launch(run=missing)
        self.assertEqual(outcome.code, 1)
        self.assertIn('docker is required', outcome.stderr)

    def test_existing_bridge_is_migrated_only_by_fresh(self):
        for args in ((), ('--resume',)):
            with self.subTest(args=args):
                outcome = self.launch(*args, existing=True, bridge='')
                self.assertEqual(outcome.code, 1)
                self.assertIn('needs migration', outcome.stderr)
                self.assertSessionUntouched(outcome)
        self.assertEqual(self.launch('--fresh', existing=True, bridge='').code, 0)
        self.assertEqual(self.launch(bridge=None).code, 0)  # no bridge yet

    def test_low_memory_is_a_warning_not_a_failure(self):
        outcome = self.launch(memory='4000000000')
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertIn('Docker has 3 GiB of RAM', outcome.stdout)
        self.assertNotIn('WARNING', self.launch(memory='not-a-number').stdout)

    def test_help_does_not_contact_docker(self):
        for argv in (('run', '--help'), ('run', '-h'), ('--help',), ('stop', '--help'), ('logs', '--help')):
            with self.subTest(argv=argv):
                outcome = self.invoke(*argv)
                self.assertEqual(outcome.code, 0)
                self.assertIn('Usage:', outcome.stdout)
                self.assertEqual(outcome.calls, [])

    def test_unknown_or_missing_command_runs_nothing(self):
        for argv in ((), ('destroy',), ('--fresh',)):
            with self.subTest(argv=argv):
                outcome = self.invoke(*argv)
                self.assertEqual(outcome.code, 1)
                self.assertEqual(outcome.calls, [])


class PreflightTests(LauncherCase):
    """Launches SafeBrowse cannot vouch for are refused before anything is created or changed."""
    MODES = ((), ('--fresh',), ('--resume',), ('--fresh', '--url', 'https://example.com/'))

    def setUp(self):
        super().setUp()
        (self.root / '.env').unlink()  # so that creating credentials would be visible

    def assertNothingChanged(self, outcome):
        self.assertEqual(outcome.code, 1)
        self.assertFalse((self.root / '.env').exists())
        self.assertFalse((self.root / '.runtime').exists())
        self.assertEqual(outcome.desktop.requests, [])
        self.assertEqual([call for call in outcome.calls if call[:2] == COMPOSE and call[2] != 'version'], [])
        self.assertFalse([call for call in outcome.calls if call[0].endswith('.py')])
        self.assertSessionUntouched(outcome)

    def test_root_or_sudo_launch_is_refused_before_contacting_docker(self):
        for args in self.MODES:
            with self.subTest(args=args):
                outcome = self.launch(*args, euid=0, existing=True)
                self.assertNothingChanged(outcome)
                self.assertEqual(outcome.calls, [])
                self.assertIn('as root or with sudo', outcome.stderr)
                self.assertIn('nothing was changed', outcome.stderr)

    def test_root_pin_is_refused_but_its_help_still_works(self):
        for args in ((), ('--refresh',)):
            with self.subTest(args=args):
                outcome = self.invoke('pin', *args, euid=0)
                self.assertEqual(outcome.code, 1)
                self.assertEqual(outcome.calls, [])
                self.assertIn("'pin' as root", outcome.stderr)
        for flag in ('--help', '-h'):
            self.assertEqual(self.invoke('pin', flag, euid=0).calls, [['pin.py', flag]])
        self.assertEqual(self.invoke('pin', '--refresh').calls, [['pin.py', '--refresh']])

    def test_help_never_checks_privileges_or_docker(self):
        for argv in (('run', '--help'), ('--help',), ('stop', '--help'), ('logs', '--help')):
            with self.subTest(argv=argv):
                outcome = self.invoke(*argv, euid=0, security='["name=rootless"]')
                self.assertEqual((outcome.code, outcome.calls), (0, []))

    def test_rootless_daemon_is_refused_from_its_own_security_metadata(self):
        for security in ('["name=seccomp,profile=builtin","name=rootless","name=cgroupns"]', '["name=rootless"]'):
            for args in self.MODES:
                with self.subTest(security=security, args=args):
                    outcome = self.launch(*args, security=security, existing=True)
                    self.assertNothingChanged(outcome)
                    self.assertIn('rootless mode', outcome.stderr)
                    self.assertIn('only been validated with a rootful Docker Engine', outcome.stderr)
                    self.assertIn("not about rootless Docker's security", outcome.stderr)
                    self.assertNotIn('less secure', outcome.stderr)

    def test_rootless_is_not_guessed_from_paths_or_environment(self):
        environ = {'DOCKER_HOST': 'unix:///run/user/1000/docker.sock', 'XDG_RUNTIME_DIR': '/run/user/1000',
                   'DOCKER_CONTEXT': 'rootless'}
        outcome = self.launch(environ=environ)
        self.assertEqual(outcome.code, 0, outcome.stderr)
        # A value that merely mentions the word is not the daemon saying it is rootless.
        self.assertEqual(self.launch(security='["name=seccomp,profile=/etc/docker/rootless.json"]').code, 0)

    def test_daemon_without_seccomp_is_refused(self):
        for security in ('[]', '["name=cgroupns"]', '["name=apparmor","name=cgroupns"]'):
            with self.subTest(security=security):
                outcome = self.launch('--fresh', security=security, existing=True)
                self.assertNothingChanged(outcome)
                self.assertIn('no seccomp support', outcome.stderr)

    def test_unreadable_daemon_metadata_fails_safely_without_echoing_it(self):
        marker = 'RAW-DAEMON-OUTPUT'
        cases = (({'security_exit': 1, 'security': marker}), {'security': ''}, {'security': 'null'}, {'security': marker},
                 {'security': '{"name": "%s"}' % marker}, {'security': '["name=seccomp", 7]'},
                 {'security': '"name=seccomp,%s"' % marker})
        for settings in cases:
            with self.subTest(settings=settings):
                outcome = self.launch('--fresh', existing=True, environ={'SECRET_VALUE': 'ENVIRONMENT-SECRET'}, **settings)
                self.assertNothingChanged(outcome)
                self.assertIn("could not read the Docker daemon's security options", outcome.stderr)
                for leaked in (marker, 'ENVIRONMENT-SECRET'):
                    self.assertNotIn(leaked, outcome.stdout + outcome.stderr)

    def test_supported_daemons_launch(self):
        for security in ('["name=seccomp,profile=builtin","name=cgroupns"]',
                         '["name=apparmor","name=seccomp,profile=builtin","name=cgroupns"]',
                         '["name=seccomp,profile=unconfined"]'):  # the browser brings its own profile
            with self.subTest(security=security):
                outcome = self.launch(security=security)
                self.assertEqual(outcome.code, 0, outcome.stderr)
                self.assertTrue((self.root / '.env').exists())
                (self.root / '.env').unlink()
                shutil.rmtree(self.root / '.runtime', ignore_errors=True)

    def test_daemon_checks_precede_every_mutation(self):
        outcome = self.launch('--fresh', existing=True)
        self.assertEqual(outcome.code, 0, outcome.stderr)
        security = outcome.calls.index(['docker', 'info', '--format', '{{json .SecurityOptions}}'])
        for call in (COMPOSE + ['build'], DOWN, ['network.py', 'select'], COMPOSE + ['up', '-d']):
            self.assertLess(security, outcome.calls.index(call))
        self.assertFalse(any('sudo' in call or 'usermod' in call or 'chown' in call for call in outcome.calls))

    def test_cleanup_and_diagnosis_stay_available(self):
        for euid, security in ((0, None), (1000, '["name=rootless"]'), (1000, 'unreadable'), (0, '["name=rootless"]')):
            settings = {} if security is None else {'security': security}
            with self.subTest(euid=euid, security=security):
                self.assertEqual(self.others(self.invoke('stop', euid=euid, **settings)), [DOWN])
                self.assertEqual(self.invoke('logs', euid=euid, **settings).code, 0)
                self.assertEqual(self.invoke('verify', euid=euid, **settings).calls, [['verify.py']])
        self.assertFalse((self.root / '.env').exists())

    def test_platform_without_user_ids_is_not_treated_as_root(self):
        host = safebrowse.Host(session=safebrowse.Session(root=self.root), run=Recorder(), environ={})
        with patch.object(safebrowse.os, 'geteuid', create=True, return_value=0):
            self.assertEqual(safebrowse.Host(session=host.session, run=Recorder(), environ={}).euid(), 0)
        self.assertIsNone(safebrowse.Host(euid=lambda: None, run=Recorder(), environ={}).euid())
        self.assertEqual(self.launch(euid=None).code, 0)

    def test_old_python_is_refused_with_an_actionable_message(self):
        for version in ((3, 9, 18, 'final', 0), (3, 11, 15, 'final', 0)):
            with self.subTest(version=version), patch.object(safebrowse.sys, 'version_info', version):
                for argv in (('run', '--fresh'), ('stop',), ('pin',), ('--help',)):
                    outcome = self.invoke(*argv)
                    self.assertEqual((outcome.code, outcome.calls), (1, []))
                    self.assertIn('Python 3.12 or newer is required; this is Python %d.%d' % version[:2], outcome.stderr)
        self.assertFalse((self.root / '.env').exists())
        for version in ((3, 12, 0, 'final', 0), (3, 14, 5, 'final', 0), (4, 0, 0, 'final', 0)):
            with self.subTest(version=version), patch.object(safebrowse.sys, 'version_info', version):
                self.assertEqual(self.invoke('--help').code, 0)


class LineEndingTests(LauncherCase):
    """Squid reads its configuration and blocklist byte for byte; CRLF there is refused, not guessed at."""

    def setUp(self):
        super().setUp()
        (self.root / '.env').unlink()

    def test_carriage_returns_in_gateway_inputs_stop_the_launch_before_any_change(self):
        for name in safebrowse.SECURITY_INPUTS:
            original = (self.root / name).read_bytes()
            for label, damaged in (('crlf', original.replace(b'\n', b'\r\n')), ('one stray', original + b'.example.net\r\n'),
                                   ('bare cr', original + b'.example.org\r')):
                for args in ((), ('--fresh',), ('--resume',)):
                    with self.subTest(name=name, damage=label, args=args):
                        (self.root / name).write_bytes(damaged)
                        outcome = self.launch(*args, existing=True)
                        self.assertEqual((outcome.code, outcome.calls), (1, []))
                        self.assertIn(name + ' contains carriage returns', outcome.stderr)
                        self.assertIn('Convert the file to LF', outcome.stderr)
                        self.assertFalse((self.root / '.env').exists() or (self.root / '.runtime').exists())
                        self.assertEqual((self.root / name).read_bytes(), damaged)  # reported, never rewritten
            (self.root / name).write_bytes(original)

    def test_missing_gateway_input_stops_the_launch(self):
        for name in safebrowse.SECURITY_INPUTS:
            with self.subTest(name=name):
                saved = (self.root / name).read_bytes()
                (self.root / name).unlink()
                outcome = self.launch('--fresh', existing=True)
                self.assertEqual((outcome.code, outcome.calls), (1, []))
                self.assertIn('could not read ' + name, outcome.stderr)
                (self.root / name).write_bytes(saved)

    def test_repository_inputs_are_accepted(self):
        for name in safebrowse.SECURITY_INPUTS:
            self.assertNotIn(b'\r', (ROOT / name).read_bytes())
        self.assertEqual(self.launch().code, 0)

    def test_teardown_and_diagnosis_do_not_depend_on_line_endings(self):
        (self.root / 'gateway/blocklist.txt').write_bytes(b'.example.net\r\n')
        self.assertEqual(self.others(self.invoke('stop')), [DOWN])
        self.assertEqual(self.invoke('logs').code, 0)

    def test_credentials_file_may_still_use_crlf(self):
        (self.root / '.env').write_bytes(CREDENTIALS.replace('\n', '\r\n').encode())
        outcome = self.launch()
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual(outcome.recorder.env_of(COMPOSE + ['up', '-d'])['SANDBOX_PASSWORD'], 'test-password')


@unittest.skipUnless(shutil.which('git') and (ROOT / '.git').exists(), 'needs Git and a Git checkout')
class WindowsCheckoutTests(unittest.TestCase):
    """A clone made with Windows-style Git settings (core.autocrlf=true, core.eol=crlf)."""
    COVERED = ('*.sh', 'scripts/*.py', 'docker-compose.yml', 'Dockerfile', '.dockerignore', 'gateway/*', 'policies/*.json',
               'security/*.json', 'security/upstream/*')

    @classmethod
    def setUpClass(cls):
        cls.temp = Path(tempfile.mkdtemp(prefix='safebrowse-checkout-'))
        cls.addClassCleanup(shutil.rmtree, cls.temp, True)
        # Isolated from the user's and the system's Git configuration; the real checkout is only read.
        cls.env = {'PATH': os.environ['PATH'], 'HOME': str(cls.temp), 'GIT_CONFIG_GLOBAL': os.devnull,
                   'GIT_CONFIG_SYSTEM': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0',
                   'GIT_AUTHOR_NAME': 'test', 'GIT_AUTHOR_EMAIL': 'test@example.invalid',
                   'GIT_COMMITTER_NAME': 'test', 'GIT_COMMITTER_EMAIL': 'test@example.invalid'}
        listing = cls.git(ROOT, 'ls-files', '--cached', '--others', '--exclude-standard', '-z').stdout
        # Ignored files such as .env and .runtime/ are not in this listing and are never copied.
        cls.files = [name for name in listing.split('\0') if name and (ROOT / name).is_file() and '.DS_Store' not in name]

    @classmethod
    def git(cls, cwd, *args):
        return subprocess.run(['git', *args], cwd=str(cwd), env=cls.env, capture_output=True, text=True, check=True)

    def checkout(self, label, attributes):
        origin, work = self.temp / (label + '-origin'), self.temp / (label + '-work')
        for name in self.files:
            if name == '.gitattributes' and not attributes:
                continue
            (origin / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, origin / name)
        self.git(origin, 'init', '--quiet')
        self.git(origin, 'add', '--all')
        self.git(origin, 'commit', '--quiet', '--message', 'fixture')
        self.git(self.temp, 'clone', '--quiet', '--config', 'core.autocrlf=true', '--config', 'core.eol=crlf',
                 str(origin), str(work))
        return work

    def launch(self, root):
        recorder = Recorder()
        host = safebrowse.Host(session=safebrowse.Session(root=root), run=recorder, fetch=Desktop(), environ={},
                               monotonic=Clock().monotonic, sleep=lambda seconds: None, euid=lambda: 1000)
        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
            code = safebrowse.main(['run', '--resume'], host=host)
        return code, recorder.calls, stderr.getvalue()

    def test_attributes_keep_every_security_input_lf(self):
        self.assertIn('.gitattributes', self.files)
        work = self.checkout('attributes', True)
        self.assertEqual(self.git(work, 'config', 'core.autocrlf').stdout.strip(), 'true')
        covered = sorted({path for pattern in self.COVERED for path in work.glob(pattern) if path.is_file()})
        self.assertGreaterEqual(len(covered), 18)
        for name in safebrowse.SECURITY_INPUTS + ('security/seccomp-firefox.json', 'run.sh', 'scripts/safebrowse.py'):
            self.assertIn(work / name, covered)
        for path in covered:
            with self.subTest(path=str(path.relative_to(work))):
                self.assertNotIn(b'\r', path.read_bytes())
                self.assertEqual(path.read_bytes(), (ROOT / path.relative_to(work)).read_bytes())
        safebrowse.check_security_inputs(safebrowse.Host(session=safebrowse.Session(root=work), run=Recorder(), environ={}))
        self.assertEqual(subprocess.run(['bash', '-n', str(work / 'run.sh')], capture_output=True).returncode, 0)
        self.assertEqual(self.git(work, 'status', '--porcelain').stdout, '')

    def test_same_settings_without_attributes_give_crlf_and_the_launcher_refuses_it(self):
        work = self.checkout('plain', False)
        self.assertIn(b'\r\n', (work / 'gateway/blocklist.txt').read_bytes())  # the simulation is real
        code, calls, stderr = self.launch(work)
        self.assertEqual((code, calls), (1, []))
        self.assertIn('gateway/squid.conf contains carriage returns', stderr)
        self.assertFalse((work / '.env').exists() or (work / '.runtime').exists())


class CredentialTests(LauncherCase):
    def rejected(self, text):
        (self.root / '.env').write_text(text)
        outcome = self.launch(existing=True)
        self.assertEqual(outcome.code, 1)
        self.assertIn('.env must contain unquoted', outcome.stderr)
        self.assertNotDiscovered(outcome)
        return outcome

    def test_env_is_data_not_shell_code(self):
        marker = self.root / 'executed'
        outcome = self.rejected(f'SANDBOX_USER=sandbox\nSANDBOX_PASSWORD=$(touch {marker})\n')
        self.assertFalse(marker.exists())
        self.assertNotIn('touch', outcome.stdout + outcome.stderr)

    def test_credentials_override_inherited_values(self):
        outcome = self.launch(environ={'SANDBOX_USER': 'wrong', 'SANDBOX_PASSWORD': 'wrong'})
        self.assertEqual(outcome.code, 0, outcome.stderr)
        for action in ('build', 'up'):
            env = outcome.recorder.env_of(outcome.recorder.compose(action)[0])
            self.assertEqual((env['SANDBOX_USER'], env['SANDBOX_PASSWORD']), ('test', 'test-password'))
        expected = 'Basic ' + base64.b64encode(b'test:test-password').decode()
        self.assertEqual(outcome.desktop.requests, [(3011, None), (3011, expected)])

    def test_duplicate_credentials_are_rejected(self):
        self.rejected('SANDBOX_USER=sandbox\nSANDBOX_PASSWORD=first\nSANDBOX_PASSWORD=second\n')
        self.rejected('SANDBOX_USER=sandbox\nSANDBOX_USER=sandbox\nSANDBOX_PASSWORD=first\n')

    def test_accepted_credential_formats(self):
        for text, expected in (
                ('SANDBOX_USER=sandbox\nSANDBOX_PASSWORD=abc\n', ('sandbox', 'abc')),
                ('SANDBOX_PASSWORD=abc\nSANDBOX_USER=sandbox', ('sandbox', 'abc')),           # no final newline
                ('SANDBOX_USER=sandbox\r\nSANDBOX_PASSWORD=abc\r\n', ('sandbox', 'abc')),     # CRLF
                ('# login\n\nSANDBOX_USER=a.b_c-1\n\r\n#x=y\nSANDBOX_PASSWORD=A1_+./:@%-\n\n', ('a.b_c-1', 'A1_+./:@%-')),
                ('SANDBOX_USER=u\nSANDBOX_PASSWORD=a=b\n', None)):                              # "=" is not allowed
            with self.subTest(text=text):
                if expected is None:
                    with self.assertRaises(ValueError):
                        safebrowse.parse_credentials(text)
                else:
                    self.assertEqual(safebrowse.parse_credentials(text), expected)

    def test_rejected_credential_formats(self):
        user, password = 'SANDBOX_USER=sandbox\n', 'SANDBOX_PASSWORD=abc\n'
        for text in ('', user, password, user + 'SANDBOX_PASSWORD=\n', 'SANDBOX_USER=\n' + password,
                     user + 'SANDBOX_PASSWORD="abc"\n', user + "SANDBOX_PASSWORD='abc'\n",
                     user + 'SANDBOX_PASSWORD=${HOME}\n', user + 'SANDBOX_PASSWORD=`id`\n',
                     user + 'SANDBOX_PASSWORD=a b\n', user + 'SANDBOX_PASSWORD=abc \n', user + 'SANDBOX_PASSWORD= abc\n',
                     user + 'SANDBOX_PASSWORD=abc\t\n', user + ' SANDBOX_PASSWORD=abc\n', user + 'SANDBOX_PASSWORD =abc\n',
                     user + 'export SANDBOX_PASSWORD=abc\n', user + password + 'OTHER=1\n', user + password + 'junk\n',
                     user + password + ' # indented comment\n', user + password + ' \n',
                     user + 'SANDBOX_PASSWORD=abc\r\r\n', 'SANDBOX_USER=sandbox\rSANDBOX_PASSWORD=abc\n',
                     'SANDBOX_USER=sandbox\x0bSANDBOX_PASSWORD=abc\n', 'SANDBOX_USER=sandbox\x0cSANDBOX_PASSWORD=abc\n',
                     'SANDBOX_USER=sandbox SANDBOX_PASSWORD=abc\n', user + 'SANDBOX_PASSWORD=café\n',
                     user + 'SANDBOX_PASSWORD=abc\x00\n', 'sandbox_user=sandbox\n' + password,
                     'SANDBOX_USER=a/b\n' + password, user + 'SANDBOX_PASSWORD=a;b\n', user + 'SANDBOX_PASSWORD=a&b\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                safebrowse.parse_credentials(text)

    def test_parse_errors_never_echo_the_file(self):
        outcome = self.rejected('SANDBOX_USER=sandbox\nSANDBOX_PASSWORD=secret value\n')
        self.assertNotIn('secret', outcome.stdout + outcome.stderr)
        (self.root / '.env').write_bytes(b'SANDBOX_USER=sandbox\nSANDBOX_PASSWORD=\xff\xfe\n')
        self.assertEqual(self.launch().code, 1)

    def test_new_credentials_are_private_random_and_usable(self):
        (self.root / '.env').unlink()
        previous = os.umask(0)
        try:
            outcome = self.launch()
        finally:
            os.umask(previous)
        self.assertEqual(outcome.code, 0, outcome.stderr)
        path = self.root / '.env'
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        user, password = safebrowse.parse_credentials(path.read_text())
        self.assertEqual(user, 'sandbox')
        self.assertRegex(password, r'\A[0-9a-f]{32}\Z')
        self.assertEqual(outcome.recorder.env_of(COMPOSE + ['up', '-d'])['SANDBOX_PASSWORD'], password)
        other = self.root / 'other.env'
        safebrowse.create_credentials(other)
        self.assertNotEqual(safebrowse.parse_credentials(other.read_text())[1], password)

    def test_existing_credentials_are_preserved_and_restricted(self):
        path = self.root / '.env'
        path.chmod(0o644)
        self.assertEqual(self.launch().code, 0)
        self.assertEqual(path.read_text(), CREDENTIALS)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            safebrowse.create_credentials(path)
        self.assertEqual(path.read_text(), CREDENTIALS)

    def test_password_is_shown_only_in_the_successful_login_banner(self):
        outcome = self.launch('--url', 'https://example.com/')
        self.assertIn('password  test-password', outcome.stdout)
        self.assertNotIn('test-password', outcome.stderr)
        self.assertFalse(any('test-password' in arg for call in outcome.calls for arg in call))
        for settings in ({'verify_exit': 1}, {'verify_exit': 2}, {'up_exit': 1}, {'init_failures': 10 ** 6}):
            with self.subTest(settings=settings):
                failed = self.launch(**settings)
                self.assertNotIn('test-password', failed.stdout + failed.stderr)
                self.assertFalse(any('test-password' in arg for call in failed.calls for arg in call))

    @unittest.skipIf(hasattr(os, 'geteuid') and os.geteuid() == 0, 'root ignores directory permissions')
    def test_credential_creation_failure_stops_before_any_session_change(self):
        (self.root / '.env').unlink()
        self.root.chmod(0o555)
        self.addCleanup(self.root.chmod, 0o755)
        outcome = self.launch()
        self.assertEqual(outcome.code, 1)
        self.assertIn('could not write .env', outcome.stderr)
        self.assertEqual([call for call in outcome.calls if call[:2] == COMPOSE and call[2] != 'version'], [])

    def test_links_and_special_files_are_rejected(self):
        path = self.root / '.env'
        real = self.root / 'real.env'
        real.write_text(CREDENTIALS)
        real.chmod(0o644)

        def replace(make):
            if os.path.lexists(path):
                path.rmdir() if path.is_dir() and not path.is_symlink() else path.unlink()
            make()

        cases = [('symlink', lambda: path.symlink_to(real)), ('dangling symlink', lambda: path.symlink_to(self.root / 'absent')),
                 ('directory', path.mkdir)]
        if hasattr(os, 'mkfifo'):
            cases.append(('fifo', lambda: os.mkfifo(path)))
        for name, make in cases:
            with self.subTest(kind=name):
                replace(make)
                outcome = self.launch()
                self.assertEqual(outcome.code, 1)
                self.assertIn('not a symlink' if 'symlink' in name else '.env must be a regular file.', outcome.stderr)
                self.assertNotDiscovered(outcome)
        self.assertFalse((self.root / 'absent').exists())
        self.assertEqual(stat.S_IMODE(real.stat().st_mode), 0o644)  # the link target was not touched


class ReadinessTests(unittest.TestCase):
    def ready(self, **responses):
        desktop = Desktop(**responses)
        return safebrowse.desktop_ready(desktop, 3011, 'sandbox', 'test'), desktop

    def test_500_does_not_count_as_ready(self):
        self.assertFalse(self.ready(anonymous=500, authenticated=500)[0])

    def test_unauthenticated_200_does_not_count_as_ready(self):
        ready, desktop = self.ready(anonymous=200)
        self.assertFalse(ready)
        self.assertEqual(desktop.requests, [(3011, None)])  # credentials are not offered to an open endpoint

    def test_authenticated_200_counts_as_ready(self):
        ready, desktop = self.ready()
        self.assertTrue(ready)
        self.assertEqual(desktop.requests, [(3011, None), (3011, 'Basic ' + base64.b64encode(b'sandbox:test').decode())])

    def test_wrong_password_does_not_count_as_ready(self):
        self.assertFalse(self.ready(authenticated=401)[0])

    def test_redirects_and_other_statuses_do_not_count_as_ready(self):
        for responses in ({'anonymous': 302}, {'authenticated': 302}, {'authenticated': 204}, {'authenticated': 403},
                          {'anonymous': 403}, {'authenticated': 500}):
            with self.subTest(responses=responses):
                self.assertFalse(self.ready(**responses)[0])

    def test_transport_errors_do_not_count_as_ready(self):
        for error in (ConnectionRefusedError(), socket.timeout(), ssl.SSLError('handshake'),
                      http.client.RemoteDisconnected('closed'), http.client.BadStatusLine('x')):
            for responses in ({'anonymous': error}, {'authenticated': error}):
                with self.subTest(error=type(error).__name__, responses=list(responses)):
                    self.assertFalse(self.ready(**responses)[0])


class Requests(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        server = self.server
        server.requests.append((self.path, self.headers.get('Host'), self.headers.get('Authorization')))
        status = server.statuses[bool(self.headers.get('Authorization') == server.accepted)]
        self.send_response(status)
        if status in (301, 302, 307, 308):
            self.send_header('Location', server.location)
        self.send_header('Content-Length', '0')
        self.end_headers()


class SlowHeaders:
    """A TLS server that answers 401 correctly, but one small header at a time.

    Bytes arrive every `interval` seconds, so no single read ever waits long; the
    complete response head takes `duration` seconds. `outcomes` records, for each
    connection, whether the whole head was sent or the client went away first.
    """

    def __init__(self, tls, interval, duration):
        self.tls, self.interval, self.duration = tls, interval, duration
        self.requests, self.outcomes, self.workers = [], [], []
        self.stopped = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(5)
        self.listener.settimeout(0.05)
        self.port = self.listener.getsockname()[1]
        self.acceptor = threading.Thread(target=self.accept, daemon=True)
        self.acceptor.start()

    def accept(self):
        while not self.stopped.is_set():
            try:
                plain, _ = self.listener.accept()
            except socket.timeout:
                continue
            worker = threading.Thread(target=self.respond, args=(plain,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def respond(self, plain):
        try:
            plain.settimeout(5)
            with self.tls.wrap_socket(plain, server_side=True) as connection:
                request = b''
                while b'\r\n\r\n' not in request:
                    received = connection.recv(4096)
                    if not received:
                        return self.outcomes.append('no request')
                    request += received
                self.requests.append(request)
                connection.sendall(b'HTTP/1.1 401 Unauthorized\r\n')
                finish = time.monotonic() + self.duration
                while time.monotonic() < finish and not self.stopped.is_set():
                    time.sleep(self.interval)
                    connection.sendall(b'X-Slow: 1\r\n')
                connection.sendall(b'Content-Length: 0\r\n\r\n')
                self.outcomes.append('sent everything')
        except OSError:
            self.outcomes.append('client went away')
        finally:
            plain.close()

    def join(self, seconds):
        """Wait for every connection handler; return the ones still running."""
        limit = time.monotonic() + seconds
        for worker in list(self.workers):
            worker.join(max(0, limit - time.monotonic()))
        return [worker for worker in self.workers if worker.is_alive()]

    def close(self):
        self.stopped.set()
        self.acceptor.join(5)
        self.join(5)
        self.listener.close()


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL creates the self-signed test certificate')
class DesktopProbeTests(unittest.TestCase):
    """The real probe against local servers that use a self-signed certificate."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.mkdtemp(prefix='safebrowse-tls-')
        cls.addClassCleanup(shutil.rmtree, cls.directory, True)
        cert, key = os.path.join(cls.directory, 'cert.pem'), os.path.join(cls.directory, 'key.pem')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=SafeBrowse unit test', '-keyout', key, '-out', cert],
                       check=True, capture_output=True)
        cls.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.tls.load_cert_chain(cert, key)

    def server(self, anonymous=401, authenticated=200, location=''):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Requests)
        server.requests, server.statuses, server.location = [], (anonymous, authenticated), location
        server.accepted = 'Basic ' + base64.b64encode(b'sandbox:test-password').decode()
        server.socket = self.tls.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def ready(self, server, password='test-password'):
        return safebrowse.desktop_ready(safebrowse.desktop_status, server.server_address[1], 'sandbox', password)

    def test_self_signed_desktop_requires_then_accepts_credentials(self):
        server = self.server()
        self.assertTrue(self.ready(server))
        host = '127.0.0.1:%d' % server.server_address[1]
        self.assertEqual(server.requests, [('/', host, None), ('/', host, server.accepted)])
        self.assertFalse(self.ready(server, password='wrong'))

    def test_certificate_exception_is_limited_to_the_probe(self):
        server = self.server()
        self.assertTrue(self.ready(server))
        self.assertEqual(ssl.create_default_context().verify_mode, ssl.CERT_REQUIRED)
        strict = http.client.HTTPSConnection('127.0.0.1', server.server_address[1], timeout=3)
        with self.assertRaises(ssl.SSLError):
            strict.request('GET', '/')
        strict.close()

    def test_redirects_are_not_followed_and_never_carry_credentials(self):
        target = self.server(anonymous=200, authenticated=200)
        location = 'https://127.0.0.1:%d/' % target.server_address[1]
        for statuses in ((302, 302), (401, 302), (401, 307), (301, 200)):
            with self.subTest(statuses=statuses):
                server = self.server(*statuses, location=location)
                self.assertFalse(self.ready(server))
        self.assertEqual(target.requests, [])

    def test_proxy_settings_are_ignored(self):
        proxy = socket.socket()
        proxy.bind(('127.0.0.1', 0))
        proxy.listen(5)
        proxy.settimeout(0.2)
        self.addCleanup(proxy.close)
        address = 'http://127.0.0.1:%d' % proxy.getsockname()[1]
        names = ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')
        server = self.server()
        with patch.dict(os.environ, dict.fromkeys(names, address)):
            os.environ.pop('NO_PROXY', None)
            os.environ.pop('no_proxy', None)
            self.assertTrue(self.ready(server))
        with self.assertRaises(socket.timeout):
            proxy.accept()  # nothing ever connected to the proxy
        self.assertEqual(len(server.requests), 2)

    def test_stalled_desktop_is_bounded_by_the_timeout(self):
        stalled = socket.socket()
        stalled.bind(('127.0.0.1', 0))
        stalled.listen(1)
        self.addCleanup(stalled.close)
        port = stalled.getsockname()[1]
        started = time.monotonic()
        with self.assertRaises(OSError):
            safebrowse.desktop_status(port, timeout=0.3)
        self.assertFalse(safebrowse.desktop_ready(lambda p, a=None: safebrowse.desktop_status(p, a, timeout=0.3),
                                                  port, 'sandbox', 'test-password'))
        self.assertLess(time.monotonic() - started, 5)

    def test_slowly_delivered_headers_cannot_outlast_the_total_budget(self):
        # The budget is ten times the gap between bytes, so a limit that applied to each
        # read separately would never fire, and the full response takes eight times the budget.
        budget, tolerance = 0.5, 1.0
        before = set(threading.enumerate())
        server = SlowHeaders(self.tls, interval=0.05, duration=4.0)
        self.addCleanup(server.close)
        gc.collect()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            started = time.monotonic()
            with self.assertRaises(socket.timeout):
                safebrowse.desktop_status(server.port, timeout=budget)
            elapsed = time.monotonic() - started
            self.assertGreaterEqual(elapsed, budget * 0.9)  # it waited for its budget, not for an early error
            self.assertLess(elapsed, budget + tolerance)

            started = time.monotonic()
            self.assertFalse(safebrowse.desktop_ready(lambda port, authorization=None: safebrowse.desktop_status(
                port, authorization, timeout=budget), server.port, 'sandbox', 'test-password'))
            self.assertLess(time.monotonic() - started, budget + tolerance)
            gc.collect()
        self.assertEqual([str(warning.message) for warning in caught if issubclass(warning.category, ResourceWarning)], [])

        # Both probes closed their connections: the server noticed long before it had finished
        # sending, and nothing it or the probe started is still running.
        self.assertEqual(server.join(1.0), [])
        self.assertEqual(server.outcomes, ['client went away'] * 2)
        self.assertEqual(len(server.requests), 2)
        self.assertTrue(all(b'Authorization' not in request for request in server.requests))  # never got past the 401 step
        server.close()
        self.assertFalse(server.acceptor.is_alive())
        self.assertEqual([thread for thread in threading.enumerate() if thread not in before], [])

    def test_headers_in_many_small_pieces_are_accepted_within_the_budget(self):
        server = SlowHeaders(self.tls, interval=0.02, duration=0.2)
        self.addCleanup(server.close)
        self.assertEqual(safebrowse.desktop_status(server.port, timeout=3), 401)
        self.assertEqual(server.join(2.0), [])
        self.assertEqual(server.outcomes, ['sent everything'])

    def test_exhausted_budget_fails_before_connecting(self):
        server = self.server()
        for budget in (0, -1):
            with self.subTest(budget=budget), self.assertRaises(socket.timeout):
                safebrowse.desktop_status(server.server_address[1], timeout=budget)
        self.assertEqual(server.requests, [])

    def test_malformed_responses_are_not_ready(self):
        for reply in (b'', b'not http at all\r\n\r\n', b'HTTP/1.1 abc Unauthorized\r\n\r\n', b'HTTP/1.1 20\r\n\r\n'):
            with self.subTest(reply=reply):
                listener = socket.socket()
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                self.addCleanup(listener.close)

                def answer():
                    plain, _ = listener.accept()
                    plain.settimeout(5)
                    with self.tls.wrap_socket(plain, server_side=True) as connection:
                        while b'\r\n\r\n' not in connection.recv(4096):
                            pass
                        connection.sendall(reply)

                thread = threading.Thread(target=answer, daemon=True)
                thread.start()
                with self.assertRaises((OSError, http.client.HTTPException)):
                    safebrowse.desktop_status(listener.getsockname()[1], timeout=3)
                thread.join(5)
                self.assertFalse(thread.is_alive())

    def test_authorization_cannot_add_header_lines(self):
        server = self.server()
        for value in ('Basic abc\r\nX-Injected: 1', 'Basic abc\nX-Injected: 1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                safebrowse.desktop_status(server.server_address[1], value)
        self.assertEqual(server.requests, [])

    def test_closed_port_is_not_ready(self):
        with socket.socket() as unused:
            unused.bind(('127.0.0.1', 0))
            port = unused.getsockname()[1]
        self.assertFalse(safebrowse.desktop_ready(safebrowse.desktop_status, port, 'sandbox', 'test-password'))


class TeardownTests(LauncherCase):
    def test_teardown_does_not_require_a_credentials_file(self):
        (self.root / '.env').unlink()
        outcome = self.invoke('stop', environ={'SANDBOX_SUBNET': '10.0.0.0/8', 'SQUID_CONFIG_PATH': '/tmp/other.conf'})
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual(self.others(outcome), [DOWN])  # besides read-only discovery, before and after
        env = outcome.recorder.env_of(DOWN)
        self.assertEqual(env['SANDBOX_PASSWORD'], 'unused-for-teardown')
        self.assertNotIn('SANDBOX_SUBNET', env)       # Compose's fallback configuration applies
        self.assertNotIn('SQUID_CONFIG_PATH', env)
        self.assertIn('Sandbox destroyed', outcome.stdout)
        self.assertFalse((self.root / '.env').exists())   # teardown never generates credentials
        self.assertFalse((self.root / '.runtime').exists())

    def test_teardown_survives_damaged_runtime_state(self):
        self.runtime_state()
        outcome = self.invoke('stop', state=False)
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual(self.others(outcome), [['network.py', 'current'], DOWN])
        self.assertNotIn('SANDBOX_SUBNET', outcome.recorder.env_of(DOWN))

    def test_teardown_uses_intact_runtime_state(self):
        self.runtime_state()
        outcome = self.invoke('stop')
        env = outcome.recorder.env_of(DOWN)
        self.assertEqual((env['SANDBOX_SUBNET'], env['SQUID_CONFIG_PATH']),
                         ('172.31.9.0/24', str(self.root / '.runtime/squid.conf')))

    def test_teardown_never_uses_the_real_password_or_starts_anything(self):
        outcome = self.invoke('stop', environ={'SANDBOX_PASSWORD': 'inherited'})
        self.assertEqual(outcome.recorder.env_of(DOWN)['SANDBOX_PASSWORD'], 'unused-for-teardown')
        self.assertEqual(self.others(outcome), [DOWN])
        self.assertEqual(outcome.desktop.requests, [])
        self.assertEqual((self.root / '.env').read_text(), CREDENTIALS)

    def test_failed_teardown_is_not_reported_as_destroyed(self):
        outcome = self.invoke('stop', down_exit=3)
        self.assertEqual(outcome.code, 3)
        self.assertNotIn('destroyed', outcome.stdout)

    def test_teardown_rejects_arguments_without_acting(self):
        outcome = self.invoke('stop', '--fresh')
        self.assertEqual(outcome.code, 1)
        self.assertEqual(outcome.calls, [])


class LogsAndDelegationTests(LauncherCase):
    VPN_STATUS = ['docker', 'inspect', '--type', 'container', '-f', '{{.State.Status}}', 'safebrowse-vpn']

    def tail(self, count, name):
        return ['docker', 'exec', 'safebrowse-gw', 'tail', '-n', count, '/var/log/squid/' + name]

    def test_logs_default_to_50_lines(self):
        outcome = self.invoke('logs')
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual(outcome.calls[1:], [self.tail('50', 'cache.log'), self.tail('50', 'access.log'), self.VPN_STATUS])
        self.assertNotIn('VPN diagnostics', outcome.stdout)
        self.assertIn('No access log', outcome.stdout)

    def test_logs_accept_a_positive_line_count(self):
        outcome = self.invoke('logs', '7', access_exit=0)
        self.assertEqual(outcome.calls[1:], [self.tail('7', 'cache.log'), self.tail('7', 'access.log'), self.VPN_STATUS])
        self.assertIn('access line', outcome.stdout)
        self.assertNotIn('No access log', outcome.stdout)

    def test_logs_reject_other_counts_without_contacting_docker(self):
        for args in (('0',), ('-1',), ('05',), ('abc',), ('1.5',), ('',), ('5 ',), ('5\n',), ('５',), ('5', '6')):
            with self.subTest(args=args):
                outcome = self.invoke('logs', *args)
                self.assertEqual(outcome.code, 1)
                self.assertIn('positive line count', outcome.stderr)
                self.assertEqual(outcome.calls, [])

    def test_logs_report_a_stopped_gateway(self):
        for settings in ({'gateway': 'exited'}, {'gateway': None}):
            with self.subTest(settings=settings):
                outcome = self.invoke('logs', **settings)
                self.assertEqual(outcome.code, 1)
                self.assertIn('Gateway is not running', outcome.stdout)
                self.assertEqual(outcome.calls[1:], [self.VPN_STATUS])  # nothing is executed in a stopped gateway

    def test_verify_keeps_its_arguments_and_exit_codes(self):
        for code in (0, 1, 2):
            with self.subTest(code=code):
                outcome = self.invoke('verify', '--wait-browser', verify_exit=code)
                self.assertEqual(outcome.code, code)
                self.assertEqual(outcome.calls, [['verify.py', '--wait-browser']])
        self.assertEqual(self.invoke('verify').calls, [['verify.py']])

    def test_pin_refreshes_only_on_request(self):
        self.assertEqual(self.invoke('pin').calls, [['pin.py']])
        outcome = self.invoke('pin', '--refresh', pin_exit=1)
        self.assertEqual(outcome.calls, [['pin.py', '--refresh']])
        self.assertEqual(outcome.code, 1)

    def test_delegated_scripts_come_from_this_checkout(self):
        seen = []

        def run(args, **options):
            seen.append(args)
            return subprocess.CompletedProcess(args, 0)
        self.invoke('verify', run=run)
        self.assertEqual(seen, [[sys.executable, str(self.root / 'scripts/verify.py')]])


if __name__ == '__main__':
    unittest.main()
