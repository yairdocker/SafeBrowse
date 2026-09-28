"""Launcher lifecycle and URL safety regressions, without Docker."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('open_url', ROOT / 'scripts/open_url.py')
open_url = importlib.util.module_from_spec(spec)
spec.loader.exec_module(open_url)


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


# Every external action is recorded. Only URL validation uses the real Python
# implementation; the test never calls Docker or opens a browser.
FAKE = r'''
import json, os, subprocess, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['ACTION_LOG'], 'a') as f:
    f.write(json.dumps([name] + args) + '\n')
if name == 'python3':
    if '--validate' in args:
        sys.exit(subprocess.run([sys.executable, os.environ['REAL_OPENER']] + args[1:]).returncode)
    if args[:1] == ['scripts/network.py']:
        print('172.31.1.0/24' if '--skip' in args else '172.31.0.0/24')
    if args[:2] == ['scripts/open_url.py', '--initialize'] and os.environ.get('INIT_FAIL_ONCE'):
        marker = Path('initialize-count')
        if not marker.exists():
            marker.write_text('1')
            sys.exit(1)
    sys.exit(0)
if name == 'verify.sh':
    sys.exit(int(os.environ.get('VERIFY_EXIT', '0')))
if name == 'curl':
    print('200' if '--config' in args else '401', end='')
    sys.exit(0)
if args[:2] == ['network', 'inspect']:
    print('isolated')
elif args[:2] == ['compose', 'ps']:
    print('existing' if os.environ.get('EXISTING') else '')
elif args[:2] == ['compose', 'build']:
    sys.exit(int(os.environ.get('BUILD_EXIT', '0')))
elif args[:2] == ['compose', 'up'] and os.environ.get('UP_OVERLAP_ONCE'):
    marker = Path('up-count')
    if not marker.exists():
        marker.write_text('1')
        print('invalid pool request: Pool overlaps with other one on this address space', file=sys.stderr)
        sys.exit(1)
elif args[:1] == ['inspect']:
    print('true\ntrue\ntrue')
elif args[:1] == ['version']:
    print('29.0.0')
elif args[:1] == ['info']:
    print('8000000000')
'''


class LauncherTests(unittest.TestCase):
    def launch(self, *args, **settings):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            (root / 'bin').mkdir()
            shutil.copyfile(ROOT / 'run.sh', root / 'run.sh')
            shutil.copyfile(ROOT / 'scripts/launch-lib.sh', root / 'scripts/launch-lib.sh')
            (root / '.env').write_text('SANDBOX_USER=test\nSANDBOX_PASSWORD=test-password\n')
            for name in ('docker', 'curl', 'python3', 'verify.sh'):
                path = root / ('verify.sh' if name == 'verify.sh' else 'bin/' + name)
                path.write_text('#!' + sys.executable + '\n' + FAKE)
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'],
                       ACTION_LOG=str(root / 'actions'), REAL_OPENER=str(ROOT / 'scripts/open_url.py'))
            for name in ('EXISTING', 'VERIFY_EXIT', 'BUILD_EXIT', 'UP_OVERLAP_ONCE', 'INIT_FAIL_ONCE'):
                env.pop(name, None)
            env.update(settings)
            result = subprocess.run(['bash', str(root / 'run.sh'), *args], env=env, text=True,
                                    capture_output=True, timeout=20)
            actions = [json.loads(line) for line in (root / 'actions').read_text().splitlines()] if (root / 'actions').exists() else []
            return result, actions

    def test_existing_session_requires_explicit_choice(self):
        result, actions = self.launch(EXISTING='1')
        self.assertEqual(result.returncode, 1)
        self.assertIn('Use --resume', result.stderr)
        self.assertFalse(any(a[:2] == ['docker', 'compose'] and a[2] in ('build', 'up', 'down') for a in actions))

    def test_resume_does_not_rebuild_restart_or_discard(self):
        result, actions = self.launch('--resume', EXISTING='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(a[:2] == ['docker', 'compose'] and a[2] in ('build', 'up', 'down') for a in actions))

    def test_fresh_builds_before_destroying_and_starting(self):
        result, actions = self.launch('--fresh', EXISTING='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        build, down, up = [next(i for i, a in enumerate(actions) if a[:3] == ['docker', 'compose', action])
                           for action in ('build', 'down', 'up')]
        self.assertLess(build, down)
        self.assertLess(down, up)

    def test_build_failure_preserves_session(self):
        result, actions = self.launch('--fresh', EXISTING='1', BUILD_EXIT='1')
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(['docker', 'compose', 'down', '--volumes', '--remove-orphans'], actions)

    def test_overlapping_pool_retries_with_another_subnet(self):
        result, actions = self.launch(UP_OVERLAP_ONCE='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        selections = [a for a in actions if a[:3] == ['python3', 'scripts/network.py', 'select']]
        self.assertEqual(len(selections), 2)
        self.assertIn('--skip', selections[1])
        self.assertEqual(sum(a[:3] == ['docker', 'compose', 'up'] for a in actions), 2)
        self.assertIn('trying another subnet', result.stdout)

    def test_firefox_startup_race_is_retried(self):
        result, actions = self.launch(INIT_FAIL_ONCE='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sum(a[:3] == ['python3', 'scripts/open_url.py', '--initialize'] for a in actions), 2)

    def test_target_is_opened_only_after_successful_verification(self):
        url = 'https://example.com/?x=$(id);&y=1'
        for code in (0, 1, 2):
            with self.subTest(code=code):
                result, actions = self.launch('--url', url, VERIFY_EXIT=str(code))
                self.assertEqual(result.returncode, code, result.stderr)
                navigation = ['python3', 'scripts/open_url.py', url]
                if code == 0:
                    self.assertLess(actions.index(['verify.sh', '--wait-browser']), actions.index(navigation))
                else:
                    self.assertNotIn(navigation, actions)
                    self.assertNotIn('automated checks passed.', result.stdout)

    def test_bad_arguments_and_url_do_not_mutate_session(self):
        for args in (('--fresh', '--resume'), ('--url',), ('--url', 'file:///etc/passwd'), ('--unknown',)):
            with self.subTest(args=args):
                result, actions = self.launch(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(a[0] == 'docker' for a in actions))

    def test_resume_requires_existing_session(self):
        result, actions = self.launch('--resume')
        self.assertEqual(result.returncode, 1)
        self.assertIn('no session exists', result.stderr)
        self.assertFalse(any(a[:3] == ['docker', 'compose', 'up'] for a in actions))

    def test_help_does_not_contact_docker(self):
        result, actions = self.launch('--help')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(actions, [])


if __name__ == '__main__':
    unittest.main()
