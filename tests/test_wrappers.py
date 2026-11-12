"""Smoke tests for the shell wrappers. The launcher itself is tested in test_launch.py."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
WRAPPERS = ('run', 'stop', 'verify', 'logs', 'pin')
BASH = shutil.which('bash')
# Stands in for scripts/safebrowse.py: records exactly what the wrapper passed on.
STUB = '''import json, os, sys
with open(os.environ["WRAPPER_LOG"], "w") as f:
    json.dump(sys.argv[1:], f)
sys.exit(int(os.environ.get("WRAPPER_EXIT", "0")))
'''
AWKWARD = ['--url', 'https://example.com/?x=$(id);&quote="hello"&backtick=`id`', 'two words', '', '*', "it's", '-n', '\\']


@unittest.skipUnless(BASH and os.name == 'posix', 'the wrappers are Bash scripts')
class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix='safebrowse wrappers '))
        self.addCleanup(shutil.rmtree, self.temp, True)
        self.root = self.temp / 'check out (copy)'
        (self.root / 'scripts').mkdir(parents=True)
        for name in WRAPPERS:
            shutil.copy(ROOT / (name + '.sh'), self.root / (name + '.sh'))
        (self.root / 'scripts/safebrowse.py').write_text(STUB)
        self.elsewhere = self.temp / 'another directory'
        self.elsewhere.mkdir()
        # Any Docker use by a wrapper smoke test is a failure, not a real action.
        self.bin = self.temp / 'bin'
        self.bin.mkdir()
        (self.bin / 'docker').write_text('#!/bin/sh\necho called >> "$DOCKER_LOG"\nexit 97\n')
        (self.bin / 'docker').chmod(0o755)
        self.env = dict(os.environ, WRAPPER_LOG=str(self.temp / 'arguments.json'), DOCKER_LOG=str(self.temp / 'docker.log'),
                        PATH=str(self.bin) + os.pathsep + os.environ['PATH'])
        self.env.pop('WRAPPER_EXIT', None)

    def forwarded(self, script, *args, cwd=None, **env):
        result = subprocess.run([str(script), *args], cwd=str(cwd or self.elsewhere), env=dict(self.env, **env),
                                capture_output=True, text=True, timeout=30)
        log = Path(self.env['WRAPPER_LOG'])
        arguments = json.loads(log.read_text()) if log.exists() else None
        log.unlink() if log.exists() else None
        return result, arguments

    def test_arguments_and_exit_status_pass_through_unchanged(self):
        for name in WRAPPERS:
            for code in (0, 1, 2, 7):
                with self.subTest(wrapper=name, code=code):
                    result, arguments = self.forwarded(self.root / (name + '.sh'), *AWKWARD, WRAPPER_EXIT=str(code))
                    self.assertEqual(arguments, [name] + AWKWARD)
                    self.assertEqual(result.returncode, code, result.stderr)

    def test_wrappers_work_through_relative_paths_and_bash(self):
        for command, cwd in (([BASH, 'run.sh'], self.root), (['./run.sh'], self.root),
                             ([BASH, '../check out (copy)/run.sh'], self.elsewhere)):
            with self.subTest(command=command):
                result = subprocess.run(command + ['--fresh'], cwd=str(cwd), env=self.env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(Path(self.env['WRAPPER_LOG']).read_text()), ['run', '--fresh'])

    def test_missing_python_is_an_actionable_error(self):
        empty = self.temp / 'empty'
        empty.mkdir()
        for name in WRAPPERS:
            with self.subTest(wrapper=name):
                result = subprocess.run([BASH, str(self.root / (name + '.sh'))], env=dict(self.env, PATH=str(empty)),
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertIn('python3 was not found', result.stderr)
                self.assertIn('Install Python 3.12 or newer', result.stderr)
                self.assertFalse(Path(self.env['WRAPPER_LOG']).exists())

    def test_committed_wrappers_are_executable_and_parse(self):
        for name in WRAPPERS:
            with self.subTest(wrapper=name):
                path = ROOT / (name + '.sh')
                self.assertTrue(os.access(path, os.X_OK))
                self.assertEqual(subprocess.run([BASH, '-n', str(path)], capture_output=True).returncode, 0)

    def test_real_help_needs_no_docker_from_any_directory(self):
        for name, expected in (('run', '--resume'), ('pin', '--refresh'), ('verify', '--wait-browser'),
                               ('stop', 'Usage:'), ('logs', 'Usage:')):
            with self.subTest(wrapper=name):
                result = subprocess.run([str(ROOT / (name + '.sh')), '--help'], cwd=str(self.elsewhere), env=self.env,
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected, result.stdout)
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/safebrowse.py'), 'run', '--help'],
                                cwd=str(self.elsewhere), env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(Path(self.env['DOCKER_LOG']).exists())

    def test_real_argument_errors_exit_1_without_docker(self):
        for name, args in (('run', ['--fresh', '--resume']), ('run', ['--url', 'file:///etc/passwd']),
                           ('logs', ['0']), ('stop', ['now'])):
            with self.subTest(wrapper=name, args=args):
                result = subprocess.run([str(ROOT / (name + '.sh')), *args], cwd=str(self.elsewhere), env=self.env,
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 1)
        self.assertFalse(Path(self.env['DOCKER_LOG']).exists())


if __name__ == '__main__':
    unittest.main()
