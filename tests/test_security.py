"""Regression checks run without Docker or network access."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


verify = module("verify")
pin = module("pin")


def result(stdout="", code=0):
    return subprocess.CompletedProcess([], code, stdout, "")


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.report = verify.Report()
        self.output = io.StringIO()
        self.redirect = contextlib.redirect_stdout(self.output)
        self.redirect.__enter__()

    def tearDown(self):
        self.redirect.__exit__(None, None, None)

    def test_only_completed_403_proves_proxy_denial(self):
        for code, status, expected in (("403", 0, "PASS"), ("503", 0, "INCONCLUSIVE"),
                                       ("000", 7, "INCONCLUSIVE"), ("403", 28, "INCONCLUSIVE"),
                                       ("200", 0, "FAIL"), ("301", 0, "FAIL"),
                                       ("407", 0, "INCONCLUSIVE"), ("", 125, "INCONCLUSIVE")):
            with self.subTest(code=code, status=status):
                self.assertEqual(verify.classify_denial(code, status, "X-Squid-Error: ERR_ACCESS_DENIED 0"), expected)

    def test_origin_403_is_not_acl_evidence(self):
        self.assertEqual(verify.classify_denial("403", 0, "Server: origin"), "INCONCLUSIVE")

    def test_503_makes_entire_verification_unsuccessful(self):
        with patch.object(verify, "execute", return_value=result("HTTP/1.1 503 Service Unavailable\r\n\r\n\n503")):
            verify.check_proxy(self.report, "http://192.168.1.1/")
        self.assertEqual(self.report.finish(), 2)
        self.assertEqual(self.report.counts["PASS"], 0)

    def test_gateway_positive_probe_rejects_http_errors(self):
        with patch.object(verify, "execute", return_value=result("HTTP/1.1 503 Service Unavailable\r\n\r\n\n503")):
            verify.check_proxy(self.report, "https://example.com/", denied=False)
        self.assertEqual(self.report.finish(), 1)

    def test_clipboard_requires_both_explicit_current_states(self):
        for text, expected in (("", "INCONCLUSIVE"),
                               ("'clipboard_in_enabled': (False,)", "INCONCLUSIVE"),
                               ("clipboard disabled", "INCONCLUSIVE"),
                               ("'clipboard_in_enabled': (False,) 'clipboard_out_enabled': (False,)", "PASS"),
                               ("'clipboard_in_enabled': (False,) 'clipboard_out_enabled': (True,)", "FAIL"),
                               ("'clipboard_in_enabled': (False,) 'clipboard_out_enabled': (False,) "
                                "'clipboard_out_enabled': (True,)", "FAIL")):
            with self.subTest(text=text):
                self.assertEqual(verify.clipboard_state(text), expected)

    def test_failed_direct_probe_is_never_a_pass(self):
        for exitcode in (125, 127):
            with self.subTest(exitcode=exitcode), patch.object(verify, "execute", return_value=result("", exitcode)):
                report = verify.Report()
                verify.check_direct(report)
                self.assertEqual(report.counts["PASS"], 0)
                self.assertEqual(report.finish(), 2)

    def test_direct_tcp_classification(self):
        for probe, expected in (({"connected": True}, "FAIL"),
                                ({"connected": False, "errno": 101}, "PASS"),
                                ({"connected": False, "errno": None}, "INCONCLUSIVE"),
                                ({"connected": False, "errno": 111}, "INCONCLUSIVE")):
            with self.subTest(probe=probe), patch.object(verify, "execute", return_value=result(json.dumps(probe))):
                report = verify.Report()
                verify.check_direct(report)
                self.assertEqual(report.counts[expected], 1)

    def test_docker_failure_is_nonzero_without_reassurance(self):
        with patch.object(verify, "docker_json", side_effect=RuntimeError("unavailable")):
            self.assertEqual(verify.main(), 2)
        self.assertNotIn("PASS", self.output.getvalue())

    def test_startup_retry_reports_only_final_browser_result(self):
        def probe(report, config):
            report.emit("INCONCLUSIVE" if probe.calls == 0 else "PASS", "profile initialization")
            probe.calls += 1
        probe.calls = 0
        with patch.object(verify, "check_browser", side_effect=probe), patch.object(verify.time, "sleep"):
            verify.check_browser_ready(self.report, wait_seconds=30)
        self.assertEqual(probe.calls, 2)
        self.assertEqual(self.report.counts, {"PASS": 1, "FAIL": 0, "INCONCLUSIVE": 0})

    def test_startup_retry_never_hides_a_verified_failure(self):
        with patch.object(verify, "check_browser", side_effect=lambda report, config: report.emit("FAIL", "disabled blocker")) as probe:
            verify.check_browser_ready(self.report, wait_seconds=30)
        self.assertEqual(probe.call_count, 1)
        self.assertEqual(self.report.finish(), 1)

    def test_startup_timeout_remains_inconclusive(self):
        with patch.object(verify, "check_browser", side_effect=lambda report, config: report.emit("INCONCLUSIVE", "missing profile")):
            verify.check_browser_ready(self.report, wait_seconds=0)
        self.assertEqual(self.report.counts["PASS"], 0)
        self.assertEqual(self.report.finish(), 2)

    def test_namespace_and_missing_addon_probes_do_not_pass(self):
        policy = (ROOT / "policies/firefox-policies.json").read_text()
        responses = [result("", 125), result("[]"), result(policy), result("[]")]
        with patch.object(verify, "execute", side_effect=responses):
            verify.check_browser(self.report)
        self.assertEqual(self.report.counts["INCONCLUSIVE"], 3)
        self.assertEqual(self.report.finish(), 2)

    def test_real_firefox_forkserver_cmdline_formats(self):
        # Firefox rewrites forked process argv into a single space-separated
        # argv[0]. A NUL-only split silently missed these real web processes.
        for command in (b"/usr/lib/firefox/firefox\0-contentproc\0tab\0",
                        b"/usr/lib/firefox/firefox -contentproc -isForBrowser 3 tab\0"):
            status = "Name:\tIsolated Web Co\nSeccomp:\t2\nNoNewPrivs:\t1\n"
            output = io.StringIO()
            with self.subTest(command=command), patch("glob.glob", return_value=["/proc/10/cmdline"]), \
                    patch("builtins.open", side_effect=[io.BytesIO(command), io.StringIO(status)]), \
                    contextlib.redirect_stdout(output):
                exec(verify.SANDBOX_PROBE, {})
            self.assertEqual(json.loads(output.getvalue()), [{"seccomp": 2, "nnp": 1}])

    def test_forkserver_is_not_misreported_as_web_content(self):
        output = io.StringIO()
        with patch("glob.glob", return_value=["/proc/10/cmdline"]), \
                patch("builtins.open", return_value=io.BytesIO(b"/usr/lib/firefox/firefox\0-contentproc\0forkserver\0")), \
                contextlib.redirect_stdout(output):
            exec(verify.SANDBOX_PROBE, {})
        self.assertEqual(json.loads(output.getvalue()), [])

    def test_disabled_addon_is_a_failure(self):
        policy = (ROOT / "policies/firefox-policies.json").read_text()
        responses = [result(), result('[{"seccomp":2,"nnp":1}]'), result(policy),
                     result('[{"active":false,"userDisabled":true,"appDisabled":false}]')]
        with patch.object(verify, "execute", side_effect=responses):
            verify.check_browser(self.report)
        self.assertEqual(self.report.finish(), 1)

    def test_policy_values_must_match_not_just_keys(self):
        policy = json.loads((ROOT / "policies/firefox-policies.json").read_text())
        policy["policies"]["Proxy"]["Locked"] = False
        responses = [result(), result('[{"seccomp":2,"nnp":1}]'), result(json.dumps(policy)),
                     result('[{"active":true,"userDisabled":false,"appDisabled":false}]')]
        with patch.object(verify, "execute", side_effect=responses):
            verify.check_browser(self.report)
        self.assertEqual(self.report.finish(), 1)


class IsolationTests(unittest.TestCase):
    def setUp(self):
        self.browser = {"Mounts": [{"Type": "tmpfs", "Destination": "/config"}],
                        "NetworkSettings": {"Networks": {verify.NETWORK: {}}},
                        "HostConfig": {"SecurityOpt": ["no-new-privileges:true"], "CapDrop": ["ALL"],
                                       "CapAdd": list(verify.CAPS), "PortBindings": {}, "Memory": 4*1024**3,
                                       "NanoCpus": 4*10**9, "PidsLimit": 1024}}
        self.ui = {"HostConfig": {"PortBindings": {"3001/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3011"}]}}}
        self.network = {"Internal": True, "Driver": "bridge", "EnableIPv6": False,
                        "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}}

    def check(self, config=verify.DEFAULT):
        report = verify.Report()
        with contextlib.redirect_stdout(io.StringIO()):
            verify.check_isolation(report, self.browser, self.ui, self.network, config)
        return report.counts["FAIL"]

    def test_tmpfs_mount_is_allowed(self):
        self.assertEqual(self.check(), 0)

    def test_host_bind_mount_is_rejected(self):
        self.browser["Mounts"].append({"Type": "bind", "Destination": "/host"})
        self.assertGreater(self.check(), 0)

    def test_single_wrong_network_is_rejected(self):
        self.browser["NetworkSettings"]["Networks"] = {"outside": {}}
        self.assertGreater(self.check(), 0)

    def test_extra_capability_is_rejected_even_with_drop_all(self):
        self.browser["HostConfig"]["CapAdd"].append("SYS_ADMIN")
        self.assertGreater(self.check(), 0)

    def test_internal_bridge_without_isolated_gateway_fails(self):
        self.network["Options"] = {}
        self.assertGreater(self.check(), 0)

    def test_selected_subnet_must_match_live_bridge(self):
        self.network["IPAM"] = {"Config": [{"Subnet": "172.31.2.0/24"}]}
        self.assertGreater(self.check(verify.DEFAULT._replace(subnet="172.31.1.0/24")), 0)

    def test_lan_ui_binding_is_rejected(self):
        self.ui["HostConfig"]["PortBindings"]["3001/tcp"][0]["HostIp"] = "0.0.0.0"
        self.assertGreater(self.check(), 0)


class PinTests(unittest.TestCase):
    def test_refresh_pulls_even_when_local_tag_exists(self):
        ref = "ubuntu/squid@sha256:" + "a"*64
        with patch.object(pin.subprocess, "run", return_value=result(json.dumps([{"RepoDigests": [ref]}]))) as mock:
            self.assertEqual(pin.resolve("ubuntu/squid", True), ref)
        self.assertEqual(mock.call_args_list[0].args[0], ["docker", "pull", "ubuntu/squid:latest"])

    def test_default_pinning_does_not_fetch(self):
        ref = "ubuntu/squid@sha256:" + "a"*64
        with patch.object(pin.subprocess, "run", return_value=result(json.dumps([{"RepoDigests": [ref]}]))) as mock:
            pin.resolve("ubuntu/squid", False)
        self.assertEqual(mock.call_count, 1)
        self.assertEqual(mock.call_args.args[0][:3], ["docker", "image", "inspect"])

    def test_refresh_failure_leaves_all_files_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("Dockerfile", "docker-compose.yml", "PINS.txt"):
                (root / name).write_bytes((ROOT / name).read_bytes())
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            refs = ["lscr.io/linuxserver/firefox@sha256:" + "a"*64,
                    "ubuntu/squid@sha256:" + "b"*64, RuntimeError("registry unavailable")]
            with patch.object(pin, "resolve", side_effect=refs), self.assertRaises(RuntimeError):
                pin.pin(root, True)
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})

    def test_successful_pinning_updates_all_references_and_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("Dockerfile", "docker-compose.yml", "PINS.txt"):
                (root / name).write_bytes((ROOT / name).read_bytes())
            refs = [repo + "@sha256:" + char*64 for (repo, _, _), char in zip(pin.IMAGES, "abc")]
            with patch.object(pin, "resolve", side_effect=refs), contextlib.redirect_stdout(io.StringIO()):
                pin.pin(root, True)
            for ref, (_, name, _) in zip(refs, pin.IMAGES):
                self.assertIn(ref, (root / name).read_text())
                self.assertIn(ref, (root / "PINS.txt").read_text())
            self.assertFalse(list(root.glob(".pin-*")))

    def test_missing_or_duplicate_reference_fails(self):
        for text in ("# ubuntu/squid:latest\n", "image: ubuntu/squid:latest\nimage: ubuntu/squid:latest\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                pin.rewrite(text, "ubuntu/squid", "image:", "ubuntu/squid@sha256:" + "a"*64)

    def test_nonlatest_tag_is_not_a_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("Dockerfile", "docker-compose.yml", "PINS.txt"):
                (root / name).write_bytes((ROOT / name).read_bytes())
            compose = root / "docker-compose.yml"
            import re
            compose.write_text(re.sub(r"ubuntu/squid@sha256:[a-f0-9]{64}", "ubuntu/squid:6.0", compose.read_text()))
            report = verify.Report()
            with patch.object(verify, "ROOT", root), contextlib.redirect_stdout(io.StringIO()):
                verify.check_pins(report)
            self.assertGreater(report.counts["FAIL"], 0)

    def test_source_files_are_resolved_independently_of_cwd(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(verify, "docker_json", side_effect=RuntimeError):
            # The wrapper resolves its own location, even from another cwd.
            run = subprocess.run([str(ROOT / "pin.sh"), "--help"], cwd=temp, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("--refresh", run.stdout)


class LauncherTests(unittest.TestCase):
    def shell(self, command, *args):
        return subprocess.run(["bash", "-c", 'set -uo pipefail; source "$1"; shift; ' + command,
                               "test", str(ROOT / "scripts/launch-lib.sh"), *args], capture_output=True, text=True)

    def test_env_is_data_not_shell_code(self):
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "executed"
            env = Path(temp) / ".env"
            env.write_text(f"SANDBOX_USER=sandbox\nSANDBOX_PASSWORD=$(touch {marker})\n")
            run = self.shell('load_credentials "$1"', str(env))
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse(marker.exists())

    def test_credentials_override_inherited_values(self):
        with tempfile.TemporaryDirectory() as temp:
            env = Path(temp) / ".env"
            env.write_text("SANDBOX_USER=sandbox\nSANDBOX_PASSWORD=test-password\n")
            run = self.shell('export SANDBOX_USER=wrong SANDBOX_PASSWORD=wrong; load_credentials "$1"; '
                             'bash -c \'test "$SANDBOX_PASSWORD" = test-password\'', str(env))
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_duplicate_credentials_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            env = Path(temp) / ".env"
            env.write_text("SANDBOX_USER=sandbox\nSANDBOX_PASSWORD=first\nSANDBOX_PASSWORD=second\n")
            self.assertNotEqual(self.shell('load_credentials "$1"', str(env)).returncode, 0)

    def test_500_does_not_count_as_ready(self):
        run = self.shell('curl() { printf 500; }; export -f curl; desktop_ready')
        self.assertNotEqual(run.returncode, 0)

    def test_unauthenticated_200_does_not_count_as_ready(self):
        run = self.shell('curl() { printf 200; }; export -f curl; desktop_ready')
        self.assertNotEqual(run.returncode, 0)

    def test_authenticated_200_counts_as_ready(self):
        run = self.shell('SANDBOX_USER=sandbox; SANDBOX_PASSWORD=test; '
                         'curl() { case "$*" in *--config*) cat >/dev/null; printf 200 ;; *) printf 401 ;; esac; }; '
                         'export -f curl; desktop_ready')
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_wrong_password_does_not_count_as_ready(self):
        run = self.shell('SANDBOX_USER=sandbox; SANDBOX_PASSWORD=wrong; '
                         'curl() { case "$*" in *--config*) cat >/dev/null ;; esac; printf 401; }; '
                         'export -f curl; desktop_ready')
        self.assertNotEqual(run.returncode, 0)

    def test_teardown_does_not_require_a_credentials_file(self):
        import os
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stop = root / "stop.sh"
            stop.write_bytes((ROOT / "stop.sh").read_bytes())
            docker = root / "docker"
            docker.write_text('#!/bin/sh\n[ "$SANDBOX_PASSWORD" = unused-for-teardown ] && [ "$1 $2" = "compose down" ]\n')
            docker.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"])
            env.pop("SANDBOX_PASSWORD", None)
            run = subprocess.run(["bash", str(stop)], env=env, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
