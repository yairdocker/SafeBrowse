"""Regression checks run without Docker or network access."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import os
import re
import subprocess
import sys
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
spec = importlib.util.spec_from_file_location("host_baseline", ROOT / "tests/host_baseline.py")
host_baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host_baseline)


def result(stdout="", code=0):
    return subprocess.CompletedProcess([], code, stdout, "")


NAMESPACES = result(json.dumps({"clone": "ok", "unshare": "ok", "settings": {"user.max_user_namespaces": "31880"}}))
CONTENT = result('[{"seccomp":2,"nnp":1,"userns":true}]')


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
            for own, separate in (("1000 1000 1\n", True), ("0 0 4294967295\n", False)):
                output = io.StringIO()
                files = [io.StringIO("0 0 4294967295\n"), io.BytesIO(command), io.StringIO(status), io.StringIO(own)]
                with self.subTest(command=command, own=own), patch("glob.glob", return_value=["/proc/10/cmdline"]), \
                        patch("builtins.open", side_effect=files), contextlib.redirect_stdout(output):
                    exec(verify.SANDBOX_PROBE, {})
                self.assertEqual(json.loads(output.getvalue()), [{"seccomp": 2, "nnp": 1, "userns": separate}])

    def test_forkserver_is_not_misreported_as_web_content(self):
        output = io.StringIO()
        files = [io.StringIO("0 0 4294967295\n"), io.BytesIO(b"/usr/lib/firefox/firefox\0-contentproc\0forkserver\0")]
        with patch("glob.glob", return_value=["/proc/10/cmdline"]), patch("builtins.open", side_effect=files), \
                contextlib.redirect_stdout(output):
            exec(verify.SANDBOX_PROBE, {})
        self.assertEqual(json.loads(output.getvalue()), [])

    def test_unreadable_namespace_map_is_not_reported_as_separate(self):
        status = "Name:\tWeb Content\nSeccomp:\t2\nNoNewPrivs:\t1\n"
        output = io.StringIO()
        files = [io.StringIO("0 0 4294967295\n"), io.BytesIO(b"/usr/lib/firefox/firefox\0-contentproc\0tab\0"),
                 io.StringIO(status), PermissionError()]
        with patch("glob.glob", return_value=["/proc/10/cmdline"]), patch("builtins.open", side_effect=files), \
                contextlib.redirect_stdout(output):
            exec(verify.SANDBOX_PROBE, {})
        self.assertEqual(json.loads(output.getvalue()), [{"seccomp": 2, "nnp": 1, "userns": None}])

    def test_disabled_addon_is_a_failure(self):
        policy = (ROOT / "policies/firefox-policies.json").read_text()
        responses = [NAMESPACES, CONTENT, result(policy),
                     result('[{"active":false,"userDisabled":true,"appDisabled":false}]')]
        with patch.object(verify, "execute", side_effect=responses):
            verify.check_browser(self.report)
        self.assertEqual(self.report.finish(), 1)

    def test_policy_values_must_match_not_just_keys(self):
        policy = json.loads((ROOT / "policies/firefox-policies.json").read_text())
        policy["policies"]["Proxy"]["Locked"] = False
        responses = [NAMESPACES, CONTENT, result(json.dumps(policy)),
                     result('[{"active":true,"userDisabled":false,"appDisabled":false}]')]
        with patch.object(verify, "execute", side_effect=responses):
            verify.check_browser(self.report)
        self.assertEqual(self.report.finish(), 1)

    def browser_checks(self, namespaces, content):
        policy = (ROOT / "policies/firefox-policies.json").read_text()
        responses = [namespaces, content, result(policy), result('[{"active":true,"userDisabled":false,"appDisabled":false}]')]
        report = verify.Report()
        with patch.object(verify, "execute", side_effect=responses) as execute:
            verify.check_browser(report)
        return report, execute

    def test_healthy_browser_passes_every_browser_check(self):
        report, execute = self.browser_checks(NAMESPACES, CONTENT)
        self.assertEqual(report.counts, {"PASS": 5, "FAIL": 0, "INCONCLUSIVE": 0})
        # The namespace probe makes Firefox's own two calls; it is not `unshare -Ur`.
        self.assertEqual(execute.call_args_list[0].args[:3], ("python3", "-I", "-c"))
        self.assertIn("0x10000000", execute.call_args_list[0].args[3])
        self.assertIn("0x20000000", execute.call_args_list[0].args[3])

    def test_namespace_probe_passes_only_on_demonstrated_success(self):
        def state(**probe):
            return verify.namespace_state(result(json.dumps(probe)))[0]
        self.assertEqual(state(clone="ok", unshare="ok", settings={}), "PASS")
        for probe in ({"clone": "EPERM", "unshare": None}, {"clone": "ok", "unshare": "EPERM"},
                      {"clone": "ok", "unshare": "no result"}, {"clone": None, "unshare": None}, {"clone": "ok"}, {}):
            with self.subTest(probe=probe):
                self.assertEqual(state(**probe), "INCONCLUSIVE")
        for broken in (result("", 125), result(""), result("not json"), result("[]"), result('"ok"')):
            with self.subTest(stdout=broken.stdout, code=broken.returncode):
                self.assertEqual(verify.namespace_state(broken)[0], "INCONCLUSIVE")

    def test_namespace_denial_does_not_name_a_layer_or_echo_arbitrary_text(self):
        probe = {"clone": "EPERM", "unshare": None, "settings": {"kernel.apparmor_restrict_unprivileged_userns": "1",
                                                                  "user.max_user_namespaces": "SECRET text"}}
        state, detail = verify.namespace_state(result(json.dumps(probe)))
        self.assertEqual(state, "INCONCLUSIVE")
        self.assertIn("does not identify", detail)
        self.assertIn("kernel.apparmor_restrict_unprivileged_userns=1", detail)
        self.assertNotIn("SECRET", detail)

    def test_content_processes_outside_their_own_namespace_fail_when_namespaces_work(self):
        shared = result('[{"seccomp":2,"nnp":1,"userns":true},{"seccomp":2,"nnp":1,"userns":false}]')
        report, _ = self.browser_checks(NAMESPACES, shared)
        self.assertEqual(report.counts["FAIL"], 1)
        unreadable = result('[{"seccomp":2,"nnp":1,"userns":null}]')
        report, _ = self.browser_checks(NAMESPACES, unreadable)
        self.assertEqual((report.counts["FAIL"], report.counts["INCONCLUSIVE"]), (0, 1))

    def test_unavailable_namespaces_stay_inconclusive_without_a_second_verdict(self):
        denied = result(json.dumps({"clone": "EPERM", "unshare": None, "settings": {}}))
        report, _ = self.browser_checks(denied, result('[{"seccomp":2,"nnp":1,"userns":false}]'))
        self.assertEqual(report.counts, {"PASS": 3, "FAIL": 0, "INCONCLUSIVE": 1})
        self.assertEqual(report.finish(), 2)

    def test_missing_firefox_filter_still_fails(self):
        report, _ = self.browser_checks(NAMESPACES, result('[{"seccomp":0,"nnp":1,"userns":true}]'))
        self.assertEqual(report.counts["FAIL"], 1)


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


APPROVED = json.loads((ROOT / "security/seccomp-firefox.json").read_text())
UPSTREAM = json.loads((ROOT / "security/upstream/moby-seccomp-default.json").read_text())
DESKTOP = {"security": ["name=seccomp,profile=builtin", "name=cgroupns"], "os": "Docker Desktop"}
UBUNTU = {"security": ["name=apparmor", "name=seccomp,profile=builtin", "name=cgroupns"], "os": "Ubuntu 24.04.3 LTS"}
EXPECTED_CALLS = {"unshare_none": "EPERM", "personality": "EPERM", "clone3": "ENOSYS", "unshare_user": "EPERM",
                  "clone_user_mount": "EPERM"}
UNFILTERED_CALLS = {"unshare_none": "ok", "personality": "ok", "clone3": "EINVAL", "unshare_user": "ok",
                    "clone_user_mount": "ok"}


def probe(**changes):
    values = {"uid": 1000, "seccomp": 2, "nnp": 1, "apparmor": None, "calls": dict(EXPECTED_CALLS)}
    values.update(changes)
    return values


class ConfinementTests(unittest.TestCase):
    """Docker's own filter and AppArmor profile, checked apart from Firefox's sandbox."""

    def setUp(self):
        self.browser = {"AppArmorProfile": "", "HostConfig": {
            "SecurityOpt": ["no-new-privileges:true", "seccomp=" + json.dumps(APPROVED, separators=(",", ":"))]}}

    def check(self, daemon=DESKTOP, observed=None, code=0, config=verify.DEFAULT):
        report, output = verify.Report(), io.StringIO()
        stdout = observed if isinstance(observed, str) else json.dumps(observed or probe())
        with patch.object(verify, "execute", return_value=result(stdout, code)) as execute, contextlib.redirect_stdout(output):
            verify.check_confinement(report, self.browser, daemon, config)
        self.execute, self.output = execute, output.getvalue()
        return report.counts

    def options(self, *values):
        self.browser["HostConfig"]["SecurityOpt"] = list(values)

    def test_accepted_configuration_on_docker_desktop(self):
        self.assertEqual(self.check(), {"PASS": 6, "FAIL": 0, "INCONCLUSIVE": 0})
        self.assertIn("NOTE", self.output)  # no AppArmor to check there, and that is not counted as a pass
        self.assertEqual(self.execute.call_args.args[:3], ("python3", "-I", "-c"))

    def test_accepted_configuration_with_apparmor(self):
        self.browser["AppArmorProfile"] = "docker-default"
        counts = self.check(UBUNTU, probe(apparmor="docker-default (enforce)"))
        self.assertEqual(counts, {"PASS": 7, "FAIL": 0, "INCONCLUSIVE": 0})
        self.assertNotIn("NOTE", self.output)

    def test_profile_is_compared_by_content_not_by_formatting(self):
        reordered = {key: APPROVED[key] for key in reversed(list(APPROVED))}
        for text in (json.dumps(APPROVED, indent=4), json.dumps(reordered), (ROOT / "security/seccomp-firefox.json").read_text()):
            with self.subTest(length=len(text)):
                self.options("no-new-privileges:true", "seccomp=" + text)
                self.assertEqual(self.check(), {"PASS": 6, "FAIL": 0, "INCONCLUSIVE": 0})
        self.options("no-new-privileges", "seccomp:" + json.dumps(APPROVED))  # the older separator
        self.assertEqual(self.check()["FAIL"], 0)

    def test_explicitly_disabled_seccomp_fails(self):
        for option in ("seccomp=unconfined", "seccomp:unconfined"):
            with self.subTest(option=option):
                self.options("no-new-privileges:true", option)
                counts = self.check(observed=probe(seccomp=0, calls=dict(UNFILTERED_CALLS)))
                self.assertEqual(counts["INCONCLUSIVE"], 0)
                self.assertGreaterEqual(counts["FAIL"], 5)
                self.assertIn("seccomp=unconfined: Docker's outer syscall filter is disabled", self.output)

    def test_explicitly_disabled_apparmor_fails(self):
        self.options("no-new-privileges:true", "seccomp=" + json.dumps(APPROVED), "apparmor=unconfined")
        self.browser["AppArmorProfile"] = "unconfined"
        self.assertEqual(self.check()["FAIL"], 1)  # refused even where the daemon has no AppArmor
        self.assertEqual(self.check(UBUNTU, probe(apparmor="unconfined"))["FAIL"], 2)

    def test_other_confinement_opt_outs_fail(self):
        for extra in ("label=disable", "label:disable", "systempaths=unconfined", "apparmor=my-profile", "no-new-privileges:false"):
            with self.subTest(extra=extra):
                self.options("no-new-privileges:true", "seccomp=" + json.dumps(APPROVED), extra)
                self.assertEqual(self.check()["FAIL"], 1)
        self.options("no-new-privileges:true", "seccomp=" + json.dumps(APPROVED))
        self.browser["HostConfig"]["Privileged"] = True
        self.assertEqual(self.check()["FAIL"], 1)

    def test_unapproved_profiles_fail_even_under_the_expected_name(self):
        widened = json.loads(json.dumps(APPROVED))
        widened["syscalls"][0]["names"].append("mount")
        unrestricted = json.loads(json.dumps(APPROVED))
        del next(rule for rule in unrestricted["syscalls"] if rule.get("comment", "").startswith("SafeBrowse")
                 and rule["names"] == ["clone"])["args"]
        permissive = dict(APPROVED, defaultAction="SCMP_ACT_ALLOW")
        for label, profile in (("extra syscall", widened), ("no argument limit", unrestricted),
                               ("allow by default", permissive), ("upstream default", UPSTREAM), ("empty", {})):
            with self.subTest(profile=label):
                self.options("no-new-privileges:true", "seccomp=" + json.dumps(profile))
                counts = self.check()
                self.assertEqual((counts["FAIL"], counts["INCONCLUSIVE"]), (1, 0))
                self.assertNotIn("PASS  browser was created with exactly", self.output)

    def test_daemon_default_filter_is_not_the_approved_configuration(self):
        for options in (("no-new-privileges:true",), ("no-new-privileges:true", "seccomp=builtin")):
            with self.subTest(options=options):
                self.options(*options)
                self.assertEqual(self.check()["FAIL"], 1)
                self.assertIn("daemon's default seccomp profile", self.output)

    def test_unreadable_profile_states_are_inconclusive(self):
        for options in (("no-new-privileges:true", "seccomp=security/seccomp-firefox.json"),
                        ("no-new-privileges:true", "seccomp=[1, 2]"),
                        ("no-new-privileges:true", "seccomp=" + json.dumps(APPROVED), "seccomp=" + json.dumps(APPROVED))):
            with self.subTest(options=[option[:30] for option in options]):
                self.options(*options)
                counts = self.check()
                self.assertEqual((counts["FAIL"], counts["INCONCLUSIVE"]), (0, 1))
        self.options("no-new-privileges:true", "seccomp=" + json.dumps(APPROVED))
        with tempfile.TemporaryDirectory() as temp:
            for name, text in (("missing.json", None), ("damaged.json", "{")):
                if text is not None:
                    (Path(temp) / name).write_text(text)
                counts = self.check(config=verify.DEFAULT._replace(seccomp_profile=Path(temp) / name))
                self.assertEqual((counts["FAIL"], counts["INCONCLUSIVE"]), (0, 1))
                self.assertNotIn("PASS  browser was created with exactly", self.output)

    def test_daemon_without_seccomp_fails_and_unknown_daemon_is_inconclusive(self):
        counts = self.check({"security": ["name=cgroupns"], "os": "Docker Desktop"})
        self.assertEqual(counts["FAIL"], 1)
        counts = self.check(None)
        self.assertEqual((counts["FAIL"], counts["INCONCLUSIVE"]), (0, 2))
        self.assertNotIn("PASS  Docker daemon supports seccomp", self.output)
        self.assertNotIn("AppArmor profile docker-default in enforce", self.output)

    def test_observed_unfiltered_process_fails_whatever_the_configuration_says(self):
        counts = self.check(observed=probe(seccomp=0, calls=dict(UNFILTERED_CALLS)))
        self.assertEqual((counts["PASS"], counts["FAIL"], counts["INCONCLUSIVE"]), (3, 3, 0))
        self.assertIn("FAIL  a UID 1000 process outside Firefox's sandbox has no seccomp filter", self.output)

    def test_seccomp_mode_alone_is_not_proof_of_the_policy(self):
        counts = self.check(observed=probe(calls=dict(UNFILTERED_CALLS)))  # Seccomp: 2, yet nothing is refused
        self.assertEqual((counts["FAIL"], counts["INCONCLUSIVE"]), (2, 0))
        for call in ("unshare_none", "personality", "unshare_user", "clone_user_mount"):
            with self.subTest(allowed=call):
                self.assertEqual(self.check(observed=probe(calls=dict(EXPECTED_CALLS, **{call: "ok"})))["FAIL"], 1)
        self.assertEqual(self.check(observed=probe(calls=dict(EXPECTED_CALLS, clone3="EINVAL")))["FAIL"], 1)

    def test_other_denials_are_not_counted_as_filter_evidence(self):
        for changes in ({"unshare_none": "ENOSYS"}, {"personality": None}, {"clone3": "EPERM"},
                        {"clone_user_mount": None}, {"unshare_user": "ENOSPC"}):
            with self.subTest(changes=changes):
                counts = self.check(observed=probe(calls=dict(EXPECTED_CALLS, **changes)))
                self.assertEqual((counts["PASS"], counts["FAIL"], counts["INCONCLUSIVE"]), (5, 0, 1))

    def test_missing_no_new_privileges_fails(self):
        self.assertEqual(self.check(observed=probe(nnp=0))["FAIL"], 1)

    def test_unusable_probe_is_inconclusive_and_passes_nothing_it_would_have_measured(self):
        for observed, code in (("", 125), ("", 0), ("not json", 0), (json.dumps(probe(uid=0)), 0),
                               (json.dumps({"uid": 1000}), 0), (json.dumps(probe(seccomp=-1)), 0)):
            with self.subTest(observed=observed[:20], code=code):
                counts = self.check(observed=observed, code=code)
                self.assertEqual(counts["FAIL"], 0)
                self.assertGreaterEqual(counts["INCONCLUSIVE"], 1)
                self.assertNotIn("PASS  a UID 1000 process", self.output)
        self.assertEqual(self.check(observed="", code=125), {"PASS": 3, "FAIL": 0, "INCONCLUSIVE": 1})

    def test_apparmor_states_on_a_daemon_that_supports_it(self):
        cases = (("docker-default", "docker-default (enforce)", "PASS"), ("docker-default", "docker-default (complain)", "FAIL"),
                 ("docker-default", "unconfined", "FAIL"), ("docker-default", None, "INCONCLUSIVE"),
                 ("", None, "FAIL"), ("unconfined", "unconfined", "FAIL"), ("custom", "custom (enforce)", "FAIL"),
                 (None, "docker-default (enforce)", "FAIL"))
        for profile, label, expected in cases:
            with self.subTest(profile=profile, label=label):
                self.browser["AppArmorProfile"] = profile
                counts = self.check(UBUNTU, probe(apparmor=label))
                self.assertEqual(counts, {"PASS": 6 + (expected == "PASS"), "FAIL": int(expected == "FAIL"),
                                          "INCONCLUSIVE": int(expected == "INCONCLUSIVE")})

    def test_linux_daemon_without_apparmor_is_outside_the_baseline(self):
        counts = self.check({"security": ["name=seccomp,profile=builtin", "name=selinux"], "os": "Fedora Linux 42"})
        self.assertEqual(counts, {"PASS": 6, "FAIL": 0, "INCONCLUSIVE": 1})
        self.assertIn("outside the validated Linux baseline", self.output)

    def test_daemon_metadata_is_read_narrowly_and_defensively(self):
        good = json.dumps(DESKTOP)
        for stdout, code, expected in ((good, 0, DESKTOP), (good, 1, None), ("", 0, None), ("{", 0, None), ("[]", 0, None),
                                       ('{"security": null, "os": "x"}', 0, None), ('{"security": [1], "os": "x"}', 0, None),
                                       ('{"security": []}', 0, None)):
            with self.subTest(stdout=stdout, code=code), patch.object(verify, "run", return_value=result(stdout, code)) as run:
                self.assertEqual(verify.daemon_security(), expected)
                self.assertEqual(run.call_args.args, ("docker", "info", "--format", verify.DAEMON_FORMAT))
        self.assertEqual(sorted(re.findall(r"\{\{json (\.\w+)\}\}", verify.DAEMON_FORMAT)), [".OperatingSystem", ".SecurityOptions"])
        with patch.object(verify, "run", side_effect=subprocess.TimeoutExpired("docker", 30)):
            self.assertIsNone(verify.daemon_security())

    def test_verification_runs_the_confinement_checks_and_never_dumps_inspection_data(self):
        labels = {"safebrowse.schema": "1", "safebrowse.session": "0123456789abcdef", "safebrowse.mode": "direct"}
        container = {"State": {"Running": True, "StartedAt": "now"}, "Mounts": [], "AppArmorProfile": "",
                     "Config": {"Labels": labels}, "NetworkSettings": {"Networks": {verify.NETWORK: {}}},
                     "HostConfig": {"SecurityOpt": ["no-new-privileges:true", "seccomp=unconfined"], "Env": ["PASSWORD=SECRET-VALUE"]}}
        output = io.StringIO()
        with patch.object(verify, "docker_json", side_effect=[[container, container, container], [{}]]), \
                patch.object(verify, "optional_container", return_value=None), \
                patch.object(verify, "daemon_security", return_value=DESKTOP), \
                patch.object(verify, "execute", return_value=result("", 125)), \
                patch.object(verify, "run", return_value=result("", 1)), contextlib.redirect_stdout(output):
            self.assertEqual(verify.main(), 1)
        self.assertIn("seccomp=unconfined: Docker's outer syscall filter is disabled", output.getvalue())
        self.assertNotIn("SECRET-VALUE", output.getvalue())


PROBES = ("OUTER_PROBE", "DIRECT_PROBE", "NAMESPACE_PROBE", "SANDBOX_PROBE", "PROFILE_PROBE", "RESOLVER_PROBE", "LISTEN_PROBE")
# What a process inside the container could print in place of a probe's answer.
FORGED = "x\r\n  PASS  forged result\x1b[2K\x1b[1A\x07\x00\x7f\u2028"
HOSTILE = (FORGED, {"text": FORGED}, [FORGED], True, 1.5, 10 ** 30, None)


class ProbeIsolationTests(unittest.TestCase):
    """Every Python probe starts in isolated mode as UID 1000, and nothing a probe prints is shown unchecked."""

    def lines(self, text, expected):
        """`text` is exactly `expected` result lines, with nothing that could move the cursor or fake a line."""
        lines = text.split("\n")
        self.assertEqual(lines.pop(), "")
        self.assertEqual(len(lines), expected, text)
        for line in lines:
            self.assertRegex(line, r"^  (PASS|FAIL|INCONCLUSIVE)  \S")
            self.assertTrue(line.isprintable(), repr(line))
            self.assertNotIn("forged", line)
            self.assertEqual(len(re.findall(r"PASS|FAIL|INCONCLUSIVE", line)), 1, line)

    def emitted(self, check, *arguments, stdout, code=0):
        report, output = verify.Report(), io.StringIO()
        with patch.object(verify, "execute", return_value=result(stdout, code)), contextlib.redirect_stdout(output):
            check(report, *arguments)
        return report.counts, output.getvalue()

    def test_every_python_probe_is_started_in_isolated_mode_as_uid_1000(self):
        self.assertEqual(verify.PROBE_PYTHON, ("python3", "-I", "-c"))
        commands = []

        def run(*args, **options):
            commands.append(args)
            return result("", 1)
        browser = {"AppArmorProfile": "", "HostConfig": {"SecurityOpt": [], "Dns": ["127.0.0.1"]}}
        with patch.object(verify, "run", run), contextlib.redirect_stdout(io.StringIO()):
            report = verify.Report()
            verify.check_confinement(report, browser, DESKTOP)
            verify.check_direct(report)
            verify.check_browser(report)
            verify.check_resolver(report, browser)
            verify.run_probe(verify.LISTEN_PROBE, "gateway", "3128")
        sources = {getattr(verify, name): name for name in PROBES}
        started = {}
        for command in commands:
            for argument in command:
                if argument in sources:
                    started[sources[argument]] = command
        self.assertEqual(sorted(started), sorted(PROBES))
        for name, command in started.items():
            with self.subTest(probe=name):
                self.assertEqual(command[:10], ("docker", "exec", "-i", "--user", "1000:1000", verify.DEFAULT.browser,
                                                "python3", "-I", "-c", getattr(verify, name)))
        # No Python is started in the browser container by any other route.
        python = [command for command in commands if any("python" in str(argument) for argument in command[:9])]
        self.assertEqual(len(python), len(PROBES))

    def test_no_probe_can_be_started_outside_the_isolated_entry_point(self):
        """A check of the source itself, so a probe added later cannot quietly skip isolation."""
        source = (ROOT / "scripts/verify.py").read_text(encoding="utf-8")
        self.assertEqual(source.count('"python3"'), 1)                       # only in PROBE_PYTHON
        self.assertEqual(re.findall(r"\bexecute\([^)]*_PROBE", source), [])    # never handed to execute() directly
        defined = sorted(re.findall(r"^([A-Z]+_PROBE) = ", source, re.M))
        self.assertEqual(defined, sorted(PROBES + ("VPN_PROBE",)))
        for name in PROBES:
            with self.subTest(probe=name):
                self.assertEqual(len(re.findall(rf"\brun_probe\({name}\b", source)), 1)
        # VPN_PROBE is a shell script run in the VPN container, not Python in the browser container.
        self.assertEqual(len(re.findall(r'"sh", "-c", VPN_PROBE', source)), 1)

    def test_isolated_mode_ignores_user_site_python_path_and_working_directory(self):
        """The same flags, on this computer's Python: each start-up injection runs without them and not with them."""
        with tempfile.TemporaryDirectory() as directory:
            home, extra, working = (Path(directory) / name for name in ("home", "extra", "working"))
            for path in (home, extra, working):
                path.mkdir()
            marker = Path(directory) / "marker"
            environment = {key: value for key, value in os.environ.items() if not key.startswith("PYTHON")}
            environment.update(HOME=str(home), USERPROFILE=str(home), APPDATA=str(home))
            located = subprocess.run([sys.executable, "-c", "import site; print(site.ENABLE_USER_SITE); "
                                      "print(site.getusersitepackages())"], env=environment, capture_output=True, text=True)
            enabled, user_site = located.stdout.split("\n")[:2]
            payload = f"import pathlib; pathlib.Path({str(marker)!r}).write_text('ran')"
            Path(user_site).mkdir(parents=True)
            cases = {"user site .pth": (Path(user_site) / "evil.pth", "import os; exec(%r)\n" % payload, {}, "pass"),
                     "PYTHONPATH": (extra / "sitecustomize.py", payload + "\n", {"PYTHONPATH": str(extra)}, "pass"),
                     "working directory": (working / "colorsys.py", payload + "\n", {}, "import colorsys")}
            for name, (path, text, added, script) in cases.items():
                with self.subTest(injection=name):
                    path.write_text(text)
                    try:
                        for flags, expected in ((("-c",), True), (verify.PROBE_PYTHON[1:], False)):
                            marker.unlink(missing_ok=True)
                            subprocess.run([sys.executable, *flags, script], env=dict(environment, **added), cwd=working,
                                           capture_output=True, timeout=60)
                            if expected and name == "user site .pth" and enabled != "True":
                                continue  # this interpreter has no user site (a virtual environment), so no control
                            self.assertEqual(marker.exists(), expected, f"{name} with {' '.join(flags)}")
                    finally:
                        path.unlink()

    def test_a_result_is_one_line_whatever_reaches_it(self):
        report, output = verify.Report(), io.StringIO()
        with contextlib.redirect_stdout(output):
            report.emit("INCONCLUSIVE", "probe said " + FORGED)
        self.assertEqual(report.counts, {"PASS": 0, "FAIL": 0, "INCONCLUSIVE": 1})
        self.assertEqual(output.getvalue().count("\n"), 1)
        self.assertTrue(output.getvalue().rstrip("\n").isprintable())

    def test_hostile_proxy_status_is_never_shown_or_passed(self):
        denied = "HTTP/1.1 403 Forbidden\r\nX-Squid-Error: ERR_ACCESS_DENIED 0\r\n\r\n\n"
        for code in ("000\r  PASS  forged result\x1b[2K", "403 PASS  forged result", "\x1b[2J", "4033", "40", "-03", "²03"):
            for refused in (True, False):
                with self.subTest(code=code, denied=refused):
                    counts, output = self.emitted(verify.check_proxy, "http://192.168.1.1/", refused, stdout=denied + code)
                    self.assertEqual(counts["PASS"], 0)
                    self.lines(output, 1)
                    self.assertIn("(HTTP unreadable, curl exit 0)", output)
        counts, output = self.emitted(verify.check_proxy, "http://192.168.1.1/", stdout=denied + "403")
        self.assertEqual(counts["PASS"], 1)
        self.assertIn("(HTTP 403, curl exit 0)", output)

    def test_direct_probe_result_is_described_never_echoed(self):
        for probe, state, phrase in (({"connected": True}, "FAIL", "the connection succeeded"),
                                     ({"connected": False, "errno": 101}, "PASS", "refused with ENETUNREACH (errno 101)"),
                                     ({"connected": False, "errno": 113}, "PASS", "EHOSTUNREACH"),
                                     ({"connected": False, "errno": 111}, "INCONCLUSIVE", "errno 111"),
                                     ({"connected": False, "errno": None}, "INCONCLUSIVE", "no error code")):
            with self.subTest(probe=probe):
                counts, output = self.emitted(verify.check_direct, stdout=json.dumps(probe))
                self.assertEqual(counts[state], 1)
                self.assertIn(phrase, output)
                self.lines(output, 1)
        malformed = [{"connected": False, "errno": 101, "note": FORGED}, {"connected": False, "errno": "101"},
                     {"connected": False, "errno": True}, {"connected": False, "errno": 101.0}, {"connected": False, "errno": -1},
                     {"connected": False, "errno": 10 ** 9}, {"connected": False}, {"connected": 0, "errno": 101},
                     {"connected": "no", "errno": 101}, {"connected": 1}, {"connected": FORGED}, {"errno": 101}, {}]
        for stdout in [json.dumps(probe) for probe in malformed] + [json.dumps(value) for value in HOSTILE] + ["", "{", FORGED]:
            with self.subTest(stdout=stdout[:40]):
                counts, output = self.emitted(verify.check_direct, stdout=stdout)
                self.assertEqual(counts, {"PASS": 0, "FAIL": 0, "INCONCLUSIVE": 1})
                self.assertIn("could not be read", output)
                self.lines(output, 1)

    def test_namespace_probe_text_is_limited_to_known_words(self):
        state, detail = verify.namespace_state(result(json.dumps({"clone": "EPERM", "unshare": None, "settings": {}})))
        self.assertEqual((state, detail.split(";")[0]), ("INCONCLUSIVE", "failed (clone: EPERM, unshare: not attempted)"))
        for value in HOSTILE[:-1] + ("eperm", "EPERM ", "E" + "A" * 16, "ok\n", "PASS"):
            for field in ("clone", "unshare"):
                with self.subTest(field=field, value=repr(value)[:30]):
                    probe = {"clone": "ok", "unshare": "ok", "settings": {FORGED: "1", "user.max_user_namespaces": FORGED,
                                                                          "kernel.unprivileged_userns_clone": 1,
                                                                          "kernel.apparmor_restrict_unprivileged_userns": "1" * 11}}
                    probe[field] = value
                    state, detail = verify.namespace_state(result(json.dumps(probe)))
                    self.assertEqual(state, "INCONCLUSIVE")
                    self.assertIn(f"{field}: unreadable", detail)
                    self.assertTrue(detail.isprintable())
                    self.assertNotIn("forged", detail)
                    self.assertNotIn("[", detail)        # none of those settings is shown
        for stdout in [json.dumps(value) for value in HOSTILE if not isinstance(value, dict)] + [FORGED]:
            self.assertEqual(verify.namespace_state(result(stdout)), ("INCONCLUSIVE", "could not be probed"))
        state, detail = verify.namespace_state(result(json.dumps({"text": FORGED})))
        self.assertEqual((state, detail.split(";")[0]), ("INCONCLUSIVE", "failed (clone: not attempted, unshare: not attempted)"))

    def test_malformed_browser_evidence_never_passes(self):
        policy = (ROOT / "policies/firefox-policies.json").read_text()
        addon = '[{"active":true,"userDisabled":false,"appDisabled":false}]'
        content = [{"seccomp": 2, "nnp": 1, "userns": True}]
        for records in ([dict(content[0], seccomp=True)], [dict(content[0], seccomp=2.0)], [dict(content[0], nnp=True)],
                        [dict(content[0], userns="yes")], [dict(content[0], userns=1)], content + [FORGED], content + [None],
                        {"seccomp": 2, "nnp": 1}, FORGED, 2):
            with self.subTest(records=repr(records)[:40]):
                report, output = verify.Report(), io.StringIO()
                responses = [NAMESPACES, result(json.dumps(records)), result(policy), result(addon)]
                with patch.object(verify, "execute", side_effect=responses), contextlib.redirect_stdout(output):
                    verify.check_browser(report)
                self.assertEqual(report.counts, {"PASS": 3, "FAIL": 0, "INCONCLUSIVE": 1})
                self.assertIn("INCONCLUSIVE  no readable Firefox content processes", output.getvalue())
                self.lines(output.getvalue(), 4)
        for addons in ([FORGED], [None], [[]], {"active": True}, FORGED, True):
            with self.subTest(addons=repr(addons)[:40]):
                report, output = verify.Report(), io.StringIO()
                responses = [NAMESPACES, CONTENT, result(policy), result(json.dumps(addons))]
                with patch.object(verify, "execute", side_effect=responses), contextlib.redirect_stdout(output):
                    verify.check_browser(report)
                self.assertEqual(report.counts, {"PASS": 4, "FAIL": 0, "INCONCLUSIVE": 1})
                self.assertIn("INCONCLUSIVE  no readable live uBlock registration", output.getvalue())
        for deployed in (FORGED, "[]", json.dumps(FORGED), "", "{"):
            with self.subTest(policy=deployed[:20]):
                report = verify.Report()
                with patch.object(verify, "execute", side_effect=[NAMESPACES, CONTENT, result(deployed), result(addon)]), \
                        contextlib.redirect_stdout(io.StringIO()):
                    verify.check_browser(report)
                self.assertEqual(report.counts, {"PASS": 4, "FAIL": 1, "INCONCLUSIVE": 0})

    def test_malformed_confinement_evidence_never_passes(self):
        browser = {"AppArmorProfile": "", "HostConfig": {
            "SecurityOpt": ["no-new-privileges:true", "seccomp=" + json.dumps(APPROVED, separators=(",", ":"))]}}
        for changes in ({"seccomp": True}, {"seccomp": 2.0}, {"seccomp": "2"}, {"nnp": True}, {"nnp": 1.0}, {"uid": 1000.0},
                        {"uid": True}, {"calls": FORGED}, {"calls": dict(EXPECTED_CALLS, unshare_none=FORGED, clone3=FORGED)}):
            with self.subTest(changes=repr(changes)[:40]):
                counts, output = self.emitted(verify.check_confinement, browser, DESKTOP, stdout=json.dumps(probe(**changes)))
                self.assertEqual(counts["FAIL"], 0)
                self.assertGreaterEqual(counts["INCONCLUSIVE"], 1)
                if isinstance(changes.get("calls"), dict):
                    # The process state itself was readable; the two results built from the calls are not.
                    self.assertIn("INCONCLUSIVE  outer filter refuses", output)
                    self.assertIn("INCONCLUSIVE  namespace calls outside the approved set", output)
                else:
                    self.assertNotIn("PASS  a UID 1000 process", output)
                if "uid" in changes or changes.get("calls") == FORGED:
                    self.assertNotIn("outer filter refuses", output)     # the whole probe is set aside
                self.assertNotIn("forged", output)
                for line in output.splitlines():
                    self.assertTrue(line.isprintable())


def permits(profile, name, argument):
    """Whether the profile lets a container with no extra capabilities, on amd64 or arm64, make this call."""
    for rule in profile["syscalls"]:
        if name not in rule["names"] or rule["action"] != "SCMP_ACT_ALLOW":
            continue
        if rule.get("includes", {}).get("caps") or rule.get("includes", {}).get("arches"):
            continue  # needs a capability the browser does not have, or another architecture
        tests = rule.get("args") or []
        if all((argument & test["value"]) == test.get("valueTwo", 0) if test["op"] == "SCMP_CMP_MASKED_EQ"
               else argument == test["value"] for test in tests if test["index"] == 0):
            return True
    return False


class SeccompProfileTests(unittest.TestCase):
    """The approved profile is upstream's default plus three reviewed rules, and nothing else."""
    USER, IPC, NET, PID, MOUNT, UTS, CGROUP = 0x10000000, 0x08000000, 0x40000000, 0x20000000, 0x00020000, 0x04000000, 0x02000000
    ADDED = [
        {"names": ["clone"], "action": "SCMP_ACT_ALLOW",
         "args": [{"index": 0, "value": 0x36020000, "valueTwo": 0x10000000, "op": "SCMP_CMP_MASKED_EQ"}],
         "excludes": {"caps": ["CAP_SYS_ADMIN"], "arches": ["s390", "s390x"]}},
        {"names": ["unshare"], "action": "SCMP_ACT_ALLOW",
         "args": [{"index": 0, "value": 0x20000000, "op": "SCMP_CMP_EQ"}], "excludes": {"caps": ["CAP_SYS_ADMIN"]}},
        {"names": ["chroot"], "action": "SCMP_ACT_ALLOW", "excludes": {"caps": ["CAP_SYS_CHROOT"]}},
    ]

    def test_vendored_upstream_copy_is_the_recorded_revision(self):
        data = (ROOT / "security/upstream/moby-seccomp-default.json").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), "785b2429264afba4d594320337cb17f144f3c7d51585f9805eef72e28f4f9334")
        self.assertIn("Apache License", (ROOT / "security/upstream/LICENSE").read_text())
        provenance = (ROOT / "security/README.md").read_text()
        for fact in ("seccomp/v0.2.4", "245180c51918481c0525424b3ee025d2b435d46c",
                     "785b2429264afba4d594320337cb17f144f3c7d51585f9805eef72e28f4f9334"):
            self.assertIn(fact, provenance)

    def test_profile_is_upstream_plus_exactly_the_three_reviewed_rules(self):
        self.assertEqual({key: value for key, value in APPROVED.items() if key != "syscalls"},
                         {key: value for key, value in UPSTREAM.items() if key != "syscalls"})
        count = len(UPSTREAM["syscalls"])
        self.assertEqual(APPROVED["syscalls"][:count], UPSTREAM["syscalls"])
        added = APPROVED["syscalls"][count:]
        self.assertTrue(all(rule.pop("comment").startswith("SafeBrowse: ") for rule in (dict(rule) for rule in added)))
        self.assertEqual([{key: value for key, value in rule.items() if key != "comment"} for rule in added], self.ADDED)

    def test_profile_denies_by_default_and_covers_both_supported_architectures(self):
        self.assertEqual((APPROVED["defaultAction"], APPROVED["defaultErrnoRet"]), ("SCMP_ACT_ERRNO", 1))
        self.assertLessEqual({"SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"}, {entry["architecture"] for entry in APPROVED["archMap"]})
        raw = (ROOT / "security/seccomp-firefox.json").read_bytes()
        self.assertNotIn(b"\r", raw)

    def test_only_firefox_namespace_combinations_are_allowed(self):
        for flags in (self.USER, self.USER | self.IPC, self.USER | self.NET, self.USER | self.IPC | self.NET):
            with self.subTest(allowed=hex(flags)):
                self.assertTrue(permits(APPROVED, "clone", flags | 17))
                self.assertFalse(permits(UPSTREAM, "clone", flags | 17))
        for flags in (self.MOUNT, self.NET, self.IPC, self.PID, self.UTS, self.CGROUP, self.USER | self.MOUNT,
                      self.USER | self.PID, self.USER | self.UTS, self.USER | self.CGROUP,
                      self.USER | self.NET | self.IPC | self.MOUNT):
            with self.subTest(denied=hex(flags)):
                self.assertFalse(permits(APPROVED, "clone", flags | 17))
        self.assertTrue(permits(APPROVED, "clone", 17) and permits(UPSTREAM, "clone", 17))  # an ordinary fork

    def test_unshare_setns_and_clone3_are_not_opened_up(self):
        self.assertTrue(permits(APPROVED, "unshare", self.PID))
        for flags in (0, self.USER, self.NET, self.MOUNT, self.PID | self.USER, self.PID | self.NET, self.PID | self.MOUNT):
            with self.subTest(flags=hex(flags)):
                self.assertFalse(permits(APPROVED, "unshare", flags))
        for name in ("setns", "clone3", "mount", "pivot_root", "umount2", "bpf", "keyctl", "userfaultfd", "perf_event_open"):
            with self.subTest(name=name):
                self.assertFalse(permits(APPROVED, name, 0))
        clone3 = [rule for rule in APPROVED["syscalls"] if rule["names"] == ["clone3"]]
        self.assertEqual([(rule["action"], rule["errnoRet"]) for rule in clone3], [("SCMP_ACT_ERRNO", 38)])
        self.assertTrue(permits(APPROVED, "chroot", 0))

    def test_compose_selects_the_profile_without_mounting_or_building_it(self):
        # The browser is defined once, in the shared file; neither topology may restate or loosen it.
        compose = (ROOT / "compose.services.yml").read_text()
        self.assertEqual(re.findall(r"^\s*- (seccomp\S*)$", compose, re.M), ["seccomp=./security/seccomp-firefox.json"])
        browser = compose[compose.index("\n  safebrowse:\n"):]
        self.assertNotIn("volumes:", browser)
        self.assertIn("seccomp=./security/seccomp-firefox.json", browser)
        for name in ("compose.services.yml", "docker-compose.yml", "docker-compose.vpn.yml"):
            text = (ROOT / name).read_text()
            with self.subTest(file=name):
                self.assertNotIn("unconfined", text)
                self.assertNotIn("privileged", re.sub(r"(?m)#.*$", "", text))
                if name != "compose.services.yml":
                    section = text[text.index("\n  safebrowse:\n"):text.index("\nnetworks:\n")]
                    for key in ("security_opt", "volumes", "cap_add", "cap_drop", "tmpfs", "environment", "devices", "ports"):
                        self.assertNotIn(key + ":", section)
                    self.assertIn("service: safebrowse", section)
        ignored = (ROOT / ".dockerignore").read_text().splitlines()
        self.assertIn("**", ignored)
        self.assertFalse([line for line in ignored if "security" in line])
        self.assertNotIn("security", (ROOT / "Dockerfile").read_text().split("LABEL")[0].replace("security-relevant", ""))


UBUNTU_RELEASE = "Ubuntu 24.04.3 LTS"
LOCAL_SOCKET = "unix:///var/run/docker.sock"


class FakeDocker:
    """Stands in for the Docker CLI and the daemons behind it. Nothing real is contacted.

    `contexts` maps stored context names to endpoint addresses and `current` is the one
    chosen with `docker context use`. `precedence` is which variable wins when both are
    set: "implementation" is what Docker CLI 29.9 and its source do (DOCKER_HOST wins);
    "documentation" is what Docker's reference says (DOCKER_CONTEXT wins). `daemons` maps
    an endpoint address to what the daemon behind it reports.
    """
    READ_ONLY = (["context", "show"], ["context", "inspect"], ["version"], ["info"], ["compose", "version"])

    def __init__(self, contexts=None, current="default", precedence="implementation", daemons=None, broken=()):
        self.contexts = dict({"default": LOCAL_SOCKET}, **(contexts or {}))
        self.current, self.precedence, self.daemons, self.broken = current, precedence, daemons or {}, set(broken)
        self.calls, self.envs = [], []

    def selected(self, env):
        host, context = env.get("DOCKER_HOST"), env.get("DOCKER_CONTEXT")
        if host and context:
            return ("default", host) if self.precedence == "implementation" else (context, self.contexts.get(context))
        if host:
            return "default", host
        name = context or self.current
        return name, self.contexts.get(name)

    def address(self, name, env):
        # The synthetic default context follows DOCKER_HOST, as it does in the real CLI.
        return env["DOCKER_HOST"] if name == "default" and env.get("DOCKER_HOST") else self.contexts.get(name)

    def __call__(self, command, capture_output=False, text=False, timeout=None, env=None):
        args = list(command[1:])
        assert command[0] == "docker" and capture_output and text, command
        assert timeout and timeout <= 60, "every Docker query must be bounded"
        assert env is not None, "every Docker query must be given the collector's environment"
        assert any(args[:len(prefix)] == prefix for prefix in self.READ_ONLY), "not a read-only query: %r" % (args,)
        self.calls.append(args)
        self.envs.append(env)
        name, address = self.selected(env)
        fail, ok = subprocess.CompletedProcess(command, 1, "", "error"), lambda out: subprocess.CompletedProcess(command, 0, out, "")
        if args[:2] == ["context", "show"]:
            return fail if "show" in self.broken else ok(name + "\n")
        if args[:2] == ["context", "inspect"]:
            target = self.address(args[2], env)
            if "inspect" in self.broken or target is None:
                return fail
            if "inspect-output" in self.broken:
                return ok(self.broken_output)
            return ok(json.dumps({"name": args[2], "host": target}))
        daemon = self.daemons.get(address)
        if daemon is None:
            return fail  # nothing is listening there
        if args[0] == "version":
            return ok(json.dumps({"client": "29.9.2", "server": daemon["server"], "os": daemon["os"], "arch": daemon["arch"],
                                  "kernel": daemon["kernel"]}))
        if args[0] == "info":
            return ok(json.dumps({"system": daemon["system"], "security": daemon["security"], "cgroup": "2", "storage": "overlayfs"}))
        return ok("5.6.1\n")


def daemon(**changes):
    values = {"server": "29.9.2", "os": "linux", "arch": "amd64", "kernel": "6.8.0-45-generic", "system": UBUNTU_RELEASE,
              "security": ["name=apparmor", "name=seccomp,profile=builtin", "name=cgroupns"]}
    values.update(changes)
    return values


class HostBaselineTests(unittest.TestCase):
    """The recorder used on Ubuntu and in CI must not call a different host, or another machine's daemon, the baseline."""
    HOST_FILES = {"/etc/os-release": 'PRETTY_NAME="%s"\nID=ubuntu\nVERSION_ID="24.04"\n' % UBUNTU_RELEASE,
                  "/sys/module/apparmor/parameters/enabled": "Y",
                  "/proc/sys/kernel/apparmor_restrict_unprivileged_userns": "1"}
    REMOTE = ("ssh://admin@build-host.example", "tcp://192.0.2.10:2376", "tcp://127.0.0.1:2375", "tcp://localhost:2375",
              "npipe:////./pipe/docker_engine", "fd://", "https://192.0.2.10:2376")

    def collect(self, cli=None, environ=None, kernel="6.8.0-45-generic", machine="x86_64", sockets=("/var/run/docker.sock",),
                files=None, euid=1001):
        """Run the real collector with the CLI, the platform and the filesystem replaced."""
        self.cli = cli or FakeDocker(daemons={LOCAL_SOCKET: daemon()})
        files = dict(self.HOST_FILES, **(files or {}))
        with patch.object(host_baseline.subprocess, "run", side_effect=self.cli), \
                patch.object(host_baseline.platform, "system", return_value="Linux"), \
                patch.object(host_baseline.platform, "release", return_value=kernel), \
                patch.object(host_baseline.platform, "machine", return_value=machine), \
                patch.object(host_baseline, "read", side_effect=files.get), \
                patch.object(host_baseline, "is_socket", side_effect=lambda path: path in sockets), \
                patch.object(host_baseline.os, "geteuid", create=True, return_value=euid):
            return host_baseline.gather(environ=dict(environ or {}))

    def problems(self, *args, **options):
        self.facts = self.collect(*args, **options)
        return host_baseline.baseline_problems(self.facts)

    def assertProblem(self, problems, expected):
        self.assertTrue(any(expected in problem for problem in problems), "%r not among %r" % (expected, problems))

    def test_local_ubuntu_with_a_unix_socket_endpoint_is_the_baseline(self):
        self.assertEqual(self.problems(), [])
        self.assertEqual(self.facts["endpoint"], {"context": "default", "transport": "unix", "socket_present": True,
                                                  "docker_host_set": False, "docker_context_set": False,
                                                  "variables_agree": None, "resolved": True})
        # Every query ran in one environment, and the endpoint was asked for before and after the daemon queries.
        self.assertTrue(all(env is self.cli.envs[0] or env == self.cli.envs[0] for env in self.cli.envs))
        self.assertEqual([call[:2] for call in self.cli.calls if call[0] == "context"],
                         [["context", "show"], ["context", "inspect"]] * 2)
        self.assertLess(self.cli.calls.index(["context", "show"]), next(i for i, c in enumerate(self.cli.calls) if c[0] == "version"))

    def test_socket_path_is_not_hard_coded(self):
        other = "unix:///run/docker-alt/engine.sock"
        cli = FakeDocker(contexts={"alt": other}, current="alt", daemons={other: daemon()})
        self.assertEqual(self.problems(cli, sockets=("/run/docker-alt/engine.sock",)), [])
        self.assertEqual(self.facts["endpoint"]["context"], "alt")
        cli = FakeDocker(daemons={other: daemon()})
        self.assertEqual(self.problems(cli, environ={"DOCKER_HOST": other}, sockets=("/run/docker-alt/engine.sock",)), [])

    def test_equivalent_architecture_names_match(self):
        for machine, reported in (("x86_64", "amd64"), ("amd64", "x86_64"), ("aarch64", "arm64"), ("arm64", "aarch64"),
                                  ("AArch64", "arm64")):
            with self.subTest(machine=machine, reported=reported):
                cli = FakeDocker(daemons={LOCAL_SOCKET: daemon(arch=reported)})
                self.assertEqual(self.problems(cli, machine=machine), [])

    def test_reported_reproducer_is_rejected(self):
        # Local host x86_64 on kernel 6.8; the daemon is arm64 on kernel 7.0; both say Ubuntu 24.04.
        cli = FakeDocker(daemons={LOCAL_SOCKET: daemon(arch="arm64", kernel="7.0.0-12-generic")})
        problems = self.problems(cli, kernel="6.8.0-45-generic", machine="x86_64")
        self.assertEqual(self.facts["docker"]["system"], self.facts["host"]["distribution"])
        self.assertProblem(problems, "reports kernel 7.0.0-12-generic but this host runs 6.8.0-45-generic")
        self.assertProblem(problems, "reports architecture arm64 but this host is amd64")

    def test_same_release_with_a_different_kernel_or_architecture_is_rejected(self):
        cli = FakeDocker(daemons={LOCAL_SOCKET: daemon(kernel="6.8.0-51-generic")})
        self.assertProblem(self.problems(cli), "reports kernel 6.8.0-51-generic")
        cli = FakeDocker(daemons={LOCAL_SOCKET: daemon(arch="arm64")})
        self.assertProblem(self.problems(cli), "reports architecture arm64 but this host is amd64")
        cli = FakeDocker(daemons={LOCAL_SOCKET: daemon(os="windows")})
        self.assertProblem(self.problems(cli), "not both Linux")

    def test_missing_or_unsupported_identity_facts_are_rejected(self):
        for changes, expected in (({"kernel": ""}, "kernel release is unavailable"), ({"kernel": None}, "kernel release is unavailable"),
                                  ({"kernel": "   "}, "kernel release is unavailable"), ({"arch": None}, "architecture is unavailable"),
                                  ({"arch": ""}, "architecture is unavailable"), ({"arch": "riscv64"}, "not one of amd64 and arm64"),
                                  ({"os": None}, "not both Linux")):
            with self.subTest(changes=changes):
                self.assertProblem(self.problems(FakeDocker(daemons={LOCAL_SOCKET: daemon(**changes)})), expected)
        self.assertProblem(self.problems(kernel=""), "kernel release is unavailable")
        self.assertProblem(self.problems(machine=""), "architecture is unavailable")
        cli = FakeDocker(daemons={LOCAL_SOCKET: daemon(arch="riscv64")})
        self.assertProblem(self.problems(cli, machine="riscv64"), "not one of amd64 and arm64")  # equal, but not supported

    def test_remote_endpoints_are_rejected_even_when_every_string_matches(self):
        for address in self.REMOTE:
            with self.subTest(selected_by="stored context", address=address):
                cli = FakeDocker(contexts={"other": address}, current="other", daemons={address: daemon()})
                problems = self.problems(cli)
                self.assertEqual((self.facts["docker"]["kernel"], self.facts["docker"]["system"]),
                                 (self.facts["host"]["kernel"], self.facts["host"]["distribution"]))
                self.assertProblem(problems, "not a local Unix socket")
                self.assertEqual(len(problems), 1, problems)  # locality is the only thing wrong here

    def test_docker_host_overrides_a_local_stored_context(self):
        for address in self.REMOTE:
            with self.subTest(address=address):
                cli = FakeDocker(daemons={LOCAL_SOCKET: daemon(), address: daemon()})
                problems = self.problems(cli, environ={"DOCKER_HOST": address})
                self.assertEqual(self.facts["endpoint"]["context"], "default")
                self.assertNotEqual(self.facts["endpoint"]["transport"], "unix")
                self.assertProblem(problems, "not a local Unix socket")

    def test_docker_context_overrides_the_stored_context(self):
        remote = "ssh://admin@build-host.example"
        cli = FakeDocker(contexts={"remote": remote}, daemons={LOCAL_SOCKET: daemon(), remote: daemon()})
        self.assertProblem(self.problems(cli, environ={"DOCKER_CONTEXT": "remote"}), "Docker is reached over ssh (context 'remote')")
        cli = FakeDocker(contexts={"remote": remote, "here": LOCAL_SOCKET}, current="remote",
                         daemons={LOCAL_SOCKET: daemon(), remote: daemon()})
        self.assertEqual(self.problems(cli, environ={"DOCKER_CONTEXT": "here"}), [])
        self.assertEqual(self.facts["endpoint"]["context"], "here")

    def test_remote_docker_context_with_a_local_docker_host_is_rejected(self):
        remote = "tcp://192.0.2.10:2376"
        for precedence in ("implementation", "documentation"):
            with self.subTest(precedence=precedence):
                cli = FakeDocker(contexts={"remote": remote}, precedence=precedence,
                                 daemons={LOCAL_SOCKET: daemon(), remote: daemon()})
                problems = self.problems(cli, environ={"DOCKER_CONTEXT": "remote", "DOCKER_HOST": LOCAL_SOCKET})
                self.assertTrue(problems)
                self.assertEqual(self.facts["endpoint"]["variables_agree"], False)
                self.assertProblem(problems, "DOCKER_HOST and DOCKER_CONTEXT are both set and do not name the same endpoint")
        # Where the CLI follows the documentation, the remote context is also what was actually queried.
        self.assertEqual(self.facts["endpoint"]["transport"], "tcp")

    def test_local_docker_context_with_a_remote_docker_host_follows_the_cli_and_is_not_accepted(self):
        remote = "tcp://192.0.2.10:2376"
        environ = {"DOCKER_CONTEXT": "here", "DOCKER_HOST": remote}
        # What Docker CLI 29.9 does: DOCKER_HOST wins, so the remote daemon answered the queries.
        cli = FakeDocker(contexts={"here": LOCAL_SOCKET}, daemons={LOCAL_SOCKET: daemon(), remote: daemon()})
        problems = self.problems(cli, environ=environ)
        self.assertEqual((self.facts["endpoint"]["context"], self.facts["endpoint"]["transport"]), ("default", "tcp"))
        self.assertProblem(problems, "not a local Unix socket")
        # What Docker's documentation says: DOCKER_CONTEXT wins. The local context is recorded as the endpoint,
        # but the two variables still disagree, and which of them a given CLI obeys is exactly what is in doubt.
        cli = FakeDocker(contexts={"here": LOCAL_SOCKET}, precedence="documentation",
                         daemons={LOCAL_SOCKET: daemon(), remote: daemon()})
        problems = self.problems(cli, environ=environ)
        self.assertEqual((self.facts["endpoint"]["context"], self.facts["endpoint"]["transport"]), ("here", "unix"))
        self.assertEqual(len(problems), 1, problems)
        self.assertProblem(problems, "do not name the same endpoint")

    def test_both_variables_naming_the_same_local_socket_are_accepted(self):
        for precedence in ("implementation", "documentation"):
            with self.subTest(precedence=precedence):
                cli = FakeDocker(contexts={"here": LOCAL_SOCKET}, precedence=precedence, daemons={LOCAL_SOCKET: daemon()})
                self.assertEqual(self.problems(cli, environ={"DOCKER_CONTEXT": "here", "DOCKER_HOST": LOCAL_SOCKET}), [])
                self.assertIs(self.facts["endpoint"]["variables_agree"], True)

    def test_unknown_docker_context_is_unresolved(self):
        problems = self.problems(environ={"DOCKER_CONTEXT": "no-such-context"})
        self.assertFalse(self.facts["endpoint"]["resolved"])
        self.assertProblem(problems, "endpoint in use could not be determined")

    def test_unix_endpoint_without_a_socket_on_this_machine_is_rejected(self):
        self.assertProblem(self.problems(sockets=()), "does not exist on this machine")
        with patch.object(host_baseline.os, "stat", side_effect=PermissionError()):
            self.assertIsNone(host_baseline.is_socket("/var/run/docker.sock"))
        with patch.object(host_baseline.os, "stat", side_effect=FileNotFoundError()):
            self.assertIs(host_baseline.is_socket("/var/run/docker.sock"), False)
        with tempfile.NamedTemporaryFile() as regular:
            self.assertIs(host_baseline.is_socket(regular.name), False)

    def test_failed_or_malformed_context_answers_are_unresolved(self):
        for broken in ("show", "inspect"):
            with self.subTest(broken=broken):
                problems = self.problems(FakeDocker(daemons={LOCAL_SOCKET: daemon()}, broken=[broken]))
                self.assertEqual(self.facts["endpoint"]["resolved"], False)
                self.assertIsNone(self.facts["endpoint"]["transport"])
                self.assertProblem(problems, "endpoint in use could not be determined")
        for output in ("", "not json", "[]", '"unix:///var/run/docker.sock"', '{"name": "default"}',
                       '{"name": "default", "host": null}', '{"name": "default", "host": 7}', '{"name": "default", "host": ""}',
                       '{"name": "another", "host": "unix:///var/run/docker.sock"}', '{"host": "unix:///var/run/docker.sock"}'):
            with self.subTest(output=output):
                cli = FakeDocker(daemons={LOCAL_SOCKET: daemon()}, broken=["inspect-output"])
                cli.broken_output = output
                self.assertProblem(self.problems(cli), "endpoint in use could not be determined")
        for address in ("/var/run/docker.sock", "unix://", "unix:", "gopher://192.0.2.10", "://"):
            with self.subTest(address=address):
                cli = FakeDocker(contexts={"odd": address}, current="odd", daemons={address: daemon()})
                self.assertProblem(self.problems(cli), "Docker is reached over unrecognised")

    def test_endpoint_that_changes_during_collection_is_unresolved(self):
        remote = "tcp://192.0.2.10:2376"
        cli = FakeDocker(contexts={"remote": remote}, daemons={LOCAL_SOCKET: daemon(), remote: daemon()})
        original = cli.__call__

        def switching(command, **options):
            if command[1] == "info":
                cli.current = "remote"  # someone runs `docker context use` in another terminal
            return original(command, **options)
        with patch.object(FakeDocker, "__call__", lambda self, command, **options: switching(command, **options)):
            problems = self.problems(cli)
        self.assertFalse(self.facts["endpoint"]["resolved"])
        self.assertProblem(problems, "changed during collection")

    def test_missing_or_hanging_docker_is_unresolved_and_never_accepted(self):
        for error in (FileNotFoundError("docker"), subprocess.TimeoutExpired("docker", 30), PermissionError("docker")):
            with self.subTest(error=type(error).__name__), patch.object(host_baseline.subprocess, "run", side_effect=error), \
                    patch.object(host_baseline.platform, "system", return_value="Linux"), \
                    patch.object(host_baseline, "read", side_effect=self.HOST_FILES.get):
                facts = host_baseline.gather(environ={})
                self.assertEqual(facts["docker"], {"compose": None})
                self.assertEqual((facts["endpoint"]["resolved"], facts["endpoint"]["transport"]), (False, None))
                problems = host_baseline.baseline_problems(facts)
                self.assertProblem(problems, "endpoint in use could not be determined")
                self.assertProblem(problems, "kernel release is unavailable")

    def test_incomplete_facts_never_pass(self):
        complete = self.collect()
        self.assertEqual(host_baseline.baseline_problems(complete), [])
        for missing in ("endpoint", "docker", "host", "settings"):
            with self.subTest(missing=missing):
                self.assertTrue(host_baseline.baseline_problems({k: v for k, v in complete.items() if k != missing}))
        for key in complete["endpoint"]:
            if key in ("docker_host_set", "docker_context_set", "variables_agree"):
                continue
            with self.subTest(endpoint_without=key):
                facts = dict(complete, endpoint={k: v for k, v in complete["endpoint"].items() if k != key})
                self.assertTrue(host_baseline.baseline_problems(facts))

    def test_existing_departures_are_still_reported(self):
        cases = (({"files": {"/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.5 LTS"\nID=ubuntu\nVERSION_ID="22.04"\n'}}, {}, "not Ubuntu 24.04"),
                 ({"files": {"/etc/os-release": 'PRETTY_NAME="%s"\nID=debian\nVERSION_ID="24.04"\n' % UBUNTU_RELEASE}}, {}, "not Ubuntu 24.04"),
                 ({}, {"system": "Docker Desktop"}, "different operating system from this host's distribution"),
                 ({}, {"system": None}, "different operating system from this host's distribution"),
                 ({}, {"server": "27.5.1"}, "older than 28"), ({}, {"server": None}, "older than 28"),
                 ({}, {"security": ["name=seccomp,profile=builtin"]}, "does not report apparmor"),
                 ({}, {"security": ["name=apparmor"]}, "does not report seccomp"),
                 ({}, {"security": None}, "does not report seccomp"),
                 ({}, {"security": ["name=apparmor", "name=seccomp", "name=rootless"]}, "reports rootless"),
                 ({}, {"security": ["name=apparmor", "name=seccomp", "name=userns"]}, "reports userns"),
                 ({"euid": 0}, {}, "running as root"),
                 ({"files": {"/sys/module/apparmor/parameters/enabled": "N"}}, {}, "AppArmor is not enabled"),
                 ({"files": {"/proc/sys/kernel/apparmor_restrict_unprivileged_userns": "0"}}, {}, "has been relaxed"),
                 ({"files": {"/proc/sys/kernel/apparmor_restrict_unprivileged_userns": None}}, {}, "has been relaxed"))
        for host, reported, expected in cases:
            with self.subTest(host=host, reported=reported):
                self.assertProblem(self.problems(FakeDocker(daemons={LOCAL_SOCKET: daemon(**reported)}), **host), expected)

    def test_recorder_prints_no_address_credentials_or_context_metadata(self):
        secret = "ssh://deploy-user@build-host.example:2222"
        cli = FakeDocker(contexts={"remote": secret}, current="remote", daemons={secret: daemon()})
        facts = self.collect(cli)
        output = io.StringIO()
        with patch.object(host_baseline, "gather", return_value=facts), contextlib.redirect_stdout(output):
            self.assertEqual(host_baseline.main([]), 0)  # the plain recorder only informs
            self.assertEqual(host_baseline.main(["--require-linux-baseline"]), 1)
        printed = output.getvalue()
        for leaked in ("deploy-user", "build-host", "2222", "ssh://", "TLS", "Storage"):
            self.assertNotIn(leaked, printed)
        self.assertIn("endpoint.transport: ssh", printed)
        self.assertIn("endpoint.context: remote", printed)
        self.assertIn("NOTE  the settings.* lines below are this machine's", printed)
        self.assertIn("NOT THE LINUX BASELINE  Docker is reached over ssh", printed)
        self.assertEqual(sorted(re.findall(r"\{\{json (\.[\w.]+)\}\}", host_baseline.CONTEXT_ENDPOINT)), [".Endpoints.docker.Host", ".Name"])
        for template in (host_baseline.DOCKER_VERSION, host_baseline.DOCKER_INFO, host_baseline.CONTEXT_ENDPOINT):
            self.assertNotIn("{{json .}}", template)

    def test_accepted_baseline_exits_zero(self):
        facts = self.collect()
        with patch.object(host_baseline, "gather", return_value=facts), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(host_baseline.main(["--require-linux-baseline"]), 0)
        self.assertNotIn("NOTE", output.getvalue())


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
            for name in pin.SOURCES + ("PINS.txt",):
                (root / name).write_bytes((ROOT / name).read_bytes())
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            refs = ["lscr.io/linuxserver/firefox@sha256:" + "a"*64, "ubuntu/squid@sha256:" + "b"*64,
                    "alpine/socat@sha256:" + "c"*64, RuntimeError("registry unavailable")]
            with patch.object(pin, "resolve", side_effect=refs), self.assertRaises(RuntimeError):
                pin.pin(root, True)
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})

    def test_successful_pinning_updates_all_references_and_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in pin.SOURCES + ("PINS.txt",):
                (root / name).write_bytes((ROOT / name).read_bytes())
            self.assertEqual(len(pin.IMAGES), 4)
            refs = [repo + "@sha256:" + char*64 for (repo, _, _, _), char in zip(pin.IMAGES, "abcd")]
            with patch.object(pin, "resolve", side_effect=refs) as resolve, contextlib.redirect_stdout(io.StringIO()):
                pin.pin(root, True)
            for ref, (_, name, _, _) in zip(refs, pin.IMAGES):
                self.assertIn(ref, (root / name).read_text())
                self.assertIn(ref, (root / "PINS.txt").read_text())
            self.assertFalse(list(root.glob(".pin-*")))
            # Every image was resolved, each with the tag the inventory names for it.
            self.assertEqual([call.args for call in resolve.call_args_list], [(repo, True, tag) for repo, _, _, tag in pin.IMAGES])
            self.assertEqual(pin.inventory(root), (dict(zip([image[0] for image in pin.IMAGES], refs)), []))
            report = verify.Report()
            with patch.object(verify, "ROOT", root), contextlib.redirect_stdout(io.StringIO()):
                verify.check_pins(report)
            self.assertEqual(report.counts, {"PASS": 6, "FAIL": 0, "INCONCLUSIVE": 0})

    def test_gluetun_is_held_at_a_release_and_never_follows_latest(self):
        tags = {repo: tag for repo, _, _, tag in pin.IMAGES}
        self.assertRegex(tags["qmcgaw/gluetun"], r"^v\d+\.\d+\.\d+$")
        ref = "qmcgaw/gluetun@sha256:" + "a"*64
        with patch.object(pin.subprocess, "run", return_value=result(json.dumps([{"RepoDigests": [ref]}]))) as mock, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(pin.resolve("qmcgaw/gluetun", True, tags["qmcgaw/gluetun"]), ref)
        self.assertEqual([call.args[0][-1] for call in mock.call_args_list], ["qmcgaw/gluetun:" + tags["qmcgaw/gluetun"]] * 2)
        self.assertIn(tags["qmcgaw/gluetun"], (ROOT / "docker-compose.vpn.yml").read_text())
        self.assertIn("release " + tags["qmcgaw/gluetun"], pin.manifest(["x"]))

    def test_inventory_is_complete_whatever_the_number_of_images(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in pin.SOURCES + ("PINS.txt",):
                (root / name).write_bytes((ROOT / name).read_bytes())

            def counts():
                report = verify.Report()
                with patch.object(verify, "ROOT", root), contextlib.redirect_stdout(io.StringIO()):
                    verify.check_pins(report)
                return report.counts
            self.assertEqual(counts()["FAIL"], 0)
            original = {name: (root / name).read_text() for name in pin.SOURCES + ("PINS.txt",)}
            cases = {
                "an image nobody listed": ("docker-compose.vpn.yml", "\n  vpn:\n", "\n  extra:\n    image: example/unlisted:latest\n  vpn:\n"),
                "a listed image in the wrong file": ("docker-compose.yml", "\n  gateway:\n", "\n  other:\n    image: ubuntu/squid:latest\n  gateway:\n"),
                "an unpinned VPN image": ("docker-compose.vpn.yml", "qmcgaw/gluetun@sha256:", "qmcgaw/gluetun:v3.41.3 #"),
                "a pin missing from the manifest": ("PINS.txt", "qmcgaw/gluetun@sha256:", "# qmcgaw/gluetun@sha256:"),
                "a stale manifest entry": ("PINS.txt", "alpine/socat@sha256:e", "alpine/socat@sha256:f"),
            }
            for label, (name, old, new) in cases.items():
                with self.subTest(case=label):
                    self.assertEqual(original[name].count(old), 1)
                    (root / name).write_text(original[name].replace(old, new))
                    self.assertGreater(counts()["FAIL"], 0)
                    (root / name).write_text(original[name])
            self.assertEqual(counts()["FAIL"], 0)

    def test_missing_or_duplicate_reference_fails(self):
        for text in ("# ubuntu/squid:latest\n", "image: ubuntu/squid:latest\nimage: ubuntu/squid:latest\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                pin.rewrite(text, "ubuntu/squid", "image:", "ubuntu/squid@sha256:" + "a"*64)

    def test_nonlatest_tag_is_not_a_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in pin.SOURCES + ("PINS.txt",):
                (root / name).write_bytes((ROOT / name).read_bytes())
            compose = root / "compose.services.yml"
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


if __name__ == "__main__":
    unittest.main()
