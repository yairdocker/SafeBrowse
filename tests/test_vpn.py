"""VPN mode without Docker: configuration parsing, secret files, mode selection and topology verification."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "tests")]
import test_launch as base  # noqa: E402  the launcher harness: Recorder, LauncherCase
import verify  # noqa: E402
import vpn  # noqa: E402

safebrowse = base.safebrowse
COMPOSE, DOWN, SESSION_ID = base.COMPOSE, base.DOWN, base.SESSION_ID
DIRECT, VPN = ("docker-compose.yml",), ("docker-compose.vpn.yml",)


def new_key():
    return base64.b64encode(os.urandom(32)).decode("ascii")


PRIVATE, PUBLIC = new_key(), new_key()
OTHER_SESSION = "f" * 16


def export(private=PRIVATE, public=PUBLIC, address="10.64.12.34/32,fc00:bbbb:bbbb:bb01::1:c22/128", dns="DNS = 10.64.0.1\n",
           allowed="0.0.0.0/0,::0/0", endpoint="185.213.154.68:51820", interface="", peer=""):
    """A file shaped like a Mullvad WireGuard export."""
    return (f"[Interface]\n# Device: Test Device\nPrivateKey = {private}\nAddress = {address}\n{dns}{interface}\n"
            f"[Peer]\nPublicKey = {public}\nAllowedIPs = {allowed}\nEndpoint = {endpoint}\n{peer}")


FINGERPRINT = vpn.fingerprint(vpn.parse(export()))


def within(seconds, function, *arguments):
    """Call `function` on a worker thread and hand its result, or its exception, back to the calling thread.

    Opening a FIFO by mistake blocks for ever, so the calls that could do so are bounded: running out of
    time is a failure, not a hung suite. Nothing is asserted on the worker thread, where a failed
    assertion would never reach unittest; the caller asserts on whatever comes back.
    """
    outcome = []

    def work():
        try:
            outcome.append((function(*arguments), None))
        except BaseException as error:  # handed to the caller, whatever it is
            outcome.append((None, error))
    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive() or not outcome:
        raise AssertionError(f"{getattr(function, '__name__', 'the call')} did not finish within {seconds} seconds")
    value, error = outcome[0]
    if error is not None:
        raise error
    return value


def refused(test, text, phrase, **options):
    with test.assertRaises(vpn.ConfigError) as caught:
        vpn.parse(text, **options)
    message = str(caught.exception)
    test.assertIn(phrase, message)
    # A refusal explains itself without repeating a key or the file.
    for secret in (PRIVATE, PUBLIC, PRIVATE[:12]):
        test.assertNotIn(secret, message)
    return message


class ParserTests(unittest.TestCase):
    def test_mullvad_export_is_reduced_to_ipv4_and_says_what_it_left_out(self):
        tunnel = vpn.parse(export())
        self.assertEqual(tunnel[:8], (PRIVATE, "10.64.12.34", PUBLIC, "", "185.213.154.68", 51820, vpn.DEFAULT_MTU, 0))
        notices = " | ".join(tunnel.notices)
        for phrase in ("IPv6 interface address was left out", "IPv6 route (::/0) was left out", "DNS setting was not used",
                       "keeps its own filtering resolvers"):
            self.assertIn(phrase, notices)
        self.assertEqual(len(tunnel.notices), 3)
        self.assertEqual(vpn.parse(export(dns="", address="10.64.12.34/32", allowed="0.0.0.0/0")).notices, ())

    def test_generated_configuration_is_minimal_and_round_trips(self):
        tunnel = vpn.parse(export(interface="MTU = 1380\n", peer=f"PresharedKey = {PUBLIC}\nPersistentKeepalive = 25\n"))
        text = vpn.render(tunnel)
        self.assertEqual(text, f"[Interface]\nPrivateKey = {PRIVATE}\nAddress = 10.64.12.34/32\nMTU = 1380\n\n[Peer]\n"
                               f"PublicKey = {PUBLIC}\nPresharedKey = {PUBLIC}\nAllowedIPs = 0.0.0.0/0\n"
                               "Endpoint = 185.213.154.68:51820\nPersistentKeepalive = 25\n")
        self.assertEqual(vpn.parse(text), tunnel._replace(notices=()))
        minimal = vpn.render(vpn.parse(export()))
        for absent in ("DNS", "fc00", "::", "Device", "#", "PresharedKey", "PersistentKeepalive", "\r"):
            self.assertNotIn(absent, minimal)
        self.assertEqual(minimal.count("\n"), 9)

    def test_formatting_variants_are_accepted(self):
        expected = vpn.parse(export())._replace(notices=())
        variants = (export().replace("\n", "\r\n"), "﻿" + export(), export().replace(" = ", "="),
                    export().replace("[Interface]", "[interface]").replace("[Peer]", "[PEER]"),
                    export().replace("PrivateKey", "privatekey").replace("AllowedIPs", "ALLOWEDIPS"),
                    export().replace("\n[Peer]", "\n  # a comment\n\t\n[Peer]"), export(allowed="::/0, 0.0.0.0/0"),
                    export(address="fc00:bbbb:bbbb:bb01::1:c22/128 , 10.64.12.34"))
        for text in variants:
            with self.subTest(text=text[:40]):
                self.assertEqual(vpn.parse(text)._replace(notices=()), expected)

    def test_keys_must_be_canonical_base64_of_32_bytes(self):
        bad = ("", "short", base64.b64encode(os.urandom(31)).decode(), base64.b64encode(os.urandom(33)).decode(),
               PRIVATE[:-1], PRIVATE + "=", PRIVATE[:-2] + "!=", PRIVATE.replace(PRIVATE[5], "-", 1) if "-" not in PRIVATE else "x",
               base64.b16encode(os.urandom(32)).decode(), PRIVATE[:-2] + ("B=" if PRIVATE[-2] != "B" else "C="), "é" * 44)
        for value in bad:
            for field, text in (("PrivateKey", export(private=value)), ("PublicKey", export(public=value)),
                                ("PresharedKey", export(peer=f"PresharedKey = {value}\n"))):
                with self.subTest(field=field, value=value[:12]), self.assertRaises(vpn.ConfigError) as caught:
                    vpn.parse(text)
                if value:
                    self.assertNotIn(value, str(caught.exception))
        # A non-canonical encoding of 32 bytes: the last character carries bits the decoder would drop.
        raw = base64.b64decode(PRIVATE)
        canonical = base64.b64encode(raw).decode()
        twisted = canonical[:-2] + chr(ord(canonical[-2]) + 1) + "="
        if base64.b64decode(twisted) == raw:
            refused(self, export(private=twisted), "PrivateKey is not")

    def test_endpoint_must_be_a_literal_public_ipv4_address_and_port(self):
        for endpoint, phrase in (("se-got-wg-001.relays.mullvad.net:51820", "literal IPv4"), ("[2a03:1b20:5:f011::a01f]:51820", "literal IPv4"),
                                 ("185.213.154.68", "literal IPv4"), ("185.213.154.68:", "literal IPv4"),
                                 ("185.213.154.68:0", "port"), ("185.213.154.68:65536", "port"), ("185.213.154.68:99999", "port"),
                                 ("185.213.154.999:51820", "literal IPv4"), ("185.213.154.68:51820 extra", "literal IPv4"),
                                 ("localhost:51820", "literal IPv4"), ("0x7f.1:51820", "literal IPv4"),
                                 ("10.0.0.5:51820", "not a public"), ("127.0.0.1:51820", "not a public"),
                                 ("192.168.1.10:51820", "not a public"), ("172.20.0.2:51820", "not a public"),
                                 ("169.254.1.1:51820", "not a public"), ("100.64.0.1:51820", "not a public"),
                                 ("198.18.0.20:51820", "not a public"), ("0.0.0.0:51820", "not a public"),
                                 ("224.0.0.1:51820", "not a public"), ("255.255.255.255:51820", "not a public")):
            with self.subTest(endpoint=endpoint):
                refused(self, export(endpoint=endpoint), phrase)
        self.assertEqual(vpn.parse(export(endpoint="185.213.154.68:1")).port, 1)
        self.assertEqual(vpn.parse(export(endpoint="185.213.154.68:65535")).port, 65535)

    def test_private_endpoints_exist_only_for_python_fixtures(self):
        text = export(endpoint="198.18.0.20:51820")
        refused(self, text, "not a public")
        self.assertEqual(vpn.parse(text, allow_private_endpoint=True).endpoint, "198.18.0.20")
        # Nothing on the command line or in the environment can turn it on.
        self.assertFalse(safebrowse.Session().private_vpn_endpoint)
        source = (ROOT / "scripts/safebrowse.py").read_text()
        self.assertEqual(source.count("private_vpn_endpoint"), 3)  # the Session field and its two uses
        self.assertNotIn("environ", source[source.index("def choose_tunnel"):source.index("def check_model")])

    def test_interface_address_must_be_one_ipv4_host(self):
        for address, phrase in (("fc00:bbbb:bbbb:bb01::1:c22/128", "exactly one IPv4"), ("10.64.0.2/32,10.64.0.3/32", "exactly one IPv4"),
                                ("10.64.0.2/24", "single host address"), ("10.64.0.0/10", "single host address"),
                                ("not-an-address", "not an IP address"), ("10.64.0.2/32,", "empty entry"),
                                ("10.64.0.2/33", "not an IP address"), ("10.64.0.2/32,fc00::zz/128", "not an IP address")):
            with self.subTest(address=address):
                refused(self, export(address=address), phrase)

    def test_only_full_tunnel_routing_is_accepted_and_ipv6_is_never_partly_kept(self):
        for allowed, phrase in (("::/0", "must include 0.0.0.0/0"), ("10.0.0.0/8", "split or partial"),
                                ("0.0.0.0/0,10.0.0.0/8", "split or partial"), ("0.0.0.0/1,128.0.0.0/1", "split or partial"),
                                ("0.0.0.0/0,::/1", "split or partial"), ("0.0.0.0/0,fc00::/7", "split or partial"),
                                ("0.0.0.0/0,2000::/3", "split or partial"), ("0.0.0.0/0,", "empty entry"),
                                ("everything", "not an IP network"), ("0.0.0.0/33", "not an IP network")):
            with self.subTest(allowed=allowed):
                refused(self, export(allowed=allowed), phrase)
        for allowed in ("0.0.0.0/0", "0.0.0.0/0,::/0", "0.0.0.0/0, ::0/0", "::/0,0.0.0.0/0"):
            with self.subTest(allowed=allowed):
                tunnel = vpn.parse(export(allowed=allowed))
                self.assertIn("AllowedIPs = 0.0.0.0/0\n", vpn.render(tunnel))
                self.assertNotIn("::", vpn.render(tunnel))

    def test_mtu_and_keepalive_ranges(self):
        for line, phrase in (("MTU = 1279", "MTU must be"), ("MTU = 1421", "MTU must be"), ("MTU = 9000", "MTU must be"),
                             ("MTU = -1", "MTU must be"), ("MTU = 1380.5", "MTU must be"), ("MTU = auto", "MTU must be")):
            with self.subTest(line=line):
                refused(self, export(interface=line + "\n"), phrase)
        for line in ("PersistentKeepalive = 65536", "PersistentKeepalive = -1", "PersistentKeepalive = off", "PersistentKeepalive = 25s"):
            with self.subTest(line=line):
                refused(self, export(peer=line + "\n"), "PersistentKeepalive must be")
        self.assertEqual(vpn.parse(export(interface="MTU = 1280\n")).mtu, 1280)
        self.assertEqual(vpn.parse(export(interface="MTU = 1420\n")).mtu, 1420)
        self.assertEqual(vpn.parse(export(peer="PersistentKeepalive = 0\n")).keepalive, 0)
        self.assertEqual(vpn.parse(export(peer="PersistentKeepalive = 65535\n")).keepalive, 65535)

    def test_exactly_one_interface_and_one_peer(self):
        second_peer = f"[Peer]\nPublicKey = {new_key()}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 185.213.154.69:51820\n"
        refused(self, export() + second_peer, "more than one [Peer]")
        refused(self, export() + "[Interface]\n", "more than one [Interface]")
        refused(self, export() + "[peer]\n", "more than one [Peer]")
        refused(self, export().split("[Peer]")[0], "no [Peer] section")
        refused(self, "[Peer]" + export().split("[Peer]")[1], "no [Interface] section")
        refused(self, "", "no [Interface] section")
        refused(self, export() + "[WireGuard]\nKey = 1\n", "unsupported section")
        refused(self, "PrivateKey = x\n" + export(), "outside any section")

    def test_duplicate_fields_are_rejected_whatever_their_case(self):
        for extra, where in ((f"PrivateKey = {new_key()}\n", "interface"), ("address = 10.64.0.9/32\n", "interface"),
                             ("DNS = 1.1.1.1\n", "interface"), ("MTU = 1300\nmtu = 1400\n", "interface")):
            with self.subTest(extra=extra[:12]):
                refused(self, export(interface=extra), "more than once")
        for extra in (f"PUBLICKEY = {new_key()}\n", "Endpoint = 185.213.154.69:51820\n", "allowedips = 0.0.0.0/0\n",
                      "PersistentKeepalive = 1\nPersistentKeepalive = 2\n"):
            with self.subTest(extra=extra[:12]):
                refused(self, export(peer=extra), "more than once")

    def test_command_hooks_are_rejected_and_never_run(self):
        marker = Path(tempfile.gettempdir()) / ("safebrowse-hook-" + os.urandom(4).hex())
        for name in ("PreUp", "PostUp", "PreDown", "PostDown", "postup", "POSTDOWN"):
            for where in ("interface", "peer"):
                with self.subTest(name=name, where=where):
                    message = refused(self, export(**{where: f"{name} = touch {marker}\n"}), "command hook")
                    self.assertNotIn(str(marker), message)
                    self.assertIn("without a kill switch", message)
        refused(self, export(interface="PostUp = iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -j REJECT\n"),
                "command hook")
        self.assertFalse(marker.exists())

    def test_unsupported_directives_and_includes_are_rejected(self):
        for line in ("ListenPort = 51820", "Table = off", "FwMark = 51820", "SaveConfig = true", "Jc = 4", "Unknown = 1"):
            with self.subTest(line=line):
                refused(self, export(interface=line + "\n"), "does not support")
        for line in ("Table = off", "PrivateKey = " + new_key(), "DNS = 1.1.1.1", "MTU = 1300"):
            with self.subTest(peer_line=line[:12]):
                refused(self, export(peer=line + "\n"), "does not support")
        for line in ("include /etc/wireguard/other.conf", "#include other.conf", "# include other.conf", "!include other.conf",
                     "@include other.conf", "Include = other.conf"):
            with self.subTest(line=line):
                refused(self, export(interface=line + "\n"), "include")
        for line in ("just words", "= value", "Private Key = x", "MTU", "MTU ="):
            with self.subTest(line=line):
                with self.assertRaises(vpn.ConfigError):
                    vpn.parse(export(interface=line + "\n"))

    def test_control_characters_and_oversized_input_are_rejected(self):
        for character in ("\0", "\x1b", "\x7f", "\x08", "\x0b"):
            with self.subTest(character=repr(character)):
                refused(self, export(interface=f"MTU = 13{character}80\n"), "control character")
        refused(self, export() + "#" * vpn.SIZE_LIMIT, "too large")

    def test_missing_required_fields(self):
        for field in ("PrivateKey", "Address"):
            text = "\n".join(line for line in export().split("\n") if not line.startswith(field))
            refused(self, text, f"[Interface] has no '{field.lower()}'")
        for field in ("PublicKey", "AllowedIPs", "Endpoint"):
            text = "\n".join(line for line in export().split("\n") if not line.startswith(field))
            refused(self, text, f"[Peer] has no '{field.lower()}'")


class FirewallRuleTests(unittest.TestCase):
    def setUp(self):
        self.tunnel = vpn.parse(export())

    def test_rules_are_exactly_the_reviewed_set(self):
        self.assertEqual(vpn.firewall_rules("172.31.9.0/24", self.tunnel), """iptables -N SAFEBROWSE_INPUT
iptables -A SAFEBROWSE_INPUT -i lo -j RETURN
iptables -A SAFEBROWSE_INPUT -i tun0 -j RETURN
iptables -A SAFEBROWSE_INPUT -s 172.31.9.0/24 -i sbx0 -p tcp -m tcp --dport 3128 -j ACCEPT
iptables -A SAFEBROWSE_INPUT -s 185.213.154.68/32 -i egr0 -p udp -m udp --sport 51820 -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A SAFEBROWSE_INPUT -j DROP
iptables -I INPUT 1 -j SAFEBROWSE_INPUT
iptables -N SAFEBROWSE_OUTPUT
iptables -A SAFEBROWSE_OUTPUT -d 127.0.0.11/32 -j DROP
iptables -A SAFEBROWSE_OUTPUT -o lo -j RETURN
iptables -A SAFEBROWSE_OUTPUT -o tun0 -j RETURN
iptables -A SAFEBROWSE_OUTPUT -d 172.31.9.0/24 -o sbx0 -p tcp -m tcp --sport 3128 -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A SAFEBROWSE_OUTPUT -d 185.213.154.68/32 -o egr0 -p udp -m udp --dport 51820 -j ACCEPT
iptables -A SAFEBROWSE_OUTPUT -j DROP
iptables -I OUTPUT 1 -j SAFEBROWSE_OUTPUT
iptables -I FORWARD 1 -j DROP
""")

    def test_restrictions_precede_every_broader_rule_and_open_no_address_range(self):
        lines = vpn.firewall_rules("172.31.9.0/24", self.tunnel).splitlines()
        # Jumps are inserted at position 1, ahead of whatever Gluetun appended; each chain ends in DROP.
        self.assertEqual([line for line in lines if " -I " in line],
                         ["iptables -I INPUT 1 -j SAFEBROWSE_INPUT", "iptables -I OUTPUT 1 -j SAFEBROWSE_OUTPUT",
                          "iptables -I FORWARD 1 -j DROP"])
        for chain, rules in vpn.chain_rules("172.31.9.0/24", "185.213.154.68", 51820).items():
            self.assertEqual(rules[-1], f"-A {chain} -j DROP")
            accepts = [rule for rule in rules if rule.endswith("-j ACCEPT")]
            self.assertEqual(len(accepts), 2)
            for rule in accepts:  # an interface, a protocol and a port, every time
                self.assertRegex(rule, r" -[io] (sbx0|egr0) -p (tcp|udp) -m (tcp|udp) --[sd]port \d+ ")
        text = "\n".join(lines)
        for wide in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "0.0.0.0/0", "-j ACCEPT\niptables -A SAFEBROWSE_INPUT -j ACCEPT",
                     "RELATED", "-p icmp", "ip6tables", "eth0", "--dport 53", "8000", "9999"):
            self.assertNotIn(wide, text)
        output = vpn.chain_rules("172.31.9.0/24", "185.213.154.68", 51820)["SAFEBROWSE_OUTPUT"]
        self.assertEqual(output[0], "-A SAFEBROWSE_OUTPUT -d 127.0.0.11/32 -j DROP")  # before loopback is let through
        self.assertLess(output.index("-A SAFEBROWSE_OUTPUT -d 127.0.0.11/32 -j DROP"), output.index("-A SAFEBROWSE_OUTPUT -o lo -j RETURN"))

    def test_rules_follow_the_selected_subnet_and_reject_bad_input(self):
        self.assertIn("-s 10.231.4.0/24 -i sbx0", vpn.firewall_rules("10.231.4.0/24", self.tunnel))
        for subnet in ("10.231.4.0/24; rm -rf /", "10.231.4.1/24", "::/0", "", "10.231.4.0/24\niptables -P INPUT ACCEPT"):
            with self.subTest(subnet=subnet), self.assertRaises(ValueError):
                vpn.firewall_rules(subnet, self.tunnel)

    def test_compose_inputs_carry_no_key(self):
        tunnel = vpn.parse(export(interface="MTU = 1380\n", peer=f"PresharedKey = {new_key()}\nPersistentKeepalive = 25\n"))
        settings = vpn.environment(tunnel, Path("/tmp/x"))
        self.assertEqual(settings, {"SAFEBROWSE_VPN_DIR": "/tmp/x", "SAFEBROWSE_VPN_MTU": "1380", "SAFEBROWSE_VPN_KEEPALIVE": "25s",
                                    "SAFEBROWSE_VPN_FINGERPRINT": vpn.fingerprint(tunnel)})
        self.assertRegex(settings["SAFEBROWSE_VPN_FINGERPRINT"], r"^[0-9a-f]{64}$")
        self.assertEqual(vpn.environment(self.tunnel, "d")["SAFEBROWSE_VPN_KEEPALIVE"], "0")
        for value in list(settings.values()) + [vpn.firewall_rules("172.31.9.0/24", tunnel)]:
            for secret in (tunnel.private_key, tunnel.public_key, tunnel.preshared_key):
                self.assertNotIn(secret, value)


class BoundedCallTests(unittest.TestCase):
    """`within` is what makes the FIFO cases safe to run; it must report what happened, not swallow it."""

    def test_result_exception_and_overrun_all_reach_the_caller(self):
        self.assertEqual(within(5, lambda value: value * 2, 21), 42)
        self.assertRaisesRegex(vpn.ConfigError, "refused", within, 5, lambda: (_ for _ in ()).throw(vpn.ConfigError("refused")))
        # The case the earlier tests could not detect: the call completes without raising.
        with self.assertRaises(AssertionError):
            self.assertRaisesRegex(vpn.ConfigError, "refused", within, 5, lambda: "accepted")
        release = threading.Event()
        try:
            self.assertRaisesRegex(AssertionError, "did not finish within 0.05 seconds", within, 0.05, release.wait)
        finally:
            release.set()


class SecretFileTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="safebrowse-vpn-unit-")).resolve()
        self.addCleanup(__import__("shutil").rmtree, self.root, True)
        self.source = self.root / "mullvad.conf"
        self.source.write_text(export())
        self.source.chmod(0o600)
        self.tunnel = vpn.parse(export())

    def mode(self, path):
        return stat.S_IMODE(os.lstat(path).st_mode)

    def test_source_is_read_but_never_changed(self):
        self.source.chmod(0o644)
        before = (self.source.read_bytes(), self.mode(self.source), self.source.stat().st_mtime_ns)
        text, notices = vpn.read_source(self.source)
        self.assertEqual(text, export())
        self.assertIn("readable by other users", notices[0])
        self.assertEqual((self.source.read_bytes(), self.mode(self.source), self.source.stat().st_mtime_ns), before)
        self.source.chmod(0o600)
        self.assertEqual(vpn.read_source(self.source)[1], ())

    def test_links_and_non_regular_sources_are_rejected(self):
        link, directory, fifo = self.root / "link.conf", self.root / "dir.conf", self.root / "fifo.conf"
        link.symlink_to(self.source)
        directory.mkdir()
        cases = [(link, "symbolic link"), (directory, "not a regular file"), (self.root / "absent.conf", "could not be opened")]
        if hasattr(os, "mkfifo"):
            os.mkfifo(fifo)
            cases.append((fifo, "not a regular file"))
        for path, phrase in cases:
            with self.subTest(path=path.name):
                # Bounded, because a FIFO must not hang the launcher; asserted here, on the test's own thread.
                self.assertRaisesRegex(vpn.ConfigError, phrase, within, 5, vpn.read_source, path)
        (self.root / "big.conf").write_bytes(b"#" * (vpn.SIZE_LIMIT + 1))
        self.assertRaisesRegex(vpn.ConfigError, "too large", vpn.read_source, self.root / "big.conf")
        (self.root / "binary.conf").write_bytes(b"\xff\xfe\x00[Interface]")
        self.assertRaisesRegex(vpn.ConfigError, "not text", vpn.read_source, self.root / "binary.conf")

    def test_staged_configuration_is_private_and_created_exclusively(self):
        with patch.object(os, "umask", wraps=os.umask):
            old = os.umask(0)  # even a permissive umask must not widen anything
            try:
                directory = vpn.stage(self.root, SESSION_ID, self.tunnel)
            finally:
                os.umask(old)
        self.assertEqual(directory, self.root / ".runtime/vpn" / SESSION_ID)
        self.assertEqual((self.mode(self.root / ".runtime/vpn"), self.mode(directory), self.mode(directory / "wg0.conf")),
                         (0o700, 0o700, 0o600))
        self.assertEqual((directory / "wg0.conf").read_text(), vpn.render(self.tunnel))
        self.assertEqual(sorted(p.name for p in directory.iterdir()), ["wg0.conf"])
        # A second session never reuses or overwrites the first one's directory.
        other = self.tunnel._replace(endpoint="185.213.154.69")
        with self.assertRaises(FileExistsError):
            vpn.stage(self.root, SESSION_ID, other)
        self.assertEqual((directory / "wg0.conf").read_text(), vpn.render(self.tunnel))
        second = vpn.stage(self.root, "f" * 16, other)
        self.assertEqual(vpn.sessions(self.root), [SESSION_ID, "f" * 16])
        self.assertNotEqual((second / "wg0.conf").read_text(), (directory / "wg0.conf").read_text())

    def test_rules_are_replaced_atomically_and_stay_private(self):
        directory = vpn.stage(self.root, SESSION_ID, self.tunnel)
        vpn.write_rules(self.root, SESSION_ID, "172.31.0.0/24", self.tunnel)
        vpn.write_rules(self.root, SESSION_ID, "172.31.1.0/24", self.tunnel)
        self.assertEqual((directory / "post-rules.txt").read_text(), vpn.firewall_rules("172.31.1.0/24", self.tunnel))
        self.assertEqual(self.mode(directory / "post-rules.txt"), 0o600)
        self.assertEqual(sorted(p.name for p in directory.iterdir()), ["post-rules.txt", "wg0.conf"])
        # A leftover or planted temporary name is replaced, never followed.
        target = self.root / "elsewhere"
        target.write_text("untouched")
        (directory / ".post-rules.txt.new").symlink_to(target)
        vpn.write_rules(self.root, SESSION_ID, "172.31.2.0/24", self.tunnel)
        self.assertEqual(target.read_text(), "untouched")
        self.assertFalse((directory / "post-rules.txt").is_symlink())
        # Rules are only ever written into a session that was staged.
        self.assertRaisesRegex(vpn.ConfigError, "is missing", vpn.write_rules, self.root, "f" * 16, "172.31.2.0/24", self.tunnel)

    def test_unsafe_store_locations_are_refused(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        (self.root / ".runtime").symlink_to(elsewhere)
        self.assertRaisesRegex(vpn.StorageError, r"^\.runtime is a symbolic link", vpn.stage, self.root, SESSION_ID, self.tunnel)
        (self.root / ".runtime").unlink()
        (self.root / ".runtime").mkdir()
        (self.root / ".runtime/vpn").symlink_to(elsewhere)
        self.assertRaisesRegex(vpn.StorageError, r"^\.runtime/vpn is a symbolic link", vpn.stage, self.root, SESSION_ID, self.tunnel)
        self.assertEqual(list(elsewhere.iterdir()), [])
        (self.root / ".runtime/vpn").unlink()
        for session in ("", "../../etc", "0123456789ABCDEF", "0123456789abcde", "0123456789abcdef0", "none"):
            with self.subTest(session=session):
                self.assertRaisesRegex(vpn.ConfigError, "session identifier", vpn.stage, self.root, session, self.tunnel)
        self.assertFalse((self.root / ".runtime/vpn").exists() and list((self.root / ".runtime/vpn").iterdir()))

    def test_stored_configuration_is_reused_only_when_intact(self):
        directory = vpn.stage(self.root, SESSION_ID, self.tunnel)
        expected = vpn.fingerprint(self.tunnel)
        self.assertEqual(vpn.load(self.root, SESSION_ID, expected), self.tunnel._replace(notices=()))
        path = directory / "wg0.conf"
        intact = path.read_text()
        for damaged in (intact.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0,::/0"), intact + "PostUp = id\n",
                        intact.replace("\n", "\r\n"), intact + "\n", intact.replace("[Peer]", "[Peer]\n# note"), "", "garbage",
                        intact.replace("185.213.154.68", "10.0.0.5"), "\xff"):
            with self.subTest(damaged=damaged[-30:]):
                path.write_bytes(damaged.encode("latin-1"))
                self.assertRaisesRegex(vpn.ConfigError, "not the one this session was started with", vpn.load, self.root,
                                       SESSION_ID, expected)
                # Even a caller holding the damaged file's own hash gets nothing that is not canonical.
                own = __import__("hashlib").sha256(damaged.encode("latin-1")).hexdigest()
                self.assertRaises(vpn.ConfigError, vpn.load, self.root, SESSION_ID, own)
        path.write_text(intact)
        for missing in ("", None, "0" * 63, "G" * 64, expected.upper(), expected + "0", "sha256:" + expected):
            self.assertRaisesRegex(vpn.ConfigError, "does not record which configuration", vpn.load, self.root, SESSION_ID, missing)
        path.unlink()
        self.assertRaisesRegex(vpn.ConfigError, "is missing", vpn.load, self.root, SESSION_ID, expected)
        path.symlink_to(self.source)
        self.assertRaisesRegex(vpn.StorageError, "wg0.conf is a symbolic link", vpn.load, self.root, SESSION_ID, expected)
        self.assertEqual(self.source.read_text(), export())
        for session in ("manual", "", "../x"):
            self.assertRaisesRegex(vpn.ConfigError, "session identifier", vpn.load, self.root, session, expected)

    def test_cleanup_removes_only_generated_files_and_never_the_source(self):
        vpn.stage(self.root, SESSION_ID, self.tunnel)
        vpn.write_rules(self.root, SESSION_ID, "172.31.0.0/24", self.tunnel)
        second = vpn.stage(self.root, "f" * 16, self.tunnel)
        self.assertEqual(vpn.discard(self.root, keep=("f" * 16,)), [])
        self.assertEqual(vpn.sessions(self.root), ["f" * 16])
        # A file SafeBrowse did not write is left alone, and the incomplete cleanup is reported.
        (second / "notes.txt").write_text("mine")
        (session, reason), = vpn.discard(self.root)
        self.assertEqual(session, "f" * 16)
        self.assertIn("1 entry that SafeBrowse did not create", reason)
        self.assertNotIn("notes.txt", reason)   # a file name someone else chose is never echoed
        self.assertEqual({p.name: p.read_text() for p in second.iterdir()}, {"notes.txt": "mine"})
        self.assertFalse(vpn.remove(self.root, "f" * 16))
        (second / "notes.txt").unlink()
        self.assertTrue(vpn.remove(self.root, "f" * 16))
        self.assertTrue(vpn.remove(self.root, "f" * 16))   # already gone
        self.assertFalse(vpn.remove(self.root, "../x"))
        # A link named like a session is never entered, and names outside the pattern are not touched.
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "wg0.conf").write_text("keep")
        (self.root / ".runtime/vpn" / ("e" * 16)).symlink_to(outside)
        (self.root / ".runtime/vpn/keep-me").mkdir()
        (session, reason), = vpn.discard(self.root)
        self.assertEqual(session, "e" * 16)
        self.assertIn("is a symbolic link", reason)
        self.assertEqual((outside / "wg0.conf").read_text(), "keep")
        self.assertTrue((self.root / ".runtime/vpn" / ("e" * 16)).is_symlink())
        self.assertTrue((self.root / ".runtime/vpn/keep-me").is_dir())
        self.assertRaisesRegex(vpn.StorageError, "is a symbolic link", vpn.sessions, self.root)   # never "no VPN session"
        self.assertEqual(self.source.read_text(), export())
        self.assertEqual(vpn.sessions(self.root / "nowhere"), [])


def snapshot(path):
    """Everything under `path` without following links: {relative name: (kind, mode, content or link target)}."""
    found = {}
    for current, directories, files in os.walk(path):
        for name in directories + files:
            entry = Path(current) / name
            status = os.lstat(entry)
            if stat.S_ISLNK(status.st_mode):
                detail = ("link", os.readlink(entry))
            elif stat.S_ISREG(status.st_mode):
                detail = ("file", stat.S_IMODE(status.st_mode), entry.read_bytes())
            else:
                detail = ("other", stat.S_IFMT(status.st_mode), stat.S_IMODE(status.st_mode))
            found[str(entry.relative_to(path))] = detail
    return found


class StorageBoundaryTests(unittest.TestCase):
    """stage, load, sessions, write_rules, remove and discard all stop at one checked boundary below the checkout."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="safebrowse-vpn-boundary-")).resolve()
        self.addCleanup(self.clean)
        self.root, self.elsewhere = self.base / "checkout", self.base / "elsewhere"
        self.root.mkdir()
        self.elsewhere.mkdir()
        self.tunnel = vpn.parse(export())
        self.expected = vpn.fingerprint(self.tunnel)
        # Real VPN storage that belongs to something else: another checkout, or a backup.
        vpn.stage(self.elsewhere, SESSION_ID, self.tunnel)
        vpn.write_rules(self.elsewhere, SESSION_ID, SUBNET, self.tunnel)
        (self.elsewhere / "sentinel.txt").write_text("outside")
        (self.elsewhere / "sentinel.txt").chmod(0o640)
        self.outside = snapshot(self.elsewhere)

    def clean(self):
        for current, directories, _ in os.walk(self.base):
            for name in directories:
                if not (Path(current) / name).is_symlink():
                    os.chmod(Path(current) / name, 0o700)
        __import__("shutil").rmtree(self.base, True)

    def local(self, session=SESSION_ID):
        """An ordinary stored session in the checkout."""
        directory = vpn.stage(self.root, session, self.tunnel)
        vpn.write_rules(self.root, session, SUBNET, self.tunnel)
        return directory

    def operations(self):
        return {"stage": lambda: vpn.stage(self.root, OTHER_SESSION, self.tunnel),
                "load": lambda: vpn.load(self.root, SESSION_ID, self.expected),
                "sessions": lambda: vpn.sessions(self.root),
                "write_rules": lambda: vpn.write_rules(self.root, SESSION_ID, SUBNET, self.tunnel),
                "discard": lambda: vpn.discard(self.root)}

    def assertAllRefuse(self, phrase, skip=()):
        """Every operation raises StorageError naming the unsafe path; nothing here or outside changes."""
        before = snapshot(self.root)
        for name, operation in self.operations().items():
            if name in skip:
                continue
            with self.subTest(operation=name):
                with self.assertRaises(vpn.StorageError) as caught:
                    operation()
                message = str(caught.exception)
                self.assertRegex(message, phrase)
                self.assertIn("will not read, write or delete", message)   # says what to do, not just what is wrong
                for secret in (PRIVATE, PUBLIC):
                    self.assertNotIn(secret, message)
        self.assertFalse(vpn.remove(self.root, SESSION_ID))    # never raises, never claims success
        self.assertEqual(snapshot(self.root), before)
        self.assertEqual(snapshot(self.elsewhere), self.outside)

    def test_reported_reproductions_no_longer_delete_or_hide_anything(self):
        # 1. .runtime is a link to a directory holding vpn/<session>/wg0.conf and post-rules.txt: discard deleted them.
        (self.root / ".runtime").symlink_to(self.elsewhere / ".runtime")
        self.assertRaises(vpn.StorageError, vpn.discard, self.root)
        self.assertEqual(snapshot(self.elsewhere), self.outside)
        (self.root / ".runtime").unlink()
        # 2. .runtime/vpn is a link to existing VPN storage: sessions() said there was none.
        (self.root / ".runtime").mkdir()
        (self.root / ".runtime/vpn").symlink_to(self.elsewhere / ".runtime/vpn")
        self.assertRaises(vpn.StorageError, vpn.sessions, self.root)
        self.assertEqual(snapshot(self.elsewhere), self.outside)

    def test_a_link_at_any_directory_level_is_refused_by_every_operation(self):
        (self.root / ".runtime").symlink_to(self.elsewhere / ".runtime")
        self.assertAllRefuse(r"^\.runtime is a symbolic link")
        (self.root / ".runtime").unlink()
        (self.root / ".runtime").mkdir()
        (self.root / ".runtime/vpn").symlink_to(self.elsewhere / ".runtime/vpn")
        self.assertAllRefuse(r"^\.runtime/vpn is a symbolic link")
        (self.root / ".runtime/vpn").unlink()
        (self.root / ".runtime/vpn").mkdir(mode=0o700)
        (self.root / ".runtime/vpn" / SESSION_ID).symlink_to(self.elsewhere / ".runtime/vpn" / SESSION_ID)
        # Staging another session does not go through the link, and a session is never staged over it.
        self.assertAllRefuse(rf"^\.runtime/vpn/{SESSION_ID} is a symbolic link", skip=("stage", "discard"))
        self.assertRaises(FileExistsError, vpn.stage, self.root, SESSION_ID, self.tunnel)
        (session, reason), = vpn.discard(self.root)     # reported as not cleaned up, and left exactly as it was
        self.assertEqual(session, SESSION_ID)
        self.assertIn("is a symbolic link", reason)
        self.assertTrue((self.root / ".runtime/vpn" / SESSION_ID).is_symlink())
        self.assertEqual(snapshot(self.elsewhere), self.outside)

    def test_dangling_links_are_unsafe_storage_not_missing_storage(self):
        nowhere = self.base / "nowhere"
        (self.root / ".runtime").symlink_to(nowhere)
        self.assertAllRefuse(r"^\.runtime is a symbolic link")
        self.assertFalse(nowhere.exists())                  # nothing was created through the link either
        (self.root / ".runtime").unlink()
        (self.root / ".runtime").mkdir()
        (self.root / ".runtime/vpn").symlink_to(nowhere)
        self.assertAllRefuse(r"^\.runtime/vpn is a symbolic link")
        (self.root / ".runtime/vpn").unlink()
        (self.root / ".runtime/vpn").mkdir(mode=0o700)
        (self.root / ".runtime/vpn" / SESSION_ID).symlink_to(nowhere)
        self.assertAllRefuse(rf"^\.runtime/vpn/{SESSION_ID} is a symbolic link", skip=("stage", "discard"))
        self.assertEqual([session for session, _ in vpn.discard(self.root)], [SESSION_ID])
        self.assertFalse(nowhere.exists())

    def test_non_directories_and_unsafe_file_types_are_refused(self):
        (self.root / ".runtime").write_text("a file")
        self.assertAllRefuse(r"^\.runtime is not a directory")
        (self.root / ".runtime").unlink()
        (self.root / ".runtime").mkdir()
        (self.root / ".runtime/vpn").write_text("a file")
        self.assertAllRefuse(r"^\.runtime/vpn is not a directory")
        (self.root / ".runtime/vpn").unlink()
        (self.root / ".runtime/vpn").mkdir(mode=0o700)
        (self.root / ".runtime/vpn" / SESSION_ID).write_text("a file")
        self.assertAllRefuse(rf"^\.runtime/vpn/{SESSION_ID} is not a directory", skip=("stage", "discard"))
        self.assertEqual([session for session, _ in vpn.discard(self.root)], [SESSION_ID])
        self.assertEqual((self.root / ".runtime/vpn" / SESSION_ID).read_text(), "a file")
        (self.root / ".runtime/vpn" / SESSION_ID).unlink()
        # The generated files themselves: a link to someone else's file, a directory, a FIFO.
        directory = self.local()
        target = self.elsewhere / ".runtime/vpn" / SESSION_ID / "wg0.conf"
        kinds = {"is a symbolic link": lambda path: path.symlink_to(target), "is not a regular file": lambda path: path.mkdir()}
        if hasattr(os, "mkfifo"):
            kinds["is not a regular file "] = lambda path: os.mkfifo(path)
        for phrase, make in kinds.items():
            for name in ("wg0.conf", "post-rules.txt"):
                with self.subTest(kind=phrase, name=name):
                    path = directory / name
                    original = path.read_bytes()
                    path.unlink()
                    make(path)
                    # Bounded, because a FIFO must not hang the launcher; asserted here, on the test's own thread.
                    self.assertRaisesRegex(vpn.StorageError, f"{name} {phrase.strip()}", within, 5, vpn.sessions, self.root)
                    if name == "wg0.conf":
                        self.assertRaisesRegex(vpn.StorageError, phrase.strip(), vpn.load, self.root, SESSION_ID, self.expected)
                    path.rmdir() if path.is_dir() and not path.is_symlink() else path.unlink()
                    path.write_bytes(original)
                    path.chmod(0o600)
        self.assertEqual(snapshot(self.elsewhere), self.outside)
        # Deleting a session removes a link itself and never what it points to.
        (directory / "wg0.conf").unlink()
        (directory / "wg0.conf").symlink_to(target)
        self.assertEqual(vpn.discard(self.root), [])
        self.assertFalse(directory.exists())
        self.assertEqual(snapshot(self.elsewhere), self.outside)

    @unittest.skipIf(vpn.OWNER is None, "this platform has no file ownership to check")
    def test_another_users_directory_or_file_is_refused_at_every_level(self):
        directory = self.local()

        def foreign(label):
            """Make the object with this label look as if another user owned it; everything else is real."""
            real = vpn.acceptable

            def check(found, status, private):
                if found == label:
                    status = os.stat_result(tuple(status[:4]) + (status.st_uid + 1,) + tuple(status[5:10]))
                return real(found, status, private)
            return patch.object(vpn, "acceptable", check)

        for label in (".runtime", ".runtime/vpn", f".runtime/vpn/{SESSION_ID}"):
            with self.subTest(label=label), foreign(label):
                skip = ("stage", "discard") if label.endswith(SESSION_ID) else ()
                self.assertAllRefuse("^" + re.escape(label) + " belongs to another user", skip=skip)
                if skip:
                    (session, reason), = vpn.discard(self.root)
                    self.assertIn("belongs to another user", reason)
                    self.assertEqual(sorted(p.name for p in directory.iterdir()), ["post-rules.txt", "wg0.conf"])
        with foreign(f".runtime/vpn/{SESSION_ID}/wg0.conf"):
            self.assertRaisesRegex(vpn.StorageError, "wg0.conf belongs to another user", vpn.load, self.root, SESSION_ID, self.expected)
            self.assertRaisesRegex(vpn.StorageError, "wg0.conf belongs to another user", vpn.sessions, self.root)
        self.assertEqual(vpn.load(self.root, SESSION_ID, self.expected), self.tunnel._replace(notices=()))

    @unittest.skipIf(vpn.OWNER is None, "this platform has no permission bits to check")
    def test_loose_or_missing_permissions_are_refused_and_never_repaired(self):
        directory = self.local()
        runtime, storage = self.root / ".runtime", self.root / ".runtime/vpn"
        cases = [(runtime, 0o777, r"^\.runtime can be changed by other users", ()),
                 (runtime, 0o775, r"^\.runtime can be changed by other users", ()),
                 (storage, 0o755, r"^\.runtime/vpn can be read or changed by other users", ()),
                 (storage, 0o701, r"^\.runtime/vpn can be read or changed by other users", ()),
                 (directory, 0o750, rf"^\.runtime/vpn/{SESSION_ID} can be read or changed by other users", ("stage", "discard"))]
        if os.geteuid() != 0:
            cases += [(storage, 0o000, r"^\.runtime/vpn could not be opened as a directory", ()),
                      (directory, 0o000, rf"^\.runtime/vpn/{SESSION_ID} could not be opened", ("stage", "discard"))]
        for path, mode, phrase, skip in cases:
            with self.subTest(path=path.name, mode=oct(mode)):
                original = stat.S_IMODE(path.stat().st_mode)
                path.chmod(mode)
                try:
                    self.assertAllRefuse(phrase, skip=skip)
                    if skip:
                        self.assertEqual([session for session, _ in vpn.discard(self.root)], [SESSION_ID])
                    self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), mode)   # not quietly chmod-ed back
                finally:
                    path.chmod(original)
                self.assertEqual(sorted(p.name for p in directory.iterdir()), ["post-rules.txt", "wg0.conf"])
        for mode in (0o644, 0o640, 0o604):
            with self.subTest(file_mode=oct(mode)):
                (directory / "wg0.conf").chmod(mode)
                self.assertRaisesRegex(vpn.StorageError, "wg0.conf can be read or changed by other users", vpn.load,
                                       self.root, SESSION_ID, self.expected)
                self.assertRaises(vpn.StorageError, vpn.sessions, self.root)
                self.assertEqual(stat.S_IMODE((directory / "wg0.conf").stat().st_mode), mode)
        (directory / "wg0.conf").chmod(0o600)
        self.assertEqual(vpn.sessions(self.root), [SESSION_ID])

    def test_ordinary_missing_storage_means_no_vpn_session_and_is_not_an_error(self):
        for prepare in (lambda: None, lambda: (self.root / ".runtime").mkdir(), lambda: (self.root / ".runtime/vpn").mkdir(mode=0o700)):
            prepare()
            with self.subTest(present=sorted(snapshot(self.root))):
                before = snapshot(self.root)
                self.assertEqual(vpn.sessions(self.root), [])
                self.assertEqual(vpn.discard(self.root), [])
                self.assertTrue(vpn.remove(self.root, SESSION_ID))
                self.assertRaisesRegex(vpn.ConfigError, "is missing", vpn.load, self.root, SESSION_ID, self.expected)
                self.assertRaisesRegex(vpn.ConfigError, "is missing", vpn.write_rules, self.root, SESSION_ID, SUBNET, self.tunnel)
                self.assertEqual(snapshot(self.root), before)     # looking creates nothing
        self.assertEqual(vpn.sessions(self.base / "no-such-checkout"), [])
        # Files that are not SafeBrowse's (a Finder .DS_Store, a note) do not make storage unsafe or get deleted.
        (self.root / ".runtime/vpn/.DS_Store").write_text("finder")
        (self.root / ".runtime/network.json").write_text("{}")
        self.assertEqual(vpn.sessions(self.root), [])
        directory = self.local()
        self.assertEqual(vpn.sessions(self.root), [SESSION_ID])
        self.assertEqual(vpn.discard(self.root), [])
        self.assertFalse(directory.exists())
        self.assertEqual((self.root / ".runtime/vpn/.DS_Store").read_text(), "finder")

    def test_operations_stay_inside_the_directory_that_was_checked(self):
        """The directory is opened once and used by descriptor, so swapping the path afterwards changes nothing."""
        if not vpn.ANCHORED:
            self.skipTest("this platform has no directory-relative file operations")
        directory = self.local()
        moved = self.root / ".runtime/vpn-moved"
        real = vpn.write_private

        def swap_then_write(checked, name, text):
            # Between the check and the write, the session path is replaced by a link to someone else's storage.
            directory.rename(moved)
            directory.symlink_to(self.elsewhere / ".runtime/vpn" / SESSION_ID)
            return real(checked, name, text)
        with patch.object(vpn, "write_private", swap_then_write):
            vpn.write_rules(self.root, SESSION_ID, "172.31.77.0/24", self.tunnel)
        self.assertEqual((moved / "post-rules.txt").read_text(), vpn.firewall_rules("172.31.77.0/24", self.tunnel))
        self.assertEqual(snapshot(self.elsewhere), self.outside)
        for name in ("resolve(", "realpath", "rmtree", "os.walk"):
            self.assertNotIn(name, (ROOT / "scripts/vpn.py").read_text())

    def test_path_based_fallback_applies_the_same_checks(self):
        """Where directory-relative operations are unavailable, every level is still checked before use."""
        with patch.object(vpn, "ANCHORED", False):
            directory = self.local()
            self.assertEqual(vpn.load(self.root, SESSION_ID, self.expected), self.tunnel._replace(notices=()))
            self.assertEqual(vpn.sessions(self.root), [SESSION_ID])
            self.assertEqual(vpn.discard(self.root), [])
            self.assertFalse(directory.exists())
            (self.root / ".runtime/vpn").rmdir()
            (self.root / ".runtime/vpn").symlink_to(self.elsewhere / ".runtime/vpn")
            self.assertAllRefuse(r"^\.runtime/vpn is a symbolic link")


class ModeCase(base.LauncherCase):
    def setUp(self):
        super().setUp()
        self.config = self.root / "mullvad.conf"
        self.config.write_text(export())
        self.config.chmod(0o600)
        (self.root / "security").mkdir()
        (self.root / "security/gluetun-auth.toml").write_bytes((ROOT / "security/gluetun-auth.toml").read_bytes())
        self.stored = []

    def store(self, session=SESSION_ID, text=None):
        """An existing VPN session's generated configuration."""
        directory = vpn.stage(self.root, session, vpn.parse(export()))
        vpn.write_rules(self.root, session, "172.31.9.0/24", vpn.parse(export()))
        if text is not None:
            (directory / "wg0.conf").write_text(text)
        self.stored = sorted(set(self.stored) | {session})
        return directory

    def invoke(self, *argv, **settings):
        # An existing VPN session was created from the file these tests store, and says so on its containers.
        if settings.get("mode") == "vpn":
            settings.setdefault("fingerprint", FINGERPRINT)
        return super().invoke(*argv, **settings)

    def stored_now(self):
        return vpn.sessions(self.root)

    def files(self, outcome, action):
        return {outcome.recorder.files[index] for index, call in enumerate(outcome.calls) if call[:3] == COMPOSE + [action]}

    def assertNoKey(self, outcome):
        """No key in any argument, environment value or line of output."""
        for secret in (PRIVATE, PUBLIC):
            for call, env in zip(outcome.calls, outcome.recorder.envs):
                self.assertFalse([value for value in call if secret in str(value)])
                self.assertFalse([name for name, value in (env or {}).items() if secret in value])
            self.assertNotIn(secret, outcome.stdout + outcome.stderr)


class ArgumentTests(ModeCase):
    def test_run_help_states_the_mode_semantics(self):
        outcome = self.launch("--help")
        self.assertEqual((outcome.code, outcome.calls), (0, []))
        for phrase in ("[--fresh | --resume] [--direct | --vpn mullvad] [--vpn-config PATH]", "never drops a VPN silently",
                       "not accepted with --resume", "Changing modes always needs --fresh"):
            self.assertIn(phrase, outcome.stdout)

    def test_conflicting_or_malformed_mode_arguments_fail_before_docker(self):
        config = str(self.config)
        for arguments in (("--direct", "--vpn", "mullvad"), ("--vpn", "mullvad", "--direct"), ("--direct", "--direct"),
                          ("--vpn", "mullvad", "--vpn", "mullvad"), ("--vpn",), ("--vpn", "proton"), ("--vpn", "--fresh"),
                          ("--vpn", ""), ("--vpn", "MULLVAD"), ("--vpn=mullvad",), ("--vpn-config", config),
                          ("--direct", "--vpn-config", config), ("--vpn", "mullvad", "--vpn-config"),
                          ("--vpn", "mullvad", "--vpn-config", ""), ("--vpn", "mullvad", "--vpn-config", config, "--vpn-config", config),
                          ("--resume", "--vpn", "mullvad", "--vpn-config", config), ("--vpn-config", config, "--resume", "--vpn", "mullvad"),
                          ("--allow-private-endpoint",), ("--vpn", "mullvad", "--private"), ("--mode", "vpn")):
            for existing in (False, True):
                with self.subTest(arguments=arguments, existing=existing):
                    outcome = self.launch(*arguments, existing=existing)
                    self.assertEqual(outcome.code, 1)
                    self.assertEqual(outcome.calls, [])
                    self.assertEqual(self.stored_now(), [])
                    self.assertFalse((self.root / ".runtime").exists())

    def test_inherited_compose_and_vpn_inputs_never_reach_a_process(self):
        hostile = {"COMPOSE_FILE": "/tmp/other.yml", "COMPOSE_PROJECT_NAME": "other", "COMPOSE_PROFILES": "debug",
                   "COMPOSE_ENV_FILES": "/tmp/env", "COMPOSE_PATH_SEPARATOR": ";", "SAFEBROWSE_SESSION": "attacker",
                   "SAFEBROWSE_VPN_DIR": "/tmp/attacker", "SAFEBROWSE_VPN_MTU": "9000", "SAFEBROWSE_VPN_KEEPALIVE": "1s",
                   "KEEP": "1"}
        for arguments in (("run",), ("run", "--vpn", "mullvad", "--vpn-config", str(self.config)), ("stop",), ("logs",), ("verify",)):
            with self.subTest(arguments=arguments):
                outcome = self.invoke(*arguments, environ=dict(hostile))
                self.assertEqual(outcome.code, 0, outcome.stderr)
                for env in outcome.recorder.envs:
                    self.assertEqual(env["KEEP"], "1")
                    self.assertFalse([name for name in env if name.startswith("COMPOSE_")])
                    for name in ("SAFEBROWSE_SESSION", "SAFEBROWSE_VPN_DIR", "SAFEBROWSE_VPN_MTU", "SAFEBROWSE_VPN_KEEPALIVE"):
                        self.assertNotEqual(env.get(name), hostile[name])
                for value in ("/tmp/other.yml", "/tmp/attacker", "attacker"):
                    self.assertNotIn(value, outcome.stdout + outcome.stderr)
                if arguments[0] == "run":
                    self.assertIn("ignoring COMPOSE_ENV_FILES, COMPOSE_FILE, COMPOSE_PATH_SEPARATOR, COMPOSE_PROFILES, "
                                  "COMPOSE_PROJECT_NAME", outcome.stdout)
                __import__("shutil").rmtree(self.root / ".runtime", True)


class ModeSelectionTests(ModeCase):
    def test_first_session_defaults_to_direct_and_every_compose_call_names_one_topology(self):
        outcome = self.launch("--url", "https://example.com/")
        self.assertEqual(outcome.code, 0, outcome.stderr)
        selected = {files for files in outcome.recorder.files if files is not None}
        self.assertEqual(selected, {DIRECT})
        self.assertIn("direct: the gateway uses this computer's own connection", outcome.stdout)
        self.assertEqual(self.stored_now(), [])
        sessions = {env["SAFEBROWSE_SESSION"] for call, env in zip(outcome.calls, outcome.recorder.envs)
                    if call[:3] in (COMPOSE + ["config"], COMPOSE + ["up"])}
        self.assertEqual(len(sessions), 1)
        self.assertRegex(sessions.pop(), r"^[0-9a-f]{16}$")
        self.assertFalse(any("SAFEBROWSE_VPN_DIR" in (env or {}) for env in outcome.recorder.envs))

    def test_new_vpn_session_needs_a_provider_and_a_configuration(self):
        (self.root / ".env").unlink()
        outcome = self.launch("--vpn", "mullvad")
        self.assertEqual(outcome.code, 1)
        self.assertIn("needs a configuration: --vpn mullvad --vpn-config PATH", outcome.stderr)
        self.assertSessionUntouched(outcome)
        self.assertFalse((self.root / ".env").exists())   # not even credentials were created
        self.assertFalse((self.root / ".runtime").exists())

    def test_vpn_session_uses_only_the_vpn_topology_and_never_exposes_a_key(self):
        outcome = self.launch("--vpn", "mullvad", "--vpn-config", str(self.config), "--url", "https://example.com/")
        self.assertEqual(outcome.code, 0, outcome.stderr)
        after_check = outcome.recorder.files[next(i for i, call in enumerate(outcome.calls) if call[:3] == COMPOSE + ["config"]):]
        self.assertEqual({files for files in after_check if files is not None}, {VPN})
        self.assertIn("VPN: the gateway's only route out is the WireGuard tunnel", outcome.stdout)
        self.assertNotIn("direct:", outcome.stdout)
        for phrase in ("IPv6 interface address was left out", "IPv6 route (::/0) was left out", "DNS setting was not used"):
            self.assertIn(phrase, outcome.stdout)
        self.assertNoKey(outcome)
        self.assertNotIn("185.213.154.68", " ".join(" ".join(map(str, call)) for call in outcome.calls))
        stored = self.stored_now()
        self.assertEqual(len(stored), 1)
        directory = self.root / ".runtime/vpn" / stored[0]
        up = outcome.recorder.env_of(COMPOSE + ["up", "-d"])
        self.assertEqual((up["SAFEBROWSE_SESSION"], up["SAFEBROWSE_VPN_DIR"], up["SAFEBROWSE_VPN_MTU"], up["SAFEBROWSE_VPN_KEEPALIVE"]),
                         (stored[0], str(directory), "1320", "0"))
        self.assertEqual({stat.S_IMODE(p.stat().st_mode) for p in directory.iterdir()}, {0o600})
        self.assertEqual((directory / "post-rules.txt").read_text(), vpn.firewall_rules("172.31.0.0/24", vpn.parse(export())))
        self.assertEqual(self.config.read_text(), export())
        self.assertEqual(outcome.calls[-1], ["open_url.py", "https://example.com/"])
        self.assertLess(outcome.calls.index(["verify.py", "--wait-browser"]), len(outcome.calls) - 1)

    def test_preparation_precedes_teardown_and_uses_the_target_topology(self):
        self.store()
        outcome = self.launch("--fresh", "--vpn", "mullvad", "--vpn-config", str(self.config), existing=True, mode="vpn")
        self.assertEqual(outcome.code, 0, outcome.stderr)
        order = [next(i for i, call in enumerate(outcome.calls) if call[:len(prefix)] == prefix) for prefix in
                 (COMPOSE + ["config"], COMPOSE + ["build"], ["docker", "image", "inspect"], DOWN, COMPOSE + ["up"])]
        self.assertEqual(order, sorted(order))
        self.assertEqual(self.files(outcome, "down") | self.files(outcome, "up") | self.files(outcome, "build"), {VPN})
        # The replaced session's secrets go once it is gone; the new session's are the only ones left.
        self.assertEqual(len(self.stored_now()), 1)
        self.assertNotEqual(self.stored_now(), [SESSION_ID])

    def test_rejected_configuration_changes_nothing(self):
        hooked, link = self.root / "hooked.conf", self.root / "link.conf"
        hooked.write_text(export(interface="PostUp = id\n"))
        link.symlink_to(self.config)
        (self.root / "host.conf").write_text(export(endpoint="se-got-wg-001.relays.mullvad.net:51820"))
        (self.root / "private.conf").write_text(export(endpoint="10.0.0.5:51820"))
        self.store()
        for name, phrase in (("hooked.conf", "command hook"), ("link.conf", "symbolic link"), ("absent.conf", "could not be opened"),
                             ("host.conf", "literal IPv4"), ("private.conf", "not a public"), ("gateway", "not a regular file")):
            for settings in ({}, {"existing": True}, {"existing": True, "mode": "vpn"}):
                with self.subTest(name=name, settings=settings):
                    action = ("--fresh",) if settings else ()
                    outcome = self.launch(*action, "--vpn", "mullvad", "--vpn-config", str(self.root / name), **settings)
                    self.assertEqual(outcome.code, 1)
                    self.assertIn("was not accepted; nothing was changed", outcome.stderr)
                    self.assertIn(phrase, outcome.stderr)
                    self.assertSessionUntouched(outcome)
                    self.assertNoKey(outcome)

    def test_failed_preparation_keeps_the_existing_session_and_its_configuration(self):
        self.store()
        original = (self.root / ".runtime/vpn" / SESSION_ID / "wg0.conf").read_text()

        def gateway_keeps_a_network(model):
            model["services"]["gateway"]["networks"] = {"egress_net": None}

        def extra_attachment(model):
            model["services"]["vpn"]["networks"]["other"] = None

        def published(model):
            model["services"]["vpn"]["ports"] = [{"host_ip": "0.0.0.0", "published": "8000", "target": 8000}]

        def more_capabilities(model):
            model["services"]["vpn"]["cap_add"].append("SYS_ADMIN")

        def wrong_mount(model):
            model["services"]["vpn"]["volumes"][0]["source"] = "/home/user/mullvad.conf"

        def writable(model):
            model["services"]["vpn"]["volumes"][0]["read_only"] = False

        def browser_mount(model):
            model["services"]["safebrowse"]["volumes"] = [{"type": "bind", "source": "/", "target": "/host"}]

        def restarting(model):
            model["services"]["vpn"]["restart"] = "always"

        def device(model):
            model["services"]["vpn"]["devices"] = [{"source": "/dev/net/tun", "target": "/dev/net/tun"}]

        def alias(model):
            model["services"]["vpn"]["networks"]["egress_net"]["aliases"] = ["gateway"]

        def unlabelled(model):
            del model["services"]["vpn"]["labels"]["safebrowse.mode"]

        def stray(model):
            model["services"]["helper"] = {"image": "example/helper"}

        def lan_desktop(model):
            model["services"]["uiproxy"]["ports"][0]["host_ip"] = "0.0.0.0"

        cases = [({"model": mutate}, "is not SafeBrowse's vpn topology") for mutate in (
            gateway_keeps_a_network, extra_attachment, published, more_capabilities, wrong_mount, writable, browser_mount,
            restarting, device, alias, unlabelled, stray, lan_desktop)]
        cases += [({"config_exit": 1}, "could not be read"), ({"build_exit": 1}, "build failed"),
                  ({"image_exit": 1, "pull_exit": 1}, "could not fetch")]
        for settings, phrase in cases:
            with self.subTest(case=str(settings)[:60]):
                outcome = self.launch("--fresh", "--vpn", "mullvad", "--vpn-config", str(self.config), existing=True,
                                      mode="vpn", **settings)
                self.assertEqual(outcome.code, 1)
                self.assertIn(phrase, outcome.stderr)
                self.assertIn("xisting session was not discarded", outcome.stderr)
                self.assertEqual(outcome.recorder.compose("down") + outcome.recorder.compose("up"), [])
                self.assertEqual(self.stored_now(), [SESSION_ID])  # the staged replacement is gone, the original intact
                self.assertEqual((self.root / ".runtime/vpn" / SESSION_ID / "wg0.conf").read_text(), original)
                self.assertNoKey(outcome)

    def test_vpn_launch_requires_the_reviewed_control_server_lock(self):
        lock = self.root / "security/gluetun-auth.toml"
        reviewed = lock.read_bytes()
        self.store()
        for label, damage in (("missing", lambda: lock.unlink()), ("crlf", lambda: lock.write_bytes(reviewed.replace(b"\n", b"\r\n"))),
                              ("opened up", lambda: lock.write_bytes(reviewed.replace(b"GET /v1/version", b"PUT /v1/vpn/status"))),
                              ("a link", lambda: (lock.unlink(), lock.symlink_to(self.config)))):
            with self.subTest(case=label):
                damage()
                outcome = self.launch("--fresh", "--vpn", "mullvad", "--vpn-config", str(self.config), existing=True, mode="vpn")
                self.assertEqual(outcome.code, 1)
                self.assertIn("control server would not be locked. Nothing was changed", outcome.stderr)
                self.assertSessionUntouched(outcome)
                if lock.is_symlink() or lock.exists():
                    lock.unlink()
                lock.write_bytes(reviewed)
        # A direct session does not depend on the file.
        lock.unlink()
        self.assertEqual(self.launch("--fresh", "--direct", existing=True, mode="vpn").code, 0)
        self.stored = []

    def test_direct_topology_is_checked_as_well(self):
        def carries_a_vpn(model):
            model["services"]["vpn"] = {"image": "qmcgaw/gluetun"}

        def shares_a_namespace(model):
            model["services"]["gateway"]["network_mode"] = "service:vpn"

        for mutate in (carries_a_vpn, shares_a_namespace):
            with self.subTest(case=mutate.__name__):
                outcome = self.launch(model=mutate)
                self.assertEqual(outcome.code, 1)
                self.assertIn("is not SafeBrowse's direct topology", outcome.stderr)
                self.assertEqual(outcome.recorder.compose("down") + outcome.recorder.compose("up"), [])

    def test_missing_images_are_fetched_before_the_old_session_is_discarded(self):
        outcome = self.launch("--fresh", "--vpn", "mullvad", "--vpn-config", str(self.config), existing=True, image_exit=1)
        self.assertEqual(outcome.code, 0, outcome.stderr)
        pulls = [call for call in outcome.calls if call[:2] == ["docker", "pull"]]
        self.assertEqual(len(pulls), 3)
        self.assertTrue(all("@sha256:" in call[-1] for call in pulls))
        self.assertLess(outcome.calls.index(pulls[-1]), outcome.calls.index(DOWN))

    def test_subnet_retry_rewrites_the_firewall_rules_for_the_new_subnet(self):
        seen = []
        recorder_answer = base.Recorder.answer

        def answer(recorder, call):
            if call[:3] == COMPOSE + ["up"]:
                directory = Path(recorder.env["SAFEBROWSE_VPN_DIR"])
                seen.append((recorder.env["SANDBOX_SUBNET"], (directory / "post-rules.txt").read_text()))
            return recorder_answer(recorder, call)
        with patch.object(base.Recorder, "answer", answer):
            outcome = self.launch("--vpn", "mullvad", "--vpn-config", str(self.config), overlaps=1)
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual([subnet for subnet, _ in seen], ["172.31.0.0/24", "172.31.1.0/24"])
        for subnet, rules in seen:
            self.assertEqual(rules, vpn.firewall_rules(subnet, vpn.parse(export())))

    def test_a_vpn_that_does_not_start_never_becomes_a_direct_session(self):
        outcome = self.launch("--vpn", "mullvad", "--vpn-config", str(self.config), up_exit=1,
                              up_text="dependency failed to start: container safebrowse-vpn is unhealthy\n")
        self.assertEqual(outcome.code, 1)
        self.assertIn("did not fall back to a direct session", outcome.stderr)
        self.assertEqual(len(outcome.recorder.compose("up")), 1)
        self.assertEqual({files for files in outcome.recorder.files if files is not None} - {VPN}, {DIRECT})  # only before selection
        self.assertEqual(self.files(outcome, "up") | self.files(outcome, "logs") | self.files(outcome, "down"), {VPN})
        self.assertEqual(outcome.calls.count(DOWN), 1)  # the pre-start cleanup; the failed session remains for diagnosis
        self.assertEqual(outcome.desktop.requests, [])
        self.assertFalse(any(call[0] in ("open_url.py", "verify.py") for call in outcome.calls))
        self.assertEqual(len(self.stored_now()), 1)

    def test_url_is_dispatched_only_after_vpn_verification_passes(self):
        for verify_exit, code in ((1, 1), (2, 2)):
            with self.subTest(verify_exit=verify_exit):
                outcome = self.launch("--vpn", "mullvad", "--vpn-config", str(self.config), "--url", "https://example.com/",
                                      verify_exit=verify_exit)
                self.assertEqual(outcome.code, code)
                self.assertNotIn(["open_url.py", "https://example.com/"], outcome.calls)
                self.assertEqual(outcome.calls.count(DOWN), 1)  # never torn down or repaired after a failed check
                self.assertEqual(len(outcome.recorder.compose("up")), 1)
                __import__("shutil").rmtree(self.root / ".runtime")


class ResumeTests(ModeCase):
    def test_resume_detects_the_mode_and_recreates_nothing(self):
        for mode, files in (("direct", DIRECT), ("vpn", VPN)):
            with self.subTest(mode=mode):
                if mode == "vpn":
                    self.store()
                outcome = self.launch("--resume", "--url", "https://example.com/", existing=True, mode=mode)
                self.assertEqual(outcome.code, 0, outcome.stderr)
                self.assertSessionUntouched(outcome)
                self.assertIn(["verify.py", "--wait-browser"], outcome.calls)
                self.assertIn("VPN: the gateway" if mode == "vpn" else "direct: the gateway", outcome.stdout)
                self.assertNoKey(outcome)

    def test_resume_accepts_a_consistent_mode_and_refuses_a_conflicting_one(self):
        self.store()
        for mode, same, other in (("direct", ("--direct",), ("--vpn", "mullvad")), ("vpn", ("--vpn", "mullvad"), ("--direct",))):
            with self.subTest(mode=mode):
                self.assertEqual(self.launch("--resume", *same, existing=True, mode=mode).code, 0)
                outcome = self.launch("--resume", *other, existing=True, mode=mode)
                self.assertEqual(outcome.code, 1)
                self.assertIn(f"is a {mode} session and --resume never changes the mode", outcome.stderr)
                self.assertSessionUntouched(outcome)
                self.assertFalse(any(call[0] in ("open_url.py", "verify.py", "network.py") for call in outcome.calls))

    def test_resume_uses_the_vpn_topology_for_diagnostics(self):
        self.store()
        outcome = self.launch("--resume", existing=True, mode="vpn", desktop=base.Desktop(anonymous=500))
        self.assertEqual(outcome.code, 1)
        self.assertEqual(self.files(outcome, "logs"), {VPN})
        self.assertSessionUntouched(outcome)

    def test_resume_requires_the_whole_vpn_session_to_be_running(self):
        self.store()
        for containers, phrase in (({"browser": True, "gateway": True, "ui": True}, "session is incomplete"),
                                   ({"browser": True, "gateway": True, "ui": True, "vpn": False}, "session is not running"),
                                   ({"vpn": True}, "session is incomplete")):
            with self.subTest(containers=containers):
                outcome = self.launch("--resume", containers=containers, mode="vpn")
                self.assertEqual(outcome.code, 1)
                self.assertIn(phrase, outcome.stderr)
                self.assertIn("use --fresh", outcome.stderr)
                self.assertSessionUntouched(outcome)   # nothing is restarted to repair it
                self.assertEqual(outcome.desktop.requests, [])

    def test_unknown_or_contradictory_modes_are_never_resumed(self):
        self.store()
        direct = {"browser": "direct", "gateway": "direct", "ui": "direct"}
        cases = (({"mode": "legacy", "existing": True}, "older SafeBrowse"),
                 ({"containers": {"browser": True, "gateway": True, "ui": True, "vpn": True}, "labels": direct, "mode": "vpn"}, "cannot be established"),
                 ({"containers": {"browser": True, "gateway": True, "ui": True, "vpn": True}, "mode": "direct"}, "cannot be established"),
                 ({"existing": True, "labels": {"gateway": "vpn"}}, "cannot be established"),
                 ({"existing": True, "session": "NOT VALID"}, "cannot be established"),
                 ({"existing": True, "mode": "tor"}, "cannot be established"))
        for settings, phrase in cases:
            for arguments in (("--resume",), ("--fresh",), ("--resume", "--url", "https://example.com/")):
                with self.subTest(settings=str(settings)[:50], arguments=arguments):
                    outcome = self.launch(*arguments, **settings)
                    self.assertEqual(outcome.code, 1)
                    self.assertIn(phrase, outcome.stderr)
                    self.assertIn("./run.sh --fresh --direct", outcome.stderr)
                    self.assertIn("./stop.sh still removes it", outcome.stderr)
                    self.assertSessionUntouched(outcome)
        # With an explicit target mode, a fresh launch may replace such a session.
        outcome = self.launch("--fresh", "--direct", existing=True, mode="legacy")
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.stored = []

    def test_inspection_failure_is_not_read_as_no_session(self):
        outcome = self.launch(inspect_exit=1)
        self.assertEqual(outcome.code, 1)
        self.assertIn("could not inspect the existing session; nothing was changed", outcome.stderr)
        self.assertSessionUntouched(outcome)


class FreshTests(ModeCase):
    def test_fresh_without_a_mode_keeps_the_existing_mode(self):
        outcome = self.launch("--fresh", existing=True)
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual(self.files(outcome, "up") | self.files(outcome, "down"), {DIRECT})
        self.store()
        outcome = self.launch("--fresh", existing=True, mode="vpn")
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual(self.files(outcome, "up") | self.files(outcome, "down") | self.files(outcome, "build"), {VPN})
        self.assertIn("VPN: the gateway's only route out", outcome.stdout)
        replacement = self.stored_now()
        self.assertEqual(len(replacement), 1)
        self.assertNotEqual(replacement, [SESSION_ID])   # staged separately, old one removed after teardown
        self.assertEqual(vpn.load(self.root, replacement[0], FINGERPRINT), vpn.parse(export())._replace(notices=()))
        self.assertNoKey(outcome)

    def test_fresh_never_downgrades_a_vpn_session_whose_configuration_is_gone_or_damaged(self):
        cases = {"missing": None, "damaged": "garbage", "widened": vpn.render(vpn.parse(export())).replace(
            "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 10.0.0.0/8"), "hooked": vpn.render(vpn.parse(export())) + "PostUp = id\n"}
        for label, text in cases.items():
            for arguments in (("--fresh",), ("--fresh", "--vpn", "mullvad")):
                with self.subTest(case=label, arguments=arguments):
                    __import__("shutil").rmtree(self.root / ".runtime", True)
                    self.stored = []
                    if text is not None:
                        self.store(text=text)
                    outcome = self.launch(*arguments, existing=True, mode="vpn")
                    self.assertEqual(outcome.code, 1)
                    self.assertIn("stored configuration cannot be reused", outcome.stderr)
                    self.assertIn("--fresh --vpn mullvad --vpn-config PATH", outcome.stderr)
                    self.assertIn("--fresh --direct", outcome.stderr)
                    self.assertSessionUntouched(outcome)
                    self.assertEqual(self.files(outcome, "up"), set())

    def test_explicit_mode_changes_replace_the_topology_and_the_secrets(self):
        self.store()
        outcome = self.launch("--fresh", "--direct", existing=True, mode="vpn")
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual(self.files(outcome, "down") | self.files(outcome, "up"), {DIRECT})
        self.assertIn("direct: the gateway", outcome.stdout)
        self.assertEqual(self.stored_now(), [])     # removed once the VPN session was torn down
        self.assertLess(outcome.calls.index(DOWN), len(outcome.calls))
        outcome = self.launch("--fresh", "--vpn", "mullvad", "--vpn-config", str(self.config), existing=True, mode="direct")
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual(self.files(outcome, "down") | self.files(outcome, "up"), {VPN})
        self.assertEqual(len(self.stored_now()), 1)

    def test_switching_to_vpn_needs_a_configuration(self):
        outcome = self.launch("--fresh", "--vpn", "mullvad", existing=True, mode="direct")
        self.assertEqual(outcome.code, 1)
        self.assertIn("needs a configuration", outcome.stderr)
        self.assertSessionUntouched(outcome)

    def test_generated_secrets_survive_until_the_old_session_is_actually_removed(self):
        self.store()
        outcome = self.launch("--fresh", "--direct", existing=True, mode="vpn", down_exit=1)
        self.assertEqual(outcome.code, 1)
        self.assertIn("could not discard the previous session", outcome.stderr)
        self.assertEqual(self.stored_now(), [SESSION_ID])
        self.assertEqual(outcome.recorder.compose("up"), [])

    def test_leftover_vpn_configuration_without_a_session_is_never_read_as_direct(self):
        self.store()
        for arguments in ((), ("--fresh",)):
            with self.subTest(arguments=arguments):
                outcome = self.launch(*arguments)
                self.assertEqual(outcome.code, 1)
                self.assertIn("SafeBrowse will not guess", outcome.stderr)
                self.assertIn("./run.sh --direct", outcome.stderr)
                self.assertSessionUntouched(outcome)
        outcome = self.launch("--direct")
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual(self.stored_now(), [])
        self.stored = []


class LifecycleCommandTests(ModeCase):
    def test_stop_works_in_either_mode_and_removes_generated_secrets_only(self):
        for mode, files in (("direct", DIRECT), ("vpn", VPN)):
            with self.subTest(mode=mode):
                self.store()
                outcome = self.invoke("stop", existing=True, mode=mode)
                self.assertEqual(outcome.code, 0, outcome.stderr)
                self.assertEqual(self.others(outcome), [DOWN])
                self.assertEqual(self.files(outcome, "down"), {files})
                self.assertEqual(outcome.recorder.env_of(DOWN)["SANDBOX_PASSWORD"], "unused-for-teardown")
                self.assertNotIn("SAFEBROWSE_VPN_DIR", outcome.recorder.env_of(DOWN))  # no secret is needed to parse the file
                self.assertEqual(self.stored_now(), [])
                self.assertEqual(self.config.read_text(), export())
                self.assertIn("generated VPN configuration removed", outcome.stdout)

    def test_stop_needs_no_credentials_metadata_or_vpn_configuration(self):
        (self.root / ".env").unlink()
        for settings in ({"existing": True, "mode": "vpn"}, {"existing": True, "mode": "legacy"},
                         {"containers": {"vpn": True}, "mode": "vpn"}, {"containers": {"vpn": False}, "mode": "legacy"}, {}):
            with self.subTest(settings=settings):
                outcome = self.invoke("stop", **settings)
                self.assertEqual(outcome.code, 0, outcome.stderr)
                self.assertEqual(self.others(outcome), [DOWN])
                self.assertFalse((self.root / ".env").exists())
                self.assertFalse((self.root / ".runtime").exists())
        # A session with a VPN container is torn down with the VPN topology, whatever its labels say.
        self.assertEqual(self.files(self.invoke("stop", containers={"vpn": False}, mode="legacy"), "down"), {VPN})

    def test_stop_still_tears_down_when_the_session_cannot_be_inspected(self):
        outcome = self.invoke("stop", inspect_exit=1)
        self.assertEqual(self.others(outcome), [DOWN])
        self.assertEqual(outcome.code, 1)   # it could not confirm that nothing is left
        self.assertIn("could not be checked", outcome.stderr)
        self.assertNotIn("destroyed", outcome.stdout)

    def test_stop_reports_containers_that_survive_teardown_and_keeps_their_secrets(self):
        self.store()
        outcome = self.invoke("stop", existing=True, mode="vpn", leftover={"vpn": True, "gateway": True})
        self.assertEqual(outcome.code, 1)
        self.assertIn("these containers still exist: safebrowse-gw, safebrowse-vpn", outcome.stderr)
        self.assertNotIn("destroyed", outcome.stdout)
        self.assertEqual(self.stored_now(), [SESSION_ID])

    def test_failed_teardown_keeps_generated_secrets(self):
        self.store()
        outcome = self.invoke("stop", existing=True, mode="vpn", down_exit=3)
        self.assertEqual(outcome.code, 3)
        self.assertEqual(self.stored_now(), [SESSION_ID])

    def test_logs_include_the_vpn_container_only_when_there_is_one(self):
        outcome = self.invoke("logs", "7", existing=True, mode="vpn")
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual(outcome.calls[-1], ["docker", "logs", "--tail", "7", "safebrowse-vpn"])
        self.assertIn("VPN diagnostics", outcome.stdout)
        outcome = self.invoke("logs", existing=True, mode="vpn", gateway="exited")
        self.assertEqual((outcome.code, outcome.calls[-1]), (1, ["docker", "logs", "--tail", "50", "safebrowse-vpn"]))
        self.assertNotIn(["docker", "logs", "--tail", "50", "safebrowse-vpn"], self.invoke("logs").calls)

    def test_verify_is_delegated_unchanged_in_either_mode(self):
        for mode in ("direct", "vpn"):
            for code in (0, 1, 2):
                outcome = self.invoke("verify", existing=True, mode=mode, verify_exit=code)
                self.assertEqual((outcome.code, outcome.calls), (code, [["verify.py"]]))


class UnsafeStorageLaunchTests(ModeCase):
    """Unsafe VPN storage stops run before anything exists or changes, and is never read as "no VPN session"."""

    def setUp(self):
        super().setUp()
        self.elsewhere = self.root.parent / (self.root.name + "-elsewhere")
        self.elsewhere.mkdir()
        self.addCleanup(__import__("shutil").rmtree, self.elsewhere, True)
        vpn.stage(self.elsewhere, SESSION_ID, vpn.parse(export()))
        vpn.write_rules(self.elsewhere, SESSION_ID, SUBNET, vpn.parse(export()))
        self.outside = snapshot(self.elsewhere)

    def layouts(self):
        runtime, storage = self.root / ".runtime", self.root / ".runtime/vpn"
        return {
            "runtime is a link": lambda: runtime.symlink_to(self.elsewhere / ".runtime"),
            "vpn is a link to real storage": lambda: (runtime.mkdir(), storage.symlink_to(self.elsewhere / ".runtime/vpn")),
            "vpn is a dangling link": lambda: (runtime.mkdir(), storage.symlink_to(self.root / "nowhere")),
            "vpn is a file": lambda: (runtime.mkdir(), storage.write_text("x")),
            "vpn is open to others": lambda: (runtime.mkdir(), storage.mkdir(mode=0o755), storage.chmod(0o755)),
            "session is a link": lambda: (runtime.mkdir(), storage.mkdir(mode=0o700),
                                          (storage / SESSION_ID).symlink_to(self.elsewhere / ".runtime/vpn" / SESSION_ID)),
        }

    def reset(self):
        runtime = self.root / ".runtime"
        if runtime.is_symlink():
            runtime.unlink()
        __import__("shutil").rmtree(runtime, True)

    def test_run_fresh_and_resume_refuse_before_credentials_staging_or_docker(self):
        config = str(self.config)
        commands = ((), ("--direct",), ("--fresh",), ("--fresh", "--direct"), ("--resume",), ("--vpn", "mullvad", "--vpn-config", config),
                    ("--fresh", "--vpn", "mullvad", "--vpn-config", config), ("--resume", "--url", "https://example.com/"))
        sessions = ({}, {"existing": True}, {"existing": True, "mode": "vpn"})
        (self.root / ".env").unlink()
        for label, make in self.layouts().items():
            make()
            before = snapshot(self.root)
            for arguments in commands:
                for settings in sessions:
                    with self.subTest(layout=label, arguments=arguments, settings=settings):
                        outcome = self.launch(*arguments, **settings)
                        self.assertEqual(outcome.code, 1)
                        self.assertIn("will not read, write or delete", outcome.stderr)
                        self.assertIn("Nothing was changed, and no session was started in either mode", outcome.stderr)
                        self.assertEqual(outcome.calls, [])                 # Docker was not even asked a question
                        self.assertEqual(outcome.desktop.requests, [])
                        self.assertNotIn("direct", outcome.stdout)          # never a fallback to direct mode
                        self.assertNoKey(outcome)
            self.assertEqual(snapshot(self.root), before)                   # no .env, nothing staged, nothing deleted
            self.assertEqual(snapshot(self.elsewhere), self.outside)
            self.reset()

    def test_linked_storage_no_longer_reads_as_a_first_direct_session(self):
        """The reported case: storage with a VPN session in it, reached through a link, started a direct session."""
        (self.root / ".runtime").mkdir()
        (self.root / ".runtime/vpn").symlink_to(self.elsewhere / ".runtime/vpn")
        outcome = self.launch()
        self.assertEqual(outcome.code, 1)
        self.assertIn(".runtime/vpn is a symbolic link", outcome.stderr)
        self.assertEqual(outcome.recorder.compose("up") + outcome.recorder.compose("down"), [])

    def test_stop_removes_containers_then_reports_that_secrets_were_not_cleaned_up(self):
        for label, make in self.layouts().items():
            for settings in ({"existing": True, "mode": "vpn"}, {"existing": True}, {}):
                with self.subTest(layout=label, settings=settings):
                    make()
                    before = snapshot(self.root)
                    outcome = self.invoke("stop", **settings)
                    self.assertEqual(self.others(outcome), [DOWN])              # the containers are still removed
                    self.assertEqual(outcome.code, 1)
                    self.assertNotIn("destroyed", outcome.stdout + outcome.stderr)
                    self.assertNotIn("removed;", outcome.stdout)
                    if label == "session is a link":
                        self.assertIn("was not removed completely", outcome.stderr)
                        self.assertIn("is a symbolic link", outcome.stdout)
                    else:
                        self.assertIn("generated VPN configuration could not be cleaned up", outcome.stderr)
                        self.assertIn("will not read, write or delete", outcome.stderr)
                    self.assertEqual(snapshot(self.root), before)
                    self.assertEqual(snapshot(self.elsewhere), self.outside)
                    self.reset()

    def test_stop_reports_files_it_did_not_create_and_only_then_claims_success(self):
        directory = self.store()
        (directory / "notes.txt").write_text("mine")
        outcome = self.invoke("stop", existing=True, mode="vpn")
        self.assertEqual((outcome.code, self.others(outcome)), (1, [DOWN]))
        self.assertIn("1 entry that SafeBrowse did not create", outcome.stdout)
        self.assertIn("was not removed completely", outcome.stderr)
        self.assertIn("may still hold a WireGuard private key", outcome.stderr)
        self.assertNotIn("destroyed", outcome.stdout)
        self.assertEqual({p.name for p in directory.iterdir()}, {"notes.txt"})   # the generated files are gone
        (directory / "notes.txt").unlink()
        outcome = self.invoke("stop")
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertIn("Sandbox destroyed", outcome.stdout)
        self.assertEqual(self.stored_now(), [])
        self.stored = []

    def test_storage_that_turns_unsafe_after_teardown_starts_nothing(self):
        self.store()
        answer = base.Recorder.answer

        def swap_on_teardown(recorder, call):
            if call[:3] == COMPOSE + ["down"]:
                storage = self.root / ".runtime/vpn"
                storage.rename(self.root / ".runtime/vpn-real")
                storage.symlink_to(self.elsewhere / ".runtime/vpn")
            return answer(recorder, call)
        for arguments in (("--fresh", "--direct"), ("--fresh", "--vpn", "mullvad", "--vpn-config", str(self.config))):
            with self.subTest(arguments=arguments), patch.object(base.Recorder, "answer", swap_on_teardown):
                outcome = self.launch(*arguments, existing=True, mode="vpn")
                self.assertEqual(outcome.code, 1)
                self.assertRegex(outcome.stderr, "no new session was started|Nothing was started")
                self.assertEqual(outcome.recorder.compose("up"), [])
                self.assertEqual(snapshot(self.elsewhere), self.outside)
                # A key file staged for the replacement cannot be removed through unsafe storage: it is reported.
                self.assertEqual("could not be removed and is still in .runtime/vpn/" in outcome.stderr, "--vpn" in arguments)
                (self.root / ".runtime/vpn").unlink()
                __import__("shutil").rmtree(self.root / ".runtime/vpn-real")
                (self.root / ".runtime/vpn").mkdir(mode=0o700)
                self.store()


ALL_ROLES = {"browser": True, "gateway": True, "ui": True, "vpn": True}
ALL_NAMES = "safebrowse, safebrowse-gw, safebrowse-ui, safebrowse-vpn"


class TeardownConfirmationTests(ModeCase):
    """A teardown that reports success is not taken as proof that the old session's containers are gone."""

    def replacements(self):
        return (("--fresh",), ("--fresh", "--vpn", "mullvad", "--vpn-config", str(self.config)), ("--fresh", "--direct"))

    def discovered_between(self, outcome, first, second):
        """The container names inspected between two recorded calls."""
        calls = outcome.calls
        start, end = calls.index(first), next(i for i, call in enumerate(calls) if call[:3] == second)
        return [call[-1] for call in calls[start + 1:end] if call[:-1] == base.discovery("")[:-1]]

    def test_fresh_after_a_project_rename_keeps_the_running_sessions_configuration(self):
        """compose down exits 0 but removes nothing: the containers belong to another Compose project."""
        self.store()
        before = snapshot(self.root / ".runtime")
        for arguments in self.replacements():
            with self.subTest(arguments=arguments):
                outcome = self.launch(*arguments, existing=True, mode="vpn", leftover=dict(ALL_ROLES))
                self.assertEqual(outcome.code, 1)
                self.assertIn(f"these containers still exist: {ALL_NAMES}", outcome.stderr)
                for phrase in ("do not belong to this checkout's Compose project", "does not remove another project's containers",
                               "No new session was started", "was left in place", "run ./stop.sh there",
                               "'docker rm --force' and the names above"):
                    self.assertIn(phrase, outcome.stderr)
                self.assertEqual(snapshot(self.root / ".runtime"), before)        # byte for byte, and nothing staged is left
                self.assertEqual(self.stored_now(), [SESSION_ID])
                self.assertEqual(outcome.recorder.compose("up"), [])
                self.assertEqual(outcome.recorder.compose("down"), [DOWN])        # one teardown of this project, no second try
                self.assertEqual([call for call in outcome.calls if call[:2] == ["docker", "rm"] or "kill" in call
                                  or call[0] == "network.py" and call[1] == "select"], [])
                self.assertNotIn(".runtime/vpn/", outcome.stderr)                # nothing was retained, so nothing to report
                self.assertNoKey(outcome)

    def test_partly_surviving_and_direct_sessions_are_refused_the_same_way(self):
        self.store()
        for mode, leftover, names in (("vpn", {"vpn": True}, "safebrowse-vpn"), ("vpn", {"gateway": False}, "safebrowse-gw"),
                                      ("direct", {"browser": True}, "safebrowse")):
            with self.subTest(mode=mode, leftover=leftover):
                outcome = self.launch("--fresh", "--direct", existing=True, mode=mode, leftover=leftover)
                self.assertEqual(outcome.code, 1)
                self.assertIn(f"these containers still exist: {names}.", outcome.stderr)
                self.assertEqual(self.stored_now(), [SESSION_ID])
                self.assertEqual(outcome.recorder.compose("up"), [])

    def test_teardown_that_cannot_be_confirmed_starts_nothing_and_keeps_the_configuration(self):
        self.store()
        before = snapshot(self.root / ".runtime")
        for arguments in self.replacements():
            with self.subTest(arguments=arguments):
                outcome = self.launch(*arguments, existing=True, mode="vpn", inspect_exit_after_down=1)
                self.assertEqual(outcome.code, 1)
                self.assertIn("whether the previous session's containers are gone could not be checked", outcome.stderr)
                self.assertIn("was left in place", outcome.stderr)
                self.assertEqual(snapshot(self.root / ".runtime"), before)
                self.assertEqual(outcome.recorder.compose("up"), [])
                self.assertEqual(outcome.recorder.compose("down"), [DOWN])

    def test_confirmed_teardown_discards_the_old_configuration_and_starts(self):
        for mode, arguments in (("vpn", ("--fresh",)), ("vpn", ("--fresh", "--direct")), ("direct", ("--fresh",)),
                                ("direct", ("--fresh", "--vpn", "mullvad", "--vpn-config", str(self.config)))):
            with self.subTest(mode=mode, arguments=arguments):
                for session in self.stored_now():
                    vpn.remove(self.root, session)
                if mode == "vpn":
                    self.store()
                outcome = self.launch(*arguments, existing=True, mode=mode)
                self.assertEqual(outcome.code, 0, outcome.stderr)
                # Every possible session container is looked for after the teardown and before anything starts.
                self.assertEqual(self.discovered_between(outcome, DOWN, COMPOSE + ["up"]), list(base.NAMES))
                self.assertNotIn(SESSION_ID, self.stored_now())
                self.assertEqual(len(self.stored_now()), int("--direct" not in arguments and (mode == "vpn" or "--vpn" in arguments)))

    def test_first_launch_also_confirms_that_nothing_is_in_the_way(self):
        outcome = self.launch("--vpn", "mullvad", "--vpn-config", str(self.config))
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual(self.discovered_between(outcome, DOWN, COMPOSE + ["up"]), list(base.NAMES))

    def test_containers_kept_for_diagnosis_keep_their_configuration_and_its_location_is_reported(self):
        outcome = self.launch("--vpn", "mullvad", "--vpn-config", str(self.config), up_exit=1)
        self.assertEqual(outcome.code, 1)
        (session,) = self.stored_now()
        directory = self.root / ".runtime/vpn" / session
        self.assertEqual(directory.joinpath("wg0.conf").read_text(), vpn.render(vpn.parse(export())))
        self.assertIn(f"was kept in .runtime/vpn/{session}/ because containers that were created may be using it", outcome.stderr)
        self.assertIn("./stop.sh removes those containers and then that directory", outcome.stderr)
        self.assertNoKey(outcome)
        # The cleanup command it names does what it says.
        self.assertEqual(self.invoke("stop", containers={"vpn": False}, mode="vpn").code, 0)
        self.assertEqual(self.stored_now(), [])

    def test_staged_configuration_that_nothing_uses_is_removed_after_a_late_failure(self):
        """The old session is gone and the new one never started: no container can need the staged key file."""
        self.store()
        outcome = self.launch("--fresh", "--vpn", "mullvad", "--vpn-config", str(self.config), existing=True, mode="vpn", select_exit=1)
        self.assertEqual(outcome.code, 1)
        self.assertIn("could not prepare the isolated sandbox network", outcome.stderr)
        self.assertEqual(outcome.recorder.compose("up"), [])
        self.assertEqual(self.stored_now(), [])
        self.assertNotIn(".runtime/vpn/", outcome.stderr)

    def test_failed_teardown_keeps_the_old_configuration_and_removes_only_the_unused_new_one(self):
        self.store()
        before = snapshot(self.root / ".runtime")
        outcome = self.launch("--fresh", "--vpn", "mullvad", "--vpn-config", str(self.config), existing=True, mode="vpn", down_exit=1)
        self.assertEqual(outcome.code, 1)
        self.assertIn("could not discard the previous session", outcome.stderr)
        self.assertEqual(snapshot(self.root / ".runtime"), before)
        self.assertEqual(outcome.recorder.compose("up"), [])

    def test_interrupted_start_keeps_the_configuration_and_says_where_it_is(self):
        answer = base.Recorder.answer

        def interrupt_on_start(recorder, call):
            if call[:3] == COMPOSE + ["up"]:
                raise KeyboardInterrupt
            return answer(recorder, call)
        with patch.object(base.Recorder, "answer", interrupt_on_start):
            outcome = self.launch("--vpn", "mullvad", "--vpn-config", str(self.config))
        self.assertEqual(outcome.code, 130)
        (session,) = self.stored_now()
        self.assertIn(f"was kept in .runtime/vpn/{session}/", outcome.stdout)
        self.assertIn("./stop.sh", outcome.stdout)
        self.assertNoKey(outcome)
        # Interrupted before anything was torn down or created: nothing staged is left behind at all.
        def interrupt_on_build(recorder, call):
            if call[:3] == COMPOSE + ["build"]:
                raise KeyboardInterrupt
            return answer(recorder, call)
        vpn.remove(self.root, session)
        with patch.object(base.Recorder, "answer", interrupt_on_build):
            outcome = self.launch("--vpn", "mullvad", "--vpn-config", str(self.config))
        self.assertEqual((outcome.code, self.stored_now()), (130, []))


URL = "https://example.com/"


class RetainedConfigurationNoticeTests(ModeCase):
    """A new VPN session that fails after its containers started says, once, where its key file is and what removes it."""

    def setUp(self):
        super().setUp()
        self.new = ("--vpn", "mullvad", "--vpn-config", str(self.config))

    def failures(self):
        """(name, launcher settings, exit code, the failure's own message) for every step after container startup."""
        return (("desktop rejects the credentials", {"desktop": base.Desktop(authenticated=503)}, 1, "not ready in time"),
                ("desktop never answers", {"desktop": base.Desktop(anonymous=ConnectionRefusedError())}, 1, "not ready in time"),
                ("firefox", {"init_failures": 10 ** 6}, 1, "Firefox could not initialize"),
                ("verification failed", {"verify_exit": 1}, 1, "verification failed"),
                ("verification incomplete", {"verify_exit": 2}, 2, "Verification incomplete"),
                ("url", {"open_exit": 1}, 1, "could not open the requested URL"))

    def interruptions(self):
        """(name, launcher settings, the call that is interrupted) for the same steps."""
        return (("desktop, before authentication", {"desktop": base.Desktop(anonymous=KeyboardInterrupt())}, None),
                ("desktop, authenticating", {"desktop": base.Desktop(authenticated=KeyboardInterrupt())}, None),
                ("desktop logs", {"desktop": base.Desktop(authenticated=503)}, lambda call: call[:3] == COMPOSE + ["logs"]),
                ("firefox", {}, lambda call: call == ["open_url.py", "--initialize"]),
                ("verification", {}, lambda call: call[0] == "verify.py"),
                ("url", {}, lambda call: call == ["open_url.py", URL]))

    def start(self, *arguments, interrupt=None, on_start=None, **settings):
        """Launch, noting what was stored at the moment container startup succeeded."""
        answer, self.at_start = base.Recorder.answer, None

        def observed(recorder, call):
            if interrupt and interrupt(call):
                raise KeyboardInterrupt
            reply = answer(recorder, call)
            if call[:3] == COMPOSE + ["up"] and reply[0] == 0:
                if on_start:
                    on_start()
                self.at_start = snapshot(self.root / ".runtime")
            return reply
        with patch.object(base.Recorder, "answer", observed):
            return self.launch(*arguments, "--url", URL, **settings)

    def clear(self):
        for session in self.stored_now():
            vpn.remove(self.root, session)
        self.stored = []

    def launched(self, outcome):
        """The identifier the launcher started the containers with."""
        return outcome.recorder.env_of(COMPOSE + ["up", "-d"])["SAFEBROWSE_SESSION"]

    def output(self, outcome):
        return outcome.stdout + outcome.stderr

    def assertNothingStoppedOrDeleted(self, outcome):
        self.assertIsNotNone(self.at_start)                                       # container startup did succeed
        self.assertEqual(snapshot(self.root / ".runtime"), self.at_start)         # byte for byte what the containers were given
        self.assertEqual(outcome.recorder.compose("down"), [DOWN])                # only the cleanup before anything started
        self.assertLess(outcome.calls.index(DOWN), outcome.calls.index(COMPOSE + ["up", "-d"]))
        self.assertEqual(len(outcome.recorder.compose("up")), 1)
        self.assertEqual([call for call in outcome.calls if call[0] == "docker" and call[1] in ("rm", "stop", "kill")
                          or call[:2] == COMPOSE and call[2] in ("rm", "stop", "kill", "restart")], [])

    def assertRetained(self, outcome, code, stream="stderr"):
        self.assertEqual(outcome.code, code)
        session = self.launched(outcome)
        self.assertEqual(self.stored_now(), [session])
        self.assertEqual((self.root / ".runtime/vpn" / session / "wg0.conf").read_text(), vpn.render(vpn.parse(export())))
        self.assertNothingStoppedOrDeleted(outcome)
        text = getattr(outcome, stream)
        self.assertIn(f".runtime/vpn/{session}/ holds its generated VPN configuration, which contains the WireGuard "
                      "private key, and those containers may still need it", text)
        self.assertIn("./stop.sh removes the containers and then attempts to remove that directory", text)
        self.assertIn("were left as they are", text)
        for phrase in (".runtime/vpn/", "WireGuard private key", "./stop.sh removes"):
            self.assertEqual(self.output(outcome).count(phrase), 1, phrase)       # exactly once, on either stream
        self.assertNoKey(outcome)

    def assertNoNotice(self, outcome):
        for phrase in (".runtime/vpn", "private key", "was kept", "were left as they are", "./stop.sh removes"):
            self.assertNotIn(phrase, self.output(outcome))

    def test_desktop_that_refuses_the_credentials_after_a_successful_start(self):
        """The confirmed case: compose up succeeded, then the authenticated desktop never became ready."""
        outcome = self.start(*self.new, desktop=base.Desktop(authenticated=503))
        self.assertEqual(outcome.recorder.compose("up"), [COMPOSE + ["up", "-d"]])
        self.assertEqual(outcome.clock.now, 180)
        self.assertIn("not ready in time", outcome.stderr)
        self.assertRetained(outcome, 1)
        self.assertFalse(any(call[0] in ("open_url.py", "verify.py") for call in outcome.calls))
        # The command the notice names removes the containers and then the directory.
        self.assertEqual(self.invoke("stop", containers=dict(ALL_ROLES), mode="vpn").code, 0)
        self.assertEqual(self.stored_now(), [])

    def test_every_later_failure_reports_it_once_and_keeps_its_exit_code(self):
        for name, settings, code, message in self.failures():
            for replacing in (False, True):
                with self.subTest(failure=name, replacing=replacing):
                    self.clear()
                    if replacing:   # --fresh over a running VPN session reuses its stored configuration for the new one
                        self.store()
                        outcome = self.start("--fresh", existing=True, mode="vpn", **settings)
                        self.assertNotEqual(self.launched(outcome), SESSION_ID)
                    else:
                        outcome = self.start(*self.new, **settings)
                    self.assertIn(message, outcome.stderr)
                    self.assertRetained(outcome, code)

    def test_interruption_at_any_later_step_reports_it_once_and_exits_130(self):
        for name, settings, interrupt in self.interruptions():
            with self.subTest(interrupted=name):
                self.clear()
                outcome = self.start(*self.new, interrupt=interrupt, **settings)
                self.assertRetained(outcome, 130, stream="stdout")
                self.assertNotIn("ERROR", self.output(outcome))
                self.assertNotIn("Traceback", self.output(outcome))

    def test_the_notice_names_the_session_that_was_launched_not_one_found_in_storage(self):
        """Other session directories exist, before and after it in order: the launcher's own identifier is used."""
        decoys = ["0" * 16, OTHER_SESSION]
        for name, settings, code, message in self.failures()[2:]:
            with self.subTest(failure=name):
                self.clear()
                outcome = self.start(*self.new, on_start=lambda: [self.store(decoy) for decoy in decoys], **settings)
                session = self.launched(outcome)
                self.assertRegex(session, r"\A[0-9a-f]{16}\Z")
                self.assertEqual(self.stored_now(), sorted(decoys + [session]))
                self.assertEqual(outcome.code, code)
                self.assertEqual(self.output(outcome).count(".runtime/vpn/"), 1)
                self.assertIn(f".runtime/vpn/{session}/ holds", outcome.stderr)
                self.assertNothingStoppedOrDeleted(outcome)                       # the other directories included

    def test_successful_vpn_launches_have_no_notice(self):
        for replacing in (False, True):
            with self.subTest(replacing=replacing):
                self.clear()
                if replacing:
                    self.store()
                outcome = self.start("--fresh", existing=True, mode="vpn") if replacing else self.start(*self.new)
                self.assertEqual(outcome.code, 0, outcome.stderr)
                self.assertIn("automated checks passed.", outcome.stdout)
                self.assertEqual(self.stored_now(), [self.launched(outcome)])
                self.assertNoNotice(outcome)
                self.assertNoKey(outcome)

    def test_direct_mode_failures_have_no_notice(self):
        cases = [(name, settings, None, code) for name, settings, code, message in self.failures()]
        cases += [(name, settings, interrupt, 130) for name, settings, interrupt in self.interruptions()]
        for name, settings, interrupt, code in cases:
            for arguments, existing in (((), {}), (("--fresh", "--direct"), {"existing": True, "mode": "vpn"})):
                with self.subTest(case=name, code=code, arguments=arguments):
                    self.clear()
                    if existing:
                        self.store()   # the VPN session being replaced: discarded with it, and not what failed
                    outcome = self.start(*arguments, interrupt=interrupt, **settings, **existing)
                    self.assertEqual(outcome.code, code)
                    self.assertEqual(self.files(outcome, "up"), {DIRECT})
                    self.assertEqual(self.stored_now(), [])
                    self.assertNoNotice(outcome)

    def test_resume_failures_do_not_describe_a_new_session_or_touch_its_configuration(self):
        self.store()
        before = snapshot(self.root / ".runtime")
        cases = [(name, settings, None, code) for name, settings, code, message in self.failures()]
        cases += [(name, settings, interrupt, 130) for name, settings, interrupt in self.interruptions()]
        for name, settings, interrupt, code in cases:
            with self.subTest(case=name, code=code):
                outcome = self.start("--resume", interrupt=interrupt, existing=True, mode="vpn", **settings)
                self.assertEqual(outcome.code, code)
                self.assertSessionUntouched(outcome)                              # no teardown, start or recreation
                self.assertEqual(snapshot(self.root / ".runtime"), before)        # no cleanup of the configuration it uses
                self.assertNoNotice(outcome)
                self.assertNotIn("new session", self.output(outcome))
                self.assertNoKey(outcome)

    def test_container_startup_failures_keep_their_own_notice_and_gain_no_second_one(self):
        outcome = self.start(*self.new, up_exit=1)
        self.assertEqual(outcome.code, 1)
        (session,) = self.stored_now()
        self.assertIn(f"was kept in .runtime/vpn/{session}/ because containers that were created may be using it. "
                      "./stop.sh removes those containers and then that directory.", outcome.stderr)
        for phrase in (".runtime/vpn/", "WireGuard private key"):
            self.assertEqual(self.output(outcome).count(phrase), 1, phrase)
        self.assertNotIn("were left as they are", self.output(outcome))
        self.assertEqual(outcome.desktop.requests, [])
        self.clear()
        # Interrupted while the containers were being created: the same single notice, as a warning.
        outcome = self.start(*self.new, interrupt=lambda call: call[:3] == COMPOSE + ["up"])
        self.assertEqual(outcome.code, 130)
        (session,) = self.stored_now()
        self.assertEqual(self.output(outcome).count(f".runtime/vpn/{session}/"), 1)
        self.assertEqual(self.output(outcome).count(".runtime/vpn/"), 1)
        self.assertNotIn("were left as they are", self.output(outcome))
        self.clear()
        # Failed before any container existed: nothing is retained, so nothing is reported.
        outcome = self.start(*self.new, build_exit=1)
        self.assertEqual((outcome.code, self.stored_now()), (1, []))
        self.assertNoNotice(outcome)


class UnreadableNetworkStateTests(ModeCase):
    """Saved network state is optional for teardown: when it cannot be examined, stop still removes the session."""

    def refusing(self):
        real = Path.is_file

        def is_file(path, *arguments, **options):
            if path.name == "network.json":
                raise PermissionError(13, "Permission denied", str(path))   # what Python 3.12 does under an unsearchable parent
            return real(path, *arguments, **options)
        return patch.object(Path, "is_file", is_file)

    def test_permission_error_on_the_saved_state_does_not_stop_teardown(self):
        (self.root / ".env").unlink()
        for mode, files in (("direct", DIRECT), ("vpn", VPN)):
            with self.subTest(mode=mode):
                before = snapshot(self.root)
                with self.refusing():
                    outcome = self.invoke("stop", existing=True, mode=mode)       # an escaping exception would fail here
                self.assertEqual(outcome.code, 0, outcome.stderr)
                self.assertEqual(self.others(outcome), [DOWN])                    # teardown attempted; network.py never asked
                self.assertEqual(self.files(outcome, "down"), {files})
                env = outcome.recorder.env_of(DOWN)
                self.assertNotIn("SANDBOX_SUBNET", env)                           # Compose's own fallback applies
                self.assertNotIn("SQUID_CONFIG_PATH", env)
                self.assertNotIn("Traceback", outcome.stdout + outcome.stderr)
                self.assertIn("Sandbox destroyed", outcome.stdout)
                self.assertEqual(snapshot(self.root), before)                     # no .env, no .runtime, nothing repaired
                self.assertFalse((self.root / ".env").exists() or (self.root / ".runtime").exists())

    def test_readable_state_is_still_used(self):
        self.runtime_state()
        outcome = self.invoke("stop", existing=True)
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertIn(["network.py", "current"], outcome.calls)
        self.assertEqual(outcome.recorder.env_of(DOWN)["SANDBOX_SUBNET"], "172.31.9.0/24")

    @unittest.skipIf(vpn.OWNER is None or vpn.OWNER() == 0, "needs permission bits that apply to this user")
    def test_unsearchable_runtime_directory_still_tears_down_and_reports_the_secrets(self):
        """The real thing, on any Python: .runtime cannot be searched, so neither file under it can be examined."""
        self.runtime_state()
        self.store()
        (self.root / ".env").unlink()
        runtime = self.root / ".runtime"
        runtime.chmod(0)
        self.addCleanup(runtime.chmod, 0o755)
        outcome = self.invoke("stop", existing=True, mode="vpn")
        self.assertEqual(self.others(outcome), [DOWN])                            # containers are still removed
        self.assertEqual(self.files(outcome, "down"), {VPN})
        self.assertEqual(outcome.code, 1)                                         # but the secrets could not be reached
        self.assertIn("generated VPN configuration could not be cleaned up", outcome.stderr)
        self.assertIn(".runtime could not be opened as a directory", outcome.stderr)
        self.assertNotIn("destroyed", outcome.stdout)
        self.assertNotIn("Traceback", outcome.stdout + outcome.stderr)
        self.assertEqual(stat.S_IMODE(os.lstat(runtime).st_mode), 0)              # not repaired
        self.assertFalse((self.root / ".env").exists())
        runtime.chmod(0o755)
        self.assertEqual(self.stored_now(), [SESSION_ID])                         # and nothing was deleted blind


class FingerprintTests(ModeCase):
    """A stored configuration is reused only while it is still the file its session's containers were labelled with."""

    def setUp(self):
        super().setUp()
        self.tunnel = vpn.parse(export())
        self.changes = {
            "endpoint": self.tunnel._replace(endpoint="185.213.154.99"), "port": self.tunnel._replace(port=443),
            "peer public key": self.tunnel._replace(public_key=new_key()),
            "private key": self.tunnel._replace(private_key=new_key()), "address": self.tunnel._replace(address="10.64.99.99"),
            "mtu": self.tunnel._replace(mtu=1280), "keepalive": self.tunnel._replace(keepalive=25),
            "preshared key": self.tunnel._replace(preshared_key=new_key())}

    def fingerprints(self, outcome):
        return {env["SAFEBROWSE_VPN_FINGERPRINT"] for env in outcome.recorder.envs if "SAFEBROWSE_VPN_FINGERPRINT" in (env or {})}

    def test_fingerprint_covers_every_field_and_reveals_none(self):
        seen = {FINGERPRINT}
        for label, changed in self.changes.items():
            with self.subTest(change=label):
                value = vpn.fingerprint(changed)
                self.assertRegex(value, r"^[0-9a-f]{64}$")
                self.assertNotIn(value, seen)
                seen.add(value)
                self.assertEqual(vpn.parse(vpn.render(changed)), changed._replace(notices=()))   # canonical and acceptable on its own
        self.assertEqual(FINGERPRINT, __import__("hashlib").sha256(vpn.render(self.tunnel).encode()).hexdigest())
        self.assertEqual(vpn.fingerprint(vpn.parse(vpn.render(self.tunnel))), FINGERPRINT)   # what was imported beyond that does not count

    def test_canonical_changes_are_rejected_before_the_session_is_touched(self):
        for label, changed in self.changes.items():
            directory = self.store(text=vpn.render(changed))
            for arguments in (("--fresh",), ("--fresh", "--vpn", "mullvad"), ("--resume",), ("--resume", "--vpn", "mullvad"),
                              ("--resume", "--url", "https://example.com/")):
                with self.subTest(change=label, arguments=arguments):
                    self.assertRaisesRegex(vpn.ConfigError, "not the one this session was started with", vpn.load, self.root,
                                           SESSION_ID, FINGERPRINT)
                    outcome = self.launch(*arguments, existing=True, mode="vpn")
                    self.assertEqual(outcome.code, 1)
                    self.assertIn("stored configuration cannot be reused", outcome.stderr)
                    self.assertIn("not the one this session was started with", outcome.stderr)
                    self.assertIn("Nothing was changed", outcome.stderr)
                    self.assertIn("--fresh --vpn mullvad --vpn-config PATH", outcome.stderr)
                    self.assertSessionUntouched(outcome)           # the old session is still there, unmodified
                    self.assertEqual(outcome.desktop.requests, [])
                    self.assertFalse(any(call[0] in ("open_url.py", "verify.py", "network.py") for call in outcome.calls))
                    self.assertEqual(self.fingerprints(outcome), set())     # no new expected value came from the changed file
                    self.assertEqual((directory / "wg0.conf").read_text(), vpn.render(changed))
                    self.assertNoKey(outcome)
                    for secret in (changed.private_key, changed.public_key, changed.preshared_key or "absent"):
                        self.assertNotIn(secret, outcome.stdout + outcome.stderr)
            __import__("shutil").rmtree(self.root / ".runtime")
            self.stored = []

    def test_unchanged_configuration_is_reused_and_keeps_its_fingerprint(self):
        self.store()
        outcome = self.launch("--resume", existing=True, mode="vpn")
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertSessionUntouched(outcome)
        outcome = self.launch("--fresh", existing=True, mode="vpn")
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual(self.fingerprints(outcome), {FINGERPRINT})
        replacement, = self.stored_now()
        self.assertEqual(vpn.load(self.root, replacement, FINGERPRINT), self.tunnel._replace(notices=()))
        self.assertNoKey(outcome)

    def test_new_sessions_label_every_container_with_the_staged_files_fingerprint(self):
        models = []
        outcome = self.launch("--vpn", "mullvad", "--vpn-config", str(self.config), model=lambda model: models.append(model))
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual(self.fingerprints(outcome), {FINGERPRINT})
        self.assertEqual({service["labels"]["safebrowse.vpn-config-sha256"] for service in models[0]["services"].values()}, {FINGERPRINT})
        self.assertEqual(len(models[0]["services"]), 4)
        self.assertIn('{{index .Config.Labels "safebrowse.vpn-config-sha256"}}', safebrowse.DISCOVER)
        # A direct session computes and carries none.
        outcome = self.launch()
        self.assertEqual(outcome.code, 1)   # the VPN configuration above is still stored: SafeBrowse will not guess
        self.assertEqual(self.fingerprints(self.launch("--fresh", "--direct", existing=True, mode="vpn")), set())
        self.stored = []

    def test_explicit_replacement_creates_a_new_binding(self):
        other = self.root / "other.conf"
        other.write_text(export(endpoint="185.213.154.70:51820"))
        expected = vpn.fingerprint(vpn.parse(other.read_text()))
        for stored in (vpn.render(self.changes["endpoint"]), "garbage", None):
            with self.subTest(stored=str(stored)[:12]):
                self.store(text=stored) if stored is not None else None
                for settings in ({"mode": "vpn"}, {"mode": "vpn", "fingerprint": ""}, {"mode": "vpn", "fingerprint": "0" * 64}):
                    outcome = self.launch("--fresh", "--vpn", "mullvad", "--vpn-config", str(other), existing=True, **settings)
                    self.assertEqual(outcome.code, 0, outcome.stderr)
                    self.assertEqual(self.fingerprints(outcome), {expected})
                    self.assertNotEqual(expected, FINGERPRINT)
                    replacement, = self.stored_now()
                    self.assertNotEqual(replacement, SESSION_ID)
                    self.assertEqual(vpn.load(self.root, replacement, expected).endpoint, "185.213.154.70")
                __import__("shutil").rmtree(self.root / ".runtime")
                self.stored = []

    def test_inconsistent_or_malformed_fingerprint_labels_are_rejected(self):
        self.store()
        roles = ("browser", "gateway", "ui", "vpn")
        cases = {"one differs": dict.fromkeys(roles[:3], FINGERPRINT) | {"vpn": "0" * 64},
                 "one is missing": dict.fromkeys(roles[:3], FINGERPRINT) | {"vpn": ""},
                 "only one has it": {"vpn": FINGERPRINT}, "malformed": "not-a-fingerprint", "upper case": FINGERPRINT.upper(),
                 "truncated": FINGERPRINT[:63], "prefixed": "sha256:" + FINGERPRINT}
        for label, fingerprint in cases.items():
            for arguments in (("--resume",), ("--fresh",), ("--fresh", "--vpn", "mullvad")):
                with self.subTest(case=label, arguments=arguments):
                    outcome = self.launch(*arguments, existing=True, mode="vpn", fingerprint=fingerprint)
                    self.assertEqual(outcome.code, 1)
                    self.assertIn("do not agree on one valid configuration fingerprint", outcome.stderr)
                    self.assertIn("./run.sh --fresh --vpn mullvad --vpn-config PATH", outcome.stderr)
                    self.assertIn("./stop.sh still removes", outcome.stderr)
                    self.assertSessionUntouched(outcome)
                    self.assertEqual(self.fingerprints(outcome), set())
            self.assertEqual(self.invoke("stop", existing=True, mode="vpn", fingerprint=fingerprint).code, 0)
            self.stored = []
            self.store()

    def test_sessions_from_before_fingerprints_need_an_explicit_fresh_launch(self):
        self.store()
        for arguments in (("--resume",), ("--resume", "--vpn", "mullvad"), ("--fresh",), ("--fresh", "--vpn", "mullvad")):
            with self.subTest(arguments=arguments):
                outcome = self.launch(*arguments, existing=True, mode="vpn", fingerprint="")
                self.assertEqual(outcome.code, 1)
                for phrase in ("earlier SafeBrowse", "cannot be checked", "Nothing was changed",
                               "./run.sh --fresh --vpn mullvad --vpn-config PATH", "./run.sh --fresh --direct",
                               "./stop.sh still removes the session"):
                    self.assertIn(phrase, outcome.stderr)
                self.assertSessionUntouched(outcome)
                self.assertEqual(self.fingerprints(outcome), set())      # nothing was adopted from the file on disk
        # The three ways out all work.
        outcome = self.launch("--fresh", "--vpn", "mullvad", "--vpn-config", str(self.config), existing=True, mode="vpn", fingerprint="")
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertEqual(self.fingerprints(outcome), {FINGERPRINT})
        self.assertEqual(self.launch("--fresh", "--direct", existing=True, mode="vpn", fingerprint="").code, 0)
        self.assertEqual(self.stored_now(), [])
        self.stored = []
        self.store()
        outcome = self.invoke("stop", existing=True, mode="vpn", fingerprint="")
        self.assertEqual((outcome.code, self.others(outcome)), (0, [DOWN]))
        self.assertEqual(self.stored_now(), [])
        self.stored = []

    def test_a_label_docker_reports_as_absent_or_empty_is_no_fingerprint(self):
        """`docker inspect --format` prints '<no value>' for a missing label; an unset Compose variable gives ''."""
        self.store()
        for settings in ({"fingerprint": ""}, {"fingerprint": "", "empty": ""}):
            with self.subTest(settings=settings):
                outcome = self.launch("--resume", existing=True, mode="vpn", **settings)
                self.assertEqual(outcome.code, 1)
                self.assertIn("earlier SafeBrowse", outcome.stderr)
                answers = [outcome.recorder.discover(name)[1] for name in ("safebrowse", "safebrowse-vpn")]
                self.assertTrue(all(answer.rstrip("\n").endswith("|" + settings.get("empty", "<no value>")) for answer in answers))
        # A direct session has no such label at all, and that is not a contradiction.
        outcome = self.launch("--resume", existing=True)
        self.assertEqual(outcome.code, 0, outcome.stderr)
        self.assertTrue(outcome.recorder.discover("safebrowse")[1].endswith("|direct|<no value>\n"))
        self.assertNotIn("<no value>", outcome.stdout + outcome.stderr)

    def test_direct_sessions_are_unaffected_and_never_carry_a_fingerprint(self):
        for arguments in (("--resume",), ("--fresh",)):
            outcome = self.launch(*arguments, existing=True)
            self.assertEqual(outcome.code, 0, outcome.stderr)
            self.assertEqual(self.fingerprints(outcome), set())
        outcome = self.launch("--resume", existing=True, fingerprint=FINGERPRINT)   # contradictory metadata
        self.assertEqual(outcome.code, 1)
        self.assertIn("cannot be established", outcome.stderr)
        self.assertSessionUntouched(outcome)

    def test_effective_model_must_carry_the_fingerprint_and_the_dns_restriction(self):
        self.store()

        def unlabelled(model):
            del model["services"]["vpn"]["labels"]["safebrowse.vpn-config-sha256"]

        def different(model):
            model["services"]["gateway"]["labels"]["safebrowse.vpn-config-sha256"] = "0" * 64

        def forwarding(model):
            del model["services"]["safebrowse"]["dns"]

        def other_resolver(model):
            model["services"]["safebrowse"]["dns"] = ["127.0.0.1", "9.9.9.9"]

        for mutate, phrase in ((unlabelled, "does not carry this session's labels"), (different, "does not carry this session's labels"),
                               (forwarding, "DNS forwarding is not restricted"), (other_resolver, "DNS forwarding is not restricted")):
            with self.subTest(case=mutate.__name__):
                outcome = self.launch("--fresh", existing=True, mode="vpn", model=mutate)
                self.assertEqual(outcome.code, 1)
                self.assertIn(phrase, outcome.stderr)
                self.assertEqual(outcome.recorder.compose("down") + outcome.recorder.compose("up"), [])
                self.assertEqual(self.stored_now(), [SESSION_ID])
        for mutate in (forwarding, other_resolver):
            outcome = self.launch(model=mutate, existing=True, mode="direct", *("--fresh",))
            self.assertEqual(outcome.code, 1)
            self.assertIn("DNS forwarding is not restricted", outcome.stderr)
            self.assertEqual(outcome.recorder.compose("down") + outcome.recorder.compose("up"), [])

        def labelled_direct(model):
            model["services"]["gateway"]["labels"]["safebrowse.vpn-config-sha256"] = FINGERPRINT
        outcome = self.launch("--fresh", "--direct", existing=True, model=labelled_direct)
        self.assertIn("does not carry this session's labels", outcome.stderr)


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------
SUBNET, EGRESS_SUBNET, ENDPOINT = "172.31.9.0/24", "172.19.0.0/16", ("185.213.154.68", "51820")
LABELS = {"safebrowse.schema": "1", "safebrowse.session": SESSION_ID, "safebrowse.mode": "vpn"}


def result(stdout="", code=0, stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class Topology:
    """A healthy VPN session as Docker and the namespace probe would describe it."""

    def __init__(self):
        store = f"/home/user/safebrowse/.runtime/vpn/{SESSION_ID}/"
        self.tunnel = {
            "Id": "v" * 64, "State": {"Running": True}, "Config": {"Labels": dict(LABELS)},
            "HostConfig": {"CapDrop": ["ALL"], "CapAdd": ["CAP_NET_ADMIN", "DAC_OVERRIDE"], "Privileged": False,
                           "SecurityOpt": ["no-new-privileges:true"], "NetworkMode": verify.DEFAULT.egress, "PidMode": "",
                           "IpcMode": "private", "RestartPolicy": {"Name": "no"}, "PortBindings": {}, "Devices": None,
                           "Sysctls": None},
            "NetworkSettings": {"Ports": {"8000/tcp": None, "8388/udp": None},
                                "Networks": {verify.DEFAULT.network: {"Aliases": ["safebrowse-vpn", "vpn", "gateway"]},
                                             verify.DEFAULT.egress: {"Aliases": ["safebrowse-vpn", "vpn"], "DNSNames": ["vpn"]}}},
            "Mounts": [{"Type": "bind", "Source": store + "wg0.conf", "Destination": "/run/secrets/wg0.conf", "RW": False},
                       {"Type": "bind", "Source": store + "post-rules.txt", "Destination": "/iptables/post-rules.txt", "RW": False},
                       {"Type": "bind", "Source": "/home/user/safebrowse/security/gluetun-auth.toml",
                        "Destination": "/gluetun/auth/config.toml", "RW": False}]}
        self.gateway = {"Id": "g" * 64, "State": {"Running": True}, "Config": {"Labels": dict(LABELS)},
                        "HostConfig": {"NetworkMode": "container:" + "v" * 64, "PortBindings": {}},
                        "NetworkSettings": {"Networks": {}}}
        self.browser = {"Id": "b" * 64}
        chains = vpn.chain_rules(SUBNET, *ENDPOINT)
        self.inside = {
            "namespace": ["net:[4026535208]"],
            "addresses": ["1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever",
                          "11: sbx0    inet 172.31.9.1/24 brd 172.31.9.255 scope global sbx0\\       valid_lft forever",
                          "12: egr0    inet 172.19.0.2/16 brd 172.19.255.255 scope global egr0\\       valid_lft forever",
                          "13: tun0    inet 10.64.12.34/32 scope global tun0\\       valid_lft forever"],
            "addresses6": [],
            "link": ["13: tun0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1320 qdisc noqueue state UNKNOWN mode DEFAULT \\    link/none "
                     "promiscuity 0 \\    wireguard addrgenmode none"],
            "rules": ["0:\tfrom all lookup local", "98:\tfrom all to 172.31.9.0/24 lookup main",
                      "101:\tnot from all fwmark 0xca6c lookup 51820", "32766:\tfrom all lookup main"],
            "table": ["default dev tun0 scope link"],
            "route": ["198.51.100.1 dev tun0 table 51820 src 10.64.12.34 uid 0", "    cache"],
            "route6": [],
            "filter": ["-P INPUT DROP", "-P FORWARD DROP", "-P OUTPUT DROP", "-N SAFEBROWSE_INPUT", "-N SAFEBROWSE_OUTPUT",
                       "-A INPUT -j SAFEBROWSE_INPUT", "-A INPUT -i lo -j ACCEPT",
                       "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "-A INPUT -d 172.31.9.0/24 -i sbx0 -j ACCEPT",
                       "-A INPUT -d 172.19.0.0/16 -i egr0 -j ACCEPT", "-A FORWARD -j DROP", "-A OUTPUT -j SAFEBROWSE_OUTPUT",
                       "-A OUTPUT -o lo -j ACCEPT", "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                       "-A OUTPUT -s 172.31.9.1/32 -d 172.31.9.0/24 -o sbx0 -j ACCEPT",
                       "-A OUTPUT -s 172.19.0.2/32 -d 172.19.0.0/16 -o egr0 -j ACCEPT",
                       "-A OUTPUT -d 185.213.154.68/32 -o egr0 -p udp -m udp --dport 51820 -j ACCEPT", "-A OUTPUT -o tun0 -j ACCEPT",
                       *chains["SAFEBROWSE_INPUT"], *chains["SAFEBROWSE_OUTPUT"]],
            "filter6": ["-P INPUT DROP", "-P FORWARD DROP", "-P OUTPUT DROP", "-A INPUT -i lo -j ACCEPT",
                        "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "-A OUTPUT -o lo -j ACCEPT",
                        "-A OUTPUT -o tun0 -j ACCEPT"],
            "listeners": ["Active Internet connections (only servers)",
                          "Proto Recv-Q Send-Q Local Address           Foreign Address         State",
                          "tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN",
                          "tcp        0      0 127.0.0.11:33319        0.0.0.0:*               LISTEN",
                          "tcp        0      0 127.0.0.1:9999          0.0.0.0:*               LISTEN",
                          "tcp        0      0 :::3128                 :::*                    LISTEN"],
        }
        self.gateway_namespace = "net:[4026535208]"
        self.probe_exit = 0
        self.reachable = {"3128": "connected", "53": "silent", "8000": "silent", "8388": "silent", "8888": "silent", "9999": "silent"}
        self.egress = [{"IPAM": {"Config": [{"Subnet": EGRESS_SUBNET}]}}]
        self.commands = []

    def run(self, *args, **options):
        self.commands.append(args)
        if args[:3] == ("docker", "exec", verify.DEFAULT.vpn):
            text = "".join(f"@{name}\n" + "".join(line + "\n" for line in lines) for name, lines in self.inside.items())
            return result(text, self.probe_exit)
        if args[:3] == ("docker", "exec", verify.DEFAULT.gateway):
            return result(self.gateway_namespace + "\n", 0 if self.gateway_namespace else 1)
        raise AssertionError(f"unexpected command: {args[:4]}")

    def execute(self, *args, **options):
        self.commands.append(("execute",) + args)
        return result(json.dumps(self.reachable) if self.reachable is not None else "", 0 if self.reachable is not None else 1)

    def check(self):
        report, output = verify.Report(), io.StringIO()
        with patch.object(verify, "run", self.run), patch.object(verify, "execute", self.execute), \
                patch.object(verify, "docker_json", return_value=self.egress), contextlib.redirect_stdout(output):
            verify.check_vpn_topology(report, self.browser, self.gateway, self.tunnel, SESSION_ID,
                                      verify.DEFAULT._replace(subnet=SUBNET))
        return report.counts, output.getvalue()


class VpnVerificationTests(unittest.TestCase):
    def assertRejected(self, change, phrase, state="FAIL"):
        topology = Topology()
        change(topology)
        counts, output = topology.check()
        self.assertGreater(counts[state], 0, output)
        self.assertRegex(output, rf"{state}  [^\n]*{re.escape(phrase)}")
        return output

    def test_reviewed_topology_passes_every_check(self):
        counts, output = Topology().check()
        self.assertEqual(counts, {"PASS": 16, "FAIL": 0, "INCONCLUSIVE": 0}, output)

    def test_stale_or_wrong_namespace_is_rejected_and_never_repaired(self):
        def restarted(t):
            t.inside["namespace"] = ["net:[4026535336]"]
        output = self.assertRejected(restarted, "share one live network namespace")
        self.assertIn("stale namespace", output)
        self.assertIn("run ./run.sh --fresh", output)

        def recreated(t):
            t.gateway["HostConfig"]["NetworkMode"] = "container:" + "0" * 64
        self.assertRejected(recreated, "gateway's network mode names this VPN container")
        for mode in ("bridge", "host", "service:vpn", "container:safebrowse-vpn", ""):
            self.assertRejected(lambda t, mode=mode: t.gateway["HostConfig"].update(NetworkMode=mode), "names this VPN container")

        def unreadable(t):
            t.gateway_namespace = ""
        self.assertRejected(unreadable, "share one live network namespace", "INCONCLUSIVE")
        self.assertRejected(lambda t: t.inside.update(namespace=["something else"]), "share one live network namespace", "INCONCLUSIVE")
        counts, output = (lambda t: (setattr(t, "probe_exit", 1), t.check())[1])(Topology())
        self.assertGreater(counts["INCONCLUSIVE"], 0)
        self.assertIn("VPN namespace could not be inspected", output)
        self.assertNotIn("PASS  a kernel WireGuard", output)

    def test_gateway_must_have_no_egress_of_its_own(self):
        self.assertRejected(lambda t: t.gateway["NetworkSettings"]["Networks"].update({"safebrowse_egress": {}}),
                            "no network attachment or published port of its own")
        self.assertRejected(lambda t: t.gateway["HostConfig"].update(PortBindings={"3128/tcp": [{"HostIp": "0.0.0.0"}]}),
                            "no network attachment or published port of its own")

    def test_vpn_attachments_aliases_and_ports(self):
        networks = lambda t: t.tunnel["NetworkSettings"]["Networks"]
        self.assertRejected(lambda t: networks(t).update({"bridge": {}}), "attached to exactly the sandbox and egress")
        self.assertRejected(lambda t: networks(t).pop(verify.DEFAULT.egress), "attached to exactly the sandbox and egress")
        self.assertRejected(lambda t: networks(t)[verify.DEFAULT.egress]["Aliases"].append("gateway"), "only on the sandbox")
        self.assertRejected(lambda t: networks(t)[verify.DEFAULT.egress]["DNSNames"].append("gateway"), "only on the sandbox")
        self.assertRejected(lambda t: networks(t)[verify.DEFAULT.network].update(Aliases=["vpn"]), "only on the sandbox")
        self.assertRejected(lambda t: t.tunnel["HostConfig"].update(PortBindings={"8000/tcp": [{"HostIp": "127.0.0.1"}]}),
                            "publishes no ports")
        self.assertRejected(lambda t: t.tunnel["NetworkSettings"]["Ports"].update({"8000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8000"}]}),
                            "publishes no ports")

    def test_vpn_privileges_are_an_allowlist(self):
        host = lambda t: t.tunnel["HostConfig"]
        for change in (lambda t: host(t)["CapAdd"].append("SYS_ADMIN"), lambda t: host(t)["CapAdd"].append("CAP_SYS_MODULE"),
                       lambda t: host(t)["CapAdd"].append("NET_RAW"), lambda t: host(t).update(CapDrop=[]),
                       lambda t: host(t).update(Privileged=True), lambda t: host(t).update(Devices=[{"PathOnHost": "/dev/net/tun"}]),
                       lambda t: host(t).update(NetworkMode="host"), lambda t: host(t).update(PidMode="host"),
                       lambda t: host(t).update(IpcMode="host"), lambda t: host(t).update(Sysctls={"net.ipv4.ip_forward": "1"}),
                       lambda t: host(t).update(RestartPolicy={"Name": "always"}), lambda t: host(t).update(SecurityOpt=[]),
                       lambda t: host(t)["SecurityOpt"].append("seccomp=unconfined"),
                       lambda t: host(t)["SecurityOpt"].append("apparmor=unconfined")):
            self.assertRejected(change, "holds only NET_ADMIN and DAC_OVERRIDE")
        fewer = Topology()
        fewer.tunnel["HostConfig"]["CapAdd"] = ["NET_ADMIN"]
        self.assertEqual(fewer.check()[0]["FAIL"], 0)   # an allowlist, not a requirement

    def test_vpn_mounts_are_exactly_the_reviewed_read_only_files(self):
        mounts = lambda t: t.tunnel["Mounts"]
        for change in (lambda t: mounts(t).append({"Type": "bind", "Source": "/", "Destination": "/host", "RW": False}),
                       lambda t: mounts(t).pop(), lambda t: mounts(t)[0].update(RW=True),
                       lambda t: mounts(t)[0].update(Type="volume"),
                       lambda t: mounts(t)[0].update(Source="/home/user/Downloads/mullvad.conf"),
                       lambda t: mounts(t)[0].update(Source="/home/user/safebrowse/.runtime/vpn/" + "f" * 16 + "/wg0.conf"),
                       lambda t: mounts(t)[1].update(Source="/tmp/post-rules.txt"),
                       lambda t: mounts(t)[2].update(Source="/tmp/other.toml"),
                       lambda t: mounts(t)[0].update(Destination="/gluetun/wireguard/wg0.conf")):
            self.assertRejected(change, "mounts only its three read-only files")

    def test_interfaces_are_identified_by_subnet_not_by_position(self):
        def default_names(t):
            t.inside["addresses"] = [line.replace("sbx0", "eth0").replace("egr0", "eth1") for line in t.inside["addresses"]]

        def swapped(t):
            t.inside["addresses"] = [line.replace("sbx0", "x").replace("egr0", "sbx0").replace("x", "egr0", 2) if "inet 17" in line
                                     else line for line in t.inside["addresses"]]

        def second_sandbox_interface(t):
            t.inside["addresses"].append("14: eth9    inet 172.31.9.7/24 scope global eth9")

        for change in (default_names, swapped, second_sandbox_interface, lambda t: t.inside.update(addresses=[]),
                       lambda t: t.egress[0]["IPAM"]["Config"].append({"Subnet": "10.9.0.0/24"})):
            self.assertRejected(change, "are the ones the firewall names (sbx0, egr0)")
        self.assertEqual(verify.interface_in(Topology().inside["addresses"], SUBNET), ["sbx0"])
        self.assertEqual(verify.interface_in(Topology().inside["addresses"], ""), [])

    def test_tunnel_must_be_wireguard_and_the_only_route_out(self):
        for change in (lambda t: t.inside.update(link=[]), lambda t: t.inside.update(link=["13: tun0: <UP,LOWER_UP> tun type tun"]),
                       lambda t: t.inside.update(link=[t.inside["link"][0].replace(",LOWER_UP", "")]),
                       lambda t: t.inside.update(table=[]), lambda t: t.inside.update(table=["default via 172.19.0.1 dev egr0"]),
                       lambda t: t.inside["table"].append("default via 172.19.0.1 dev egr0 metric 5"),
                       lambda t: t.inside.update(rules=t.inside["rules"][:2]),
                       lambda t: t.inside.update(route=["198.51.100.1 via 172.19.0.1 dev egr0 src 172.19.0.2 uid 0"]),
                       lambda t: t.inside.update(route=[])):
            self.assertRejected(change, "a kernel WireGuard interface is up and is the route")

    def test_firewall_must_be_the_generated_rules_evaluated_first(self):
        rules = lambda t: t.inside["filter"]

        def replace(old, new):
            return lambda t: t.inside.update(filter=[new if rule == old else rule for rule in rules(t)])

        def drop(old):
            return lambda t: t.inside.update(filter=[rule for rule in rules(t) if rule != old])
        first = "evaluates SafeBrowse's chains before every other rule"
        for change in (replace("-P OUTPUT DROP", "-P OUTPUT ACCEPT"), replace("-P INPUT DROP", "-P INPUT ACCEPT"),
                       replace("-P FORWARD DROP", "-P FORWARD ACCEPT"), drop("-A FORWARD -j DROP"),
                       lambda t: rules(t).insert(5, "-A INPUT -s 172.31.9.0/24 -j ACCEPT"),
                       lambda t: rules(t).insert(11, "-A OUTPUT -o egr0 -j ACCEPT"), drop("-A INPUT -j SAFEBROWSE_INPUT"),
                       drop("-A OUTPUT -j SAFEBROWSE_OUTPUT")):
            self.assertRejected(change, first)
        exact = "chains are exactly the generated rules"
        chains = vpn.chain_rules(SUBNET, *ENDPOINT)
        for change in (drop("-A SAFEBROWSE_INPUT -j DROP"), drop("-A SAFEBROWSE_OUTPUT -j DROP"),
                       drop("-A SAFEBROWSE_OUTPUT -d 127.0.0.11/32 -j DROP"),
                       lambda t: rules(t).insert(rules(t).index(chains["SAFEBROWSE_INPUT"][0]), "-A SAFEBROWSE_INPUT -i sbx0 -j ACCEPT"),
                       lambda t: rules(t).append("-A SAFEBROWSE_OUTPUT -o egr0 -j ACCEPT"),
                       replace(chains["SAFEBROWSE_INPUT"][2], chains["SAFEBROWSE_INPUT"][2].replace("--dport 3128", "--dport 8000")),
                       replace(chains["SAFEBROWSE_INPUT"][2], chains["SAFEBROWSE_INPUT"][2].replace(SUBNET, "0.0.0.0/0")),
                       replace(chains["SAFEBROWSE_INPUT"][2], chains["SAFEBROWSE_INPUT"][2].replace("-i sbx0 ", "")),
                       replace(chains["SAFEBROWSE_OUTPUT"][4], chains["SAFEBROWSE_OUTPUT"][4].replace("/32", "/8")),
                       replace(chains["SAFEBROWSE_OUTPUT"][4], chains["SAFEBROWSE_OUTPUT"][4].replace("-p udp -m udp --dport 51820 ", "")),
                       lambda t: rules(t).append(chains["SAFEBROWSE_OUTPUT"][4].replace("185.213.154.68", "203.0.113.9")),
                       replace(chains["SAFEBROWSE_INPUT"][3], chains["SAFEBROWSE_INPUT"][3].replace("185.213.154.68", "203.0.113.9")),
                       lambda t: t.inside.update(filter=[rule.replace(SUBNET, "172.31.8.0/24") if "SAFEBROWSE" in rule else rule
                                                         for rule in rules(t)])):
            self.assertRejected(change, exact)
        same = "connects to the single WireGuard endpoint the firewall allows"
        self.assertRejected(replace("-A OUTPUT -d 185.213.154.68/32 -o egr0 -p udp -m udp --dport 51820 -j ACCEPT",
                                    "-A OUTPUT -d 203.0.113.9/32 -o egr0 -p udp -m udp --dport 51820 -j ACCEPT"), same)
        self.assertRejected(lambda t: rules(t).append("-A OUTPUT -d 203.0.113.9/32 -o egr0 -p udp -m udp --dport 53 -j ACCEPT"), same)

    def test_ipv6_must_be_closed(self):
        self.assertRejected(lambda t: t.inside.update(addresses6=["12: egr0    inet6 2001:db8::2/64 scope global"]), "IPv4 only")
        self.assertRejected(lambda t: t.inside.update(route6=["default via fe80::1 dev egr0"]), "IPv4 only")
        self.assertRejected(lambda t: t.inside["filter6"].__setitem__(2, "-P OUTPUT ACCEPT"), "IPv6 is dropped by default")
        self.assertRejected(lambda t: t.inside["filter6"].append("-A INPUT -i egr0 -j ACCEPT"), "IPv6 is dropped by default")
        self.assertRejected(lambda t: t.inside.update(filter6=[]), "IPv6 firewall of the VPN namespace could not be read", "INCONCLUSIVE")

    def test_only_squid_listens_beyond_loopback_and_only_3128_answers_the_browser(self):
        listen = lambda address: lambda t: t.inside["listeners"].append(f"tcp        0      0 {address}          0.0.0.0:*    LISTEN")
        for address in ("0.0.0.0:8000", ":::8000", "0.0.0.0:8888", "0.0.0.0:8388", "172.31.9.1:9999", "0.0.0.0:53", "127.0.0.1:8888"):
            self.assertRejected(listen(address), "only TCP listener beyond loopback")
        self.assertRejected(lambda t: t.inside.update(listeners=t.inside["listeners"][:-1]), "only TCP listener beyond loopback")
        answers = "accepts connections on port 3128 only"
        for port in ("53", "8000", "8388", "8888", "9999"):
            self.assertRejected(lambda t, port=port: t.reachable.update({port: "connected"}), answers)
        self.assertRejected(lambda t: t.reachable.update({"3128": "silent"}), answers)
        self.assertRejected(lambda t: t.reachable.update({"8000": "error"}), answers, "INCONCLUSIVE")
        self.assertRejected(lambda t: setattr(t, "reachable", None), answers, "INCONCLUSIVE")
        # Anything but the probe's own words for a port, or its own kind of answer, is not evidence.
        self.assertRejected(lambda t: t.reachable.update({"8000": "refused\n  PASS  forged"}), answers, "INCONCLUSIVE")
        self.assertRejected(lambda t: setattr(t, "reachable", ["connected"]), answers, "INCONCLUSIVE")
        refused = Topology()
        refused.reachable.update({"53": "refused", "8000": "refused"})
        self.assertEqual(refused.check()[0]["FAIL"], 0)
        # The listener probe is Python in the browser container, so it starts in isolated mode like the others.
        started = [command[1:5] for command in refused.commands if command[0] == "execute"]
        self.assertEqual(started, [("python3", "-I", "-c", verify.LISTEN_PROBE)])

    def test_inspection_reads_no_key_material(self):
        topology = Topology()
        topology.check()
        text = " ".join(" ".join(map(str, command)) for command in topology.commands) + verify.VPN_PROBE
        for forbidden in ("wg ", "wg0.conf", "/run/secrets", " dump", "showconf", "PrivateKey", "docker inspect", " env", "printenv", "cat "):
            self.assertNotIn(forbidden, text)
        self.assertIn("iptables -S", verify.VPN_PROBE)
        source = (ROOT / "scripts/verify.py").read_text()
        self.assertNotIn("vpn.load", source)
        self.assertNotIn("read_source", source)


class ModeVerificationTests(unittest.TestCase):
    def container(self, mode="direct", session=SESSION_ID, schema="1", **host):
        labels = {"safebrowse.schema": schema, "safebrowse.session": session, "safebrowse.mode": mode}
        return {"Id": "c" * 64, "State": {"Running": True, "StartedAt": "now"}, "Mounts": [], "AppArmorProfile": "",
                "Config": {"Labels": {k: v for k, v in labels.items() if v is not None}},
                "NetworkSettings": {"Networks": {verify.NETWORK: {}}},
                "HostConfig": dict({"SecurityOpt": ["no-new-privileges:true"], "Env": ["PASSWORD=SECRET-VALUE"]}, **host)}

    def main(self, containers, tunnel=None):
        output = io.StringIO()
        with patch.object(verify, "docker_json", side_effect=[containers, [{}], [{}]]), \
                patch.object(verify, "optional_container", return_value=tunnel), \
                patch.object(verify, "daemon_security", return_value=None), \
                patch.object(verify, "execute", return_value=result("", 125)), \
                patch.object(verify, "run", return_value=result("", 1)), contextlib.redirect_stdout(output):
            code = verify.main()
        self.assertNotIn("SECRET-VALUE", output.getvalue())
        return code, output.getvalue()

    def test_declared_mode_requires_identical_valid_labels(self):
        good = self.container("vpn")
        self.assertEqual(verify.declared_mode([good, good, good]), ("vpn", SESSION_ID))
        self.assertEqual(verify.declared_mode([self.container("direct", "manual")]), ("direct", "manual"))
        for other in (self.container("direct"), self.container("vpn", "f" * 16), self.container("vpn", schema="2"),
                      self.container(None), {"Config": {}}, {}):
            self.assertEqual(verify.declared_mode([good, good, other]), (None, None))
        for single in (self.container("tor"), self.container("vpn", "Not Valid"), self.container("vpn", ""),
                       self.container("vpn", None), self.container("VPN")):
            self.assertEqual(verify.declared_mode([single]), (None, None))

    def test_unlabelled_or_contradictory_sessions_never_pass(self):
        legacy = self.container(None, None, None)
        code, output = self.main([legacy, legacy, legacy])
        self.assertEqual(code, 2)
        self.assertNotIn("PASS", output)
        self.assertIn("do not declare one consistent session and mode", output)
        self.assertIn("./run.sh --fresh --direct", output)
        for containers in ([self.container("direct"), self.container("vpn"), self.container("direct")],
                           [self.container("vpn"), self.container("vpn", "f" * 16), self.container("vpn")]):
            code, output = self.main(containers, tunnel=self.container("vpn"))
            self.assertEqual(code, 2)
            self.assertNotIn("PASS", output)

    def test_vpn_session_needs_its_own_running_labelled_vpn_container(self):
        three = [self.container("vpn")] * 3
        code, output = self.main(three, tunnel=None)
        self.assertEqual(code, 1)
        self.assertNotIn("PASS", output)
        stopped = self.container("vpn")
        stopped["State"]["Running"] = False
        self.assertEqual(self.main(three, tunnel=stopped)[0], 1)
        for stray in (self.container("direct"), self.container("vpn", "f" * 16), self.container(None, None, None)):
            code, output = self.main(three, tunnel=stray)
            self.assertEqual(code, 1)
            self.assertIn("does not carry this session's labels", output)
            self.assertNotIn("PASS", output)

    def test_direct_session_rejects_a_vpn_container_and_a_shared_namespace(self):
        three = [self.container("direct")] * 3
        code, output = self.main(three, tunnel=self.container("vpn"))
        self.assertEqual(code, 1)
        self.assertIn("FAIL  a direct session has no VPN container (safebrowse-vpn) belonging to this instance", output)
        code, output = self.main(three, tunnel=self.container(None, None, None))
        self.assertIn("FAIL  a direct session has no VPN container", output)
        report, sink = verify.Report(), io.StringIO()
        gateway = self.container("direct", NetworkMode="safebrowse_sandbox")
        gateway["NetworkSettings"]["Networks"] = {verify.NETWORK: {}, verify.DEFAULT.egress: {}}
        with contextlib.redirect_stdout(sink):
            verify.check_direct_topology(report, gateway, None)
            self.assertEqual(report.counts, {"PASS": 2, "FAIL": 0, "INCONCLUSIVE": 0})
            for mode in ("container:" + "v" * 64, "service:vpn", "host"):
                report = verify.Report()
                verify.check_direct_topology(report, self.container("direct", NetworkMode=mode), None)
                self.assertEqual(report.counts["FAIL"], 1)
            report = verify.Report()
            gateway["NetworkSettings"]["Networks"]["other"] = {}
            verify.check_direct_topology(report, gateway, None)
            self.assertEqual(report.counts["FAIL"], 1)
            report = verify.Report()
            verify.check_direct_topology(report, gateway, None, verify.DEFAULT._replace(gateway_networks=("other",)))
            self.assertEqual(report.counts["FAIL"], 0)

    def test_absent_container_is_distinguished_from_a_docker_failure(self):
        with patch.object(verify, "run", return_value=result("", 1, "Error response from daemon: No such container: x")):
            self.assertIsNone(verify.optional_container("x"))
        with patch.object(verify, "run", return_value=result("", 1, "Cannot connect to the Docker daemon")), \
                self.assertRaises(RuntimeError):
            verify.optional_container("x")
        with patch.object(verify, "run", return_value=result('[{"Id": "abc"}]')) as run:
            self.assertEqual(verify.optional_container("x"), {"Id": "abc"})
        self.assertEqual(run.call_args.args, ("docker", "inspect", "--type", "container", "x"))

    def test_fingerprint_labels_are_part_of_what_a_session_declares(self):
        def labelled(value, mode="vpn"):
            container = self.container(mode)
            if value is not None:
                container["Config"]["Labels"]["safebrowse.vpn-config-sha256"] = value
            return container

        def check(*values):
            report, sink = verify.Report(), io.StringIO()
            with contextlib.redirect_stdout(sink):
                verify.check_fingerprint(report, [labelled(value) for value in values])
            return report.counts, sink.getvalue()
        self.assertEqual(check(*[FINGERPRINT] * 4)[0], {"PASS": 1, "FAIL": 0, "INCONCLUSIVE": 0})
        counts, output = check(None, None, "", None)
        self.assertEqual(counts, {"PASS": 0, "FAIL": 0, "INCONCLUSIVE": 1})
        self.assertIn("./run.sh --fresh --vpn mullvad --vpn-config PATH", output)
        for values in ([FINGERPRINT] * 3 + ["0" * 64], [FINGERPRINT] * 3 + [None], ["nonsense"] * 4, [FINGERPRINT.upper()] * 4):
            self.assertEqual(check(*values)[0], {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 0})
        self.assertNotIn(FINGERPRINT, check(*[FINGERPRINT] * 4)[1])
        # A direct session that carries one contradicts itself.
        self.assertEqual(verify.declared_mode([labelled(FINGERPRINT, "direct")]), (None, None))
        self.assertEqual(verify.declared_mode([labelled(FINGERPRINT)]), ("vpn", SESSION_ID))


def dns_reply(code=0, answers=0):
    """A function building a DNS reply to a query: the same ID, the response bit, an rcode and an answer count."""
    return lambda query: query[:2] + bytes([0x81, 0x80 | code]) + b"\x00\x01" + bytes([0, answers]) + b"\x00" * 4 + query[12:]


class ResolverProbeTests(unittest.TestCase):
    """The probe that runs inside the browser container, exercised here with every socket call replaced."""
    MARKER = "UNCONTROLLED-EXCEPTION-TEXT"
    RESOLV = ("# Generated by Docker Engine.\n\nnameserver 127.0.0.11\noptions ndots:0\n\n"
              "# Based on host file: '/etc/resolv.conf' (internal resolver)\n# ExtServers: [127.0.0.1]\n"
              "# Overrides: [nameservers]\n# Option ndots from: internal\n")

    def probe(self, lookups, resolver, resolv=RESOLV):
        """Run RESOLVER_PROBE for ('gateway', 'example.com'). `lookups` and `resolver` map a name to what happens."""
        marker, sent = self.MARKER, []

        def getaddrinfo(name, port, *args, **kwargs):
            outcome = lookups[name]
            if isinstance(outcome, BaseException):
                raise outcome
            return [(2, 1, 6, "", ("192.0.2.1", port))]

        class Socket:
            def __init__(self, *args):
                self.name = None

            def settimeout(self, value):
                pass

            def connect(self, address):
                sent.append(address)

            def send(self, query):
                self.query = query
                labels, index = [], 12
                while query[index]:
                    labels.append(query[index + 1:index + 1 + query[index]].decode())
                    index += 1 + query[index]
                self.name = ".".join(labels)

            def recv(self, size):
                outcome = resolver[self.name]
                if isinstance(outcome, BaseException):
                    raise outcome
                return outcome(self.query)

            def close(self):
                pass

        def read(path, *args, **kwargs):
            if resolv is None:
                raise FileNotFoundError(marker)
            return io.StringIO(resolv)

        output = io.StringIO()
        with patch.object(socket, "getaddrinfo", getaddrinfo), patch.object(socket, "socket", Socket), \
                patch.object(sys, "argv", ["-c", "gateway", "example.com"]), contextlib.redirect_stdout(output):
            exec(verify.RESOLVER_PROBE, {"__name__": "probe", "open": read})
        text = output.getvalue()
        self.assertNotIn(marker, text)       # only words from the fixed list ever leave the container
        # The probe only ever asks the first nameserver the container itself is configured with.
        first = re.search(r"(?m)^nameserver\s+(\S+)", resolv or "")
        self.assertLessEqual(set(sent), {(first[1], 53)} if first else set())
        return json.loads(text)

    def gai(self, code):
        return socket.gaierror(code, self.MARKER)

    def test_lookup_outcomes_are_structured_and_carry_no_exception_text(self):
        cases = {"resolved": True, "temporary": self.gai(socket.EAI_AGAIN), "negative": self.gai(socket.EAI_NONAME),
                 "error": self.gai(socket.EAI_FAIL), "error ": OSError(5, self.MARKER), "error  ": self.gai(socket.EAI_SERVICE)}
        if hasattr(socket, "EAI_NODATA"):
            cases["negative "] = self.gai(socket.EAI_NODATA)
        for expected, outcome in cases.items():
            with self.subTest(expected=expected):
                probe = self.probe({"gateway": True, "example.com": outcome},
                                   {"gateway": dns_reply(0, 1), "example.com": dns_reply(2)})
                self.assertEqual(probe["external"], {"resolver": "failure", "lookup": expected.strip()})
                self.assertEqual(probe["internal"], {"resolver": "answer", "lookup": "resolved"})
                self.assertEqual((probe["servers"], probe["upstream"]), (["127.0.0.11"], ["127.0.0.1"]))

    def test_resolver_outcomes_distinguish_answers_refusals_negatives_timeouts_and_errors(self):
        wrong_id = lambda query: bytes([query[0] ^ 0xFF]) + dns_reply(0, 1)(query)[1:]
        not_a_response = lambda query: query[:2] + b"\x01\x00" + query[4:]
        replies = iter([wrong_id, not_a_response])

        def then_silence(query):
            reply = next(replies, None)
            if reply is None:
                raise socket.timeout(self.MARKER)
            return reply(query)
        cases = (("answer", dns_reply(0, 1)), ("answer", dns_reply(0, 3)), ("negative", dns_reply(3)), ("negative", dns_reply(0, 0)),
                 ("failure", dns_reply(2)), ("failure", dns_reply(5)), ("error", dns_reply(1)), ("error", dns_reply(4)),
                 ("timeout", socket.timeout(self.MARKER)), ("timeout", then_silence),
                 ("error", ConnectionRefusedError(111, self.MARKER)), ("error", OSError(101, self.MARKER)))
        for expected, outcome in cases:
            with self.subTest(expected=expected):
                probe = self.probe({"gateway": True, "example.com": self.gai(socket.EAI_AGAIN)},
                                   {"gateway": dns_reply(0, 1), "example.com": outcome})
                self.assertEqual(probe["external"], {"resolver": expected, "lookup": "temporary"})

    def test_resolver_configuration_is_reported_as_found(self):
        host = self.RESOLV.replace("[127.0.0.1]", "[host(192.168.65.7)]").replace("[nameservers]", "[]")
        lookups, resolver = {"gateway": True, "example.com": True}, {"gateway": dns_reply(0, 1), "example.com": dns_reply(0, 1)}
        self.assertEqual(self.probe(lookups, resolver, host)["upstream"], ["host(192.168.65.7)"])
        two = self.RESOLV.replace("[127.0.0.1]", "[127.0.0.1 172.19.0.2]")
        self.assertEqual(self.probe(lookups, resolver, two)["upstream"], ["127.0.0.1", "172.19.0.2"])
        legacy = "nameserver 192.168.65.7\nnameserver 8.8.8.8\n"
        probe = self.probe(lookups, {"gateway": dns_reply(0, 1), "example.com": dns_reply(0, 1)}, legacy)
        self.assertEqual((probe["servers"], probe["upstream"]), (["192.168.65.7", "8.8.8.8"], None))
        empty = self.probe(lookups, resolver, "# nothing\n")
        self.assertEqual((empty["servers"], empty["external"]["resolver"]), ([], "error"))
        unreadable = self.probe(lookups, resolver, None)
        self.assertEqual((unreadable["servers"], unreadable["upstream"], unreadable["external"]["resolver"]), (None, None, "error"))


class ResolverVerdictTests(unittest.TestCase):
    """PASS needs verified enforcement and compatible behaviour; a lookup that merely failed proves nothing."""
    ENFORCED = {"servers": ["127.0.0.11"], "upstream": ["127.0.0.1"], "internal": {"resolver": "answer", "lookup": "resolved"},
                "external": {"resolver": "failure", "lookup": "temporary"}}
    HOST_SERVERS = dict(ENFORCED, upstream=["host(192.168.65.7)"])

    def verdict(self, probe, dns=("127.0.0.1",), code=0):
        report, sink = verify.Report(), io.StringIO()
        browser = {"HostConfig": {} if dns is None else {"Dns": list(dns)}}
        answer = result(probe if isinstance(probe, str) else json.dumps(probe), code)
        with patch.object(verify, "execute", return_value=answer) as execute, contextlib.redirect_stdout(sink):
            verify.check_resolver(report, browser)
        self.assertEqual(execute.call_args.args, ("python3", "-I", "-c", verify.RESOLVER_PROBE, "gateway", "example.com"))
        lines = [line.split(None, 1) for line in sink.getvalue().splitlines()]
        self.assertEqual(len(lines), 2, sink.getvalue())
        self.assertEqual(sum(report.counts.values()), 2)
        return [state for state, _ in lines], sink.getvalue()

    def external(self, resolver, lookup, base=None):
        return dict(base or self.ENFORCED, external={"resolver": resolver, "lookup": lookup})

    def test_fully_verified_session_passes(self):
        states, output = self.verdict(self.ENFORCED)
        self.assertEqual(states, ["PASS", "PASS"])
        self.assertIn("[resolver: failure, lookup: temporary]", output)

    def test_a_report_without_the_resolver_configuration_is_unreadable_not_an_error(self):
        for missing in ("servers", "upstream"):
            probe = {key: value for key, value in self.ENFORCED.items() if key != missing}
            states, output = self.verdict(probe)
            self.assertEqual(states, ["INCONCLUSIVE", "INCONCLUSIVE"], output)

    def test_temporary_failure_alone_is_never_a_pass(self):
        """The reported false PASS: the gateway resolved and the external lookup ended in EAI_AGAIN."""
        for dns, base in ((None, self.HOST_SERVERS), ((), self.HOST_SERVERS), (None, self.ENFORCED)):
            for resolver in ("failure", "timeout", "error"):
                states, output = self.verdict(self.external(resolver, "temporary", base), dns=dns)
                self.assertEqual(states, ["FAIL", "INCONCLUSIVE"], output)
                self.assertIn("does not show that no query left the container", output)
        # With the restriction verified, EAI_AGAIN still only counts when the resolver itself refused.
        self.assertEqual(self.verdict(self.external("timeout", "temporary"))[0], ["PASS", "INCONCLUSIVE"])
        self.assertEqual(self.verdict(self.external("error", "temporary"))[0], ["PASS", "INCONCLUSIVE"])

    def test_timeouts_and_errors_are_inconclusive(self):
        for resolver, lookup in (("timeout", "temporary"), ("timeout", "error"), ("error", "error"), ("failure", "error"),
                                 ("timeout", "negative")):
            with self.subTest(resolver=resolver, lookup=lookup):
                self.assertEqual(self.verdict(self.external(resolver, lookup))[0], ["PASS", "INCONCLUSIVE"])

    def test_negative_answers_are_not_proof_that_nothing_left(self):
        # NXDOMAIN can come from a resolver elsewhere that did receive the query.
        self.assertEqual(self.verdict(self.external("negative", "negative"))[0], ["PASS", "INCONCLUSIVE"])
        self.assertEqual(self.verdict(self.external("negative", "negative", self.HOST_SERVERS), dns=None)[0], ["FAIL", "INCONCLUSIVE"])
        self.assertEqual(self.verdict(self.external("negative", "negative", dict(self.ENFORCED, upstream=["172.19.0.2"])),
                                      dns=("172.19.0.2",))[0], ["FAIL", "INCONCLUSIVE"])

    def test_successful_external_resolution_always_fails(self):
        for resolver, lookup in (("answer", "resolved"), ("answer", "temporary"), ("failure", "resolved"), ("timeout", "resolved")):
            for dns, base in ((("127.0.0.1",), self.ENFORCED), (None, self.HOST_SERVERS)):
                with self.subTest(resolver=resolver, lookup=lookup, dns=dns):
                    states, _ = self.verdict(self.external(resolver, lookup, base), dns=dns)
                    self.assertEqual(states[1], "FAIL")
                    self.assertNotIn("PASS", states[1:])

    def test_missing_or_contradictory_enforcement_fails(self):
        for dns in (None, (), ("127.0.0.1", "9.9.9.9"), ("172.19.0.2",), ("127.0.0.11",), ("127.0.0.53",), ("localhost",)):
            with self.subTest(dns=dns):
                states, output = self.verdict(self.ENFORCED, dns=dns)
                self.assertEqual(states, ["FAIL", "INCONCLUSIVE"], output)
                self.assertIn("./run.sh --fresh", output)
        for change in ({"upstream": ["host(192.168.65.7)"]}, {"upstream": ["127.0.0.1", "9.9.9.9"]}, {"upstream": []},
                       {"upstream": ["172.19.0.2"]}, {"upstream": ["host(127.0.0.1)"]}, {"servers": ["8.8.8.8"]},
                       {"servers": ["127.0.0.11", "8.8.8.8"]}, {"servers": []}, {"servers": ["127.0.0.1"]}):
            with self.subTest(change=change):
                self.assertEqual(self.verdict(dict(self.ENFORCED, **change))[0], ["FAIL", "INCONCLUSIVE"])

    def test_unavailable_enforcement_evidence_is_inconclusive(self):
        for change in ({"upstream": None}, {"servers": None, "upstream": None}):
            with self.subTest(change=change):
                self.assertEqual(self.verdict(dict(self.ENFORCED, **change))[0], ["INCONCLUSIVE", "INCONCLUSIVE"])
        for broken, code in (("not json", 0), ("", 1), (json.dumps(self.ENFORCED), 125), ("[]", 0), ("{}", 0),
                             (json.dumps(dict(self.ENFORCED, external={"resolver": "refused by policy", "lookup": "temporary"})), 0),
                             (json.dumps(dict(self.ENFORCED, external="failure")), 0),
                             (json.dumps(dict(self.ENFORCED, upstream="127.0.0.1")), 0),
                             (json.dumps(dict(self.ENFORCED, servers=[["127.0.0.11"]])), 0)):
            with self.subTest(broken=broken[:30], code=code):
                self.assertEqual(self.verdict(broken, code=code)[0], ["INCONCLUSIVE", "INCONCLUSIVE"])
        # Even then, a container created without the restriction is a failure, not an unknown.
        self.assertEqual(self.verdict("not json", dns=None)[0], ["FAIL", "INCONCLUSIVE"])

    def test_service_discovery_must_still_work(self):
        for internal in ({"resolver": "failure", "lookup": "temporary"}, {"resolver": "answer", "lookup": "temporary"},
                         {"resolver": "timeout", "lookup": "resolved"}):
            self.assertEqual(self.verdict(dict(self.ENFORCED, internal=internal))[0], ["PASS", "INCONCLUSIVE"])

    def test_nothing_the_container_reports_is_printed_back(self):
        hostile = dict(self.ENFORCED, upstream=["\x1b[31mPASS", "EVIL-UPSTREAM"], servers=["EVIL-SERVER"])
        for probe in (hostile, dict(self.ENFORCED, upstream=["EVIL-UPSTREAM"])):
            _, output = self.verdict(probe)
            for text in ("EVIL", "\x1b"):
                self.assertNotIn(text, output)
        self.assertNotIn("except Exception", verify.RESOLVER_PROBE)
        self.assertNotIn("str(e", verify.RESOLVER_PROBE)


class RepositoryTests(unittest.TestCase):
    def read(self, name):
        return (ROOT / name).read_text(encoding="utf-8")

    def test_vpn_topology_file_grants_nothing_beyond_the_reviewed_set(self):
        text = re.sub(r"(?m)#.*$", "", self.read("docker-compose.vpn.yml"))
        for forbidden in ("privileged", "SYS_ADMIN", "SYS_MODULE", "NET_RAW", "network_mode: host", "sysctls", "devices:",
                          "/dev/net/tun", "ports:", "pid:", "ipc:", "unconfined", "restart: always", "restart: unless-stopped",
                          "PRIVATE_KEY", "PRESHARED", "FIREWALL_OUTBOUND_SUBNETS", "FIREWALL_INPUT_PORTS", "FIREWALL_VPN_INPUT_PORTS"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(re.findall(r"cap_add:\n((?:\s+- \w+\s*\n)+)", text), ["      - NET_ADMIN       \n      - DAC_OVERRIDE    \n"])
        gateway = text[text.index("\n  gateway:\n"):text.index("\n  uiproxy:\n")]
        self.assertIn("network_mode: service:vpn", gateway)
        for key in ("networks:", "hostname:", "ports:"):
            self.assertNotIn(key, gateway)
        self.assertIn("condition: service_healthy", gateway)
        self.assertEqual(text.count("- gateway"), 2)  # the alias on the sandbox network and the browser's dependency
        self.assertRegex(text, r"image: qmcgaw/gluetun@sha256:[0-9a-f]{64}\n")
        for setting in ("HTTP_CONTROL_SERVER_ADDRESS=127.0.0.1:8000", "HEALTH_SERVER_ADDRESS=127.0.0.1:9999", "DNS_SERVER=off",
                        "HTTPPROXY=off", "SHADOWSOCKS=off", "PUBLICIP_ENABLED=off", "VERSION_INFORMATION=off", "UPDATER_PERIOD=0",
                        "BLOCK_MALICIOUS=off", "WIREGUARD_ALLOWED_IPS=0.0.0.0/0", "WIREGUARD_IMPLEMENTATION=kernelspace",
                        "LOG_LEVEL=warn", "VPN_SERVICE_PROVIDER=custom", "VPN_TYPE=wireguard"):
            self.assertIn("- " + setting, [line.strip() for line in text.splitlines()])  # the whole value, nothing appended
        self.assertEqual(text.count("read_only: true"), 3)
        self.assertEqual(text.count("create_host_path: false"), 3)

    def test_both_topologies_share_networks_and_service_definitions(self):
        direct, tunnel = self.read("docker-compose.yml"), self.read("docker-compose.vpn.yml")
        self.assertEqual(direct[direct.index("\nnetworks:\n"):].replace("docker-compose.vpn.yml", "X"),
                         tunnel[tunnel.index("\nnetworks:\n"):].replace("docker-compose.yml", "X"))
        for text in (direct, tunnel):
            self.assertEqual(sorted(re.findall(r"service: (\w+)", text)), ["gateway", "safebrowse", "uiproxy"])
            self.assertEqual(text.count("file: compose.services.yml"), 3)
        self.assertNotIn("vpn", re.sub(r"(?m)#.*$", "", direct))
        shared = self.read("compose.services.yml")
        for key in ("networks:", "network_mode:", "hostname: gateway", "depends_on:", "safebrowse.mode"):
            self.assertNotIn(key, re.sub(r"(?m)#.*$", "", shared))
        self.assertIn("- TZ=Etc/UTC", shared)
        self.assertNotIn("Melbourne", shared + direct + tunnel)

    def test_control_server_roles_leave_only_the_version_route(self):
        text = re.sub(r"(?m)#.*$", "", self.read("security/gluetun-auth.toml"))
        self.assertEqual(re.findall(r"routes = (\[.*\])", text), ['["GET /v1/version"]'])
        self.assertEqual(text.count("[[roles]]"), 1)
        for secret in ("apikey", "password", "username"):
            self.assertNotIn(secret, text)

    def test_generated_secrets_are_ignored_by_git_and_excluded_from_the_build(self):
        self.assertIn(".runtime/", self.read(".gitignore").splitlines())
        ignored = self.read(".dockerignore").splitlines()
        self.assertIn("**", ignored)
        self.assertFalse([line for line in ignored if line.startswith("!") and ("runtime" in line or "conf" in line)])
        attributes = self.read(".gitattributes")
        for pattern in ("*.toml", "*.yml", "security/**"):
            self.assertIn(pattern, attributes)
        for name in ("compose.services.yml", "docker-compose.vpn.yml", "security/gluetun-auth.toml", "scripts/vpn.py"):
            self.assertNotIn(b"\r", (ROOT / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
