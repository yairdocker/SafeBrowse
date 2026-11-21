"""Offline regressions for the VPN suite's packet-capture windows (tests/vpn_capture.py).

Nothing here starts a container or captures a packet: Docker is a scripted stand-in, the clock is simulated,
and the packets are hand-built Ethernet frames with the tcpdump lines that would describe them.
"""
import io
import json
from pathlib import Path
import re
import struct
import subprocess
import tarfile
import tempfile
import unittest

import vpn_capture
from vpn_capture import CaptureError

ROOT = Path(__file__).resolve().parent.parent
VPN, PEER, OBSERVER, TUNNEL = "198.18.0.2", "198.18.0.20", "198.18.0.30", "10.64.0.2"
OWN, PEER_LINK, OTHER_LINK, BROADCAST = "02:42:c6:12:00:02", "02:42:c6:12:00:14", "02:42:c6:12:00:1e", "ff:ff:ff:ff:ff:ff"
KEY = "kPrivateKeyMaterialForTheFixtureOnly0123456789="


def frame(source, target, ethertype=0x0800, body=b"\0" * 28):
    return bytes.fromhex(target.replace(":", "")) + bytes.fromhex(source.replace(":", "")) + struct.pack("!H", ethertype) + body


def pcap(packets, order="<", magic=0xa1b2c3d4, linktype=1, start=1794528000):
    data = struct.pack(order + "IHHiIII", magic, 2, 4, 0, 0, 262144, linktype)
    for index, packet in enumerate(packets):
        data += struct.pack(order + "IIII", start + index, 1000 + index, len(packet), len(packet)) + packet
    return data


def tar(members):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


# (frame, tcpdump -nn -q line): what the suite accepts...
OUT_TUNNEL = (frame(OWN, PEER_LINK), f"00:04:10.000001 IP {VPN}.43210 > {PEER}.51820: UDP, length 148")
IN_TUNNEL = (frame(PEER_LINK, OWN), f"00:04:10.000002 IP {PEER}.51820 > {VPN}.43210: UDP, length 92")
# One complete Ethernet frame from hosted Ubuntu run 44780762773, including its ICMPv6 checksum.
RS_PACKET = bytes.fromhex(
    "333300000002 5265a0cb021b 86dd 60000000 0010 3aff "
    "fe800000000000005065a0fffecb021b ff020000000000000000000000000002 "
    "85009496 00000000 01015265a0cb021b")
RS_LINE = "00:04:11.000007 IP6 fe80::5065:a0ff:fecb:21b > ff02::2: ICMP6, router solicitation, length 16"
INBOUND_RS = (RS_PACKET, RS_LINE)

# ...and deliberately unmatched records, one of each kind the suite must keep rejecting.
UNMATCHED = {
    "outbound from the tunnel address": (frame(OWN, OTHER_LINK), f"00:04:11.000003 IP {TUNNEL}.40000 > 203.0.113.10.80: tcp 0"),
    "outbound from the egress address": (frame(OWN, OTHER_LINK), f"00:04:11.000004 IP {VPN}.40002 > {OBSERVER}.80: tcp 0"),
    "inbound to the egress address": (frame(OTHER_LINK, OWN), f"00:04:11.000005 IP {OBSERVER}.80 > {VPN}.40002: tcp 0"),
    "inbound broadcast": (frame(OTHER_LINK, BROADCAST), "00:04:11.000006 IP 198.18.0.1.68 > 255.255.255.255.67: UDP, length 300"),
    "IPv6": (frame(OTHER_LINK, "33:33:00:00:00:02", 0x86dd), "00:04:11.000007 IP6 fe80::42:c6ff:fe12:1e > ff02::2: ICMP6, router solicitation, length 16"),
    "non-IP": (frame(OTHER_LINK, "01:80:c2:00:00:0e", 0x88cc), "00:04:11.000008 LLDP, length 46"),
    "unparseable": (frame(OWN, PEER_LINK, 0xffff), "?? this is not a line tcpdump is known to print"),
    "another port on the peer": (frame(OWN, PEER_LINK), f"00:04:11.000009 IP {VPN}.43210 > {PEER}.51821: UDP, length 148"),
    "TCP to the WireGuard port": (frame(OWN, PEER_LINK), f"00:04:11.000010 IP {VPN}.43210 > {PEER}.51820: tcp 0"),
    "another host using the port": (frame(OTHER_LINK, OWN), f"00:04:11.000011 IP {OBSERVER}.51820 > {VPN}.43210: UDP, length 92"),
    "ICMP from the peer": (frame(PEER_LINK, OWN), f"00:04:11.000012 IP {PEER} > {VPN}: ICMP {PEER} udp port 51820 unreachable, length 36"),
}


def statistics(captured, received, dropped):
    """What tcpdump writes when it stops: "1 packet", otherwise "N packets"."""
    def counted(number, what):
        return f"{number} packet{'' if number == 1 else 's'} {what}\n"
    return ("tcpdump: listening on egr0, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n"
            + counted(captured, "captured") + counted(received, "received by filter")
            + counted(dropped, "dropped by kernel")).encode()


class Result:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class Docker:
    """A scripted Docker. `traffic` maps a window's sequence number to its (frame, line) packets."""

    def __init__(self, traffic=None, **settings):
        self.traffic, self.settings, self.calls, self.probes = traffic or {}, settings, [], []
        self.probe = None

    def packets(self, container):
        return self.traffic.get(int(container.rsplit("-", 1)[1]), [OUT_TUNNEL, IN_TUNNEL])

    def __call__(self, *args, input=None, timeout=60):
        self.calls.append(args)
        setting = self.settings.get
        if setting("raises") and args[:2] == setting("raises"):
            raise subprocess.TimeoutExpired(args, timeout)
        if args[:3] == ("docker", "rm", "--force"):
            if self.probe:
                self.probes.append((args[3], self.probe(args[3])))
            return Result()
        if args[:3] == ("docker", "run", "--detach"):
            return Result(setting("start_exit", 0))
        if args[:2] == ("docker", "exec") and args[3:5] == ("test", "-s"):
            return Result(1 if setting("never_ready") else 0)
        if args[:2] == ("docker", "exec") and args[3] == "ip" and "link" in args:
            if setting("no_link_address"):
                return Result(1)
            return Result(stdout=f"2: egr0@if9: <BROADCAST,UP> mtu 1500 link/ether {OWN} brd {BROADCAST}\n".encode())
        if args[:2] == ("docker", "stop"):
            return Result(setting("stop_exit", 0))
        if args[:2] == ("docker", "inspect"):
            return Result(stdout=f"{setting('tcpdump_exit', 0)}\n".encode())
        if args[:2] == ("docker", "logs"):
            count = len(self.packets(args[2]))
            output = setting("logs", statistics(setting("reported", count), setting("received", count), setting("dropped", 0)))
            return Result(setting("logs_exit", 0), stderr=output)
        if args[:2] == ("docker", "cp"):
            container = args[2].split(":")[0]
            if setting("cp_exit"):
                return Result(setting("cp_exit"))
            data = setting("capture", pcap([packet for packet, _ in self.packets(container)]))
            return Result(stdout=setting("archive", tar([("egress.pcap", data)])))
        if args[:4] == ("docker", "run", "--rm", "-i"):
            if setting("decode_exit"):
                return Result(setting("decode_exit"), stderr=b"tcpdump: truncated dump file")
            if "decoded" in self.settings:
                return Result(stdout=setting("decoded"))
            lines = next(([line for _, line in packets] for packets in
                          [self.packets(f"x-{n:02d}") for n in range(1, 40)]
                          if pcap([packet for packet, _ in packets]) == input), None)
            return Result(stdout=("\n".join(lines) + "\n").encode() if lines else b"")
        if args[:2] == ("docker", "exec"):  # the read-only state listings
            if setting("state_exit") and args[3] in setting("state_unavailable", ("ip6tables-save",)):
                return Result(setting("state_exit"))
            return Result(stdout=setting("state", f"output of {' '.join(args[3:])}\n").encode())
        raise AssertionError(f"unexpected command: {args}")

    def index(self, *prefix):
        return next(position for position, call in enumerate(self.calls) if call[:len(prefix)] == prefix)


class CaptureCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve() / "evidence"
        self.lines, self.now = [], [1794528000.0]

    def capture(self, docker=None, directory="default", **options):
        self.docker = docker or Docker()
        return vpn_capture.Capture(
            self.docker, "fixture", "fixture-vpn", "fixture-peer:test", "egr0", PEER, lambda: VPN,
            directory=self.directory if directory == "default" else directory, emit=self.lines.append,
            clock=lambda: self.now[0], sleep=lambda seconds: self.now.__setitem__(0, self.now[0] + seconds), **options)

    def printed(self, prefix):
        return [line for line in self.lines if line.startswith(prefix)]

    def manifest(self, window):
        return json.loads((self.directory / window / "manifest.json").read_text())

    def files(self):
        return sorted(str(path.relative_to(self.directory)) for path in self.directory.rglob("*") if path.is_file())


class VerdictTests(unittest.TestCase):
    """The acceptance rule is exactly what it was before windows and diagnostics existed."""

    def test_the_pattern_is_the_original_expression(self):
        original = (rf"IP ({re.escape(VPN)}\.\d+ > {re.escape(PEER)}\.51820|"
                    rf"{re.escape(PEER)}\.51820 > {re.escape(VPN)}\.\d+): UDP")
        self.assertEqual(vpn_capture.tunnel_pattern(VPN, PEER).pattern, original)
        self.assertEqual(vpn_capture.CAPTURE_FILTER, ("not", "arp"))

    def test_wireguard_in_either_direction_is_accepted_unchanged(self):
        text = "\n".join([OUT_TUNNEL[1], IN_TUNNEL[1], OUT_TUNNEL[1]]) + "\n"
        lines, rejected = vpn_capture.split(text, VPN, PEER)
        self.assertEqual((len(lines), rejected), (3, []))
        self.assertTrue(vpn_capture.acceptable(len(lines), rejected))

    def test_every_kind_of_unmatched_record_is_still_rejected(self):
        for kind, (_, line) in UNMATCHED.items():
            with self.subTest(kind=kind):
                lines, rejected = vpn_capture.split(f"{OUT_TUNNEL[1]}\n{line}\n{IN_TUNNEL[1]}\n", VPN, PEER)
                self.assertEqual((len(lines), rejected), (3, [1]))
                self.assertFalse(vpn_capture.acceptable(len(lines), rejected))
                self.assertFalse(vpn_capture.acceptable(len(lines), rejected, quiet=True))

    def test_only_blank_lines_are_not_packets(self):
        lines, rejected = vpn_capture.split(f"\n{OUT_TUNNEL[1]}\n   \n-\n\n", VPN, PEER)
        self.assertEqual((lines, rejected), ([OUT_TUNNEL[1], "-"], [1]))

    def test_an_empty_window_passes_only_where_the_scenario_may_be_quiet(self):
        self.assertFalse(vpn_capture.acceptable(0, []))
        self.assertTrue(vpn_capture.acceptable(0, [], quiet=True))
        self.assertTrue(vpn_capture.acceptable(2, []))
        self.assertFalse(vpn_capture.acceptable(2, [0], quiet=True))

    def test_direction_annotations_do_not_change_the_verdict(self):
        records = [OUT_TUNNEL, IN_TUNNEL, *UNMATCHED.values()]
        text = "\n".join(line for _, line in records) + "\n"
        expected = vpn_capture.split(text, VPN, PEER)
        _, parsed = vpn_capture.frames(pcap([packet for packet, _ in records]))
        for own in (OWN, PEER_LINK, OTHER_LINK, None):  # whatever the measurement says about who sent what
            with self.subTest(own=own):
                described = [vpn_capture.describe(index, parsed[index], 1, own, line, VPN)
                             for index, (_, line) in enumerate(records)]
                self.assertEqual(vpn_capture.split(text, VPN, PEER), expected)
                # The annotated summaries themselves, fed back in, are judged exactly as the plain lines were.
                self.assertEqual(vpn_capture.split("\n".join(described), VPN, PEER)[1], expected[1])
        self.assertEqual(expected[1], list(range(2, len(records))))


class ReadingTests(unittest.TestCase):
    def test_complete_captures_are_read_in_every_form_tcpdump_writes(self):
        packets = [OUT_TUNNEL[0], IN_TUNNEL[0]]
        for order, magic in (("<", 0xa1b2c3d4), (">", 0xa1b2c3d4), ("<", 0xa1b23c4d), (">", 0xa1b23c4d)):
            with self.subTest(order=order, magic=hex(magic)):
                linktype, found = vpn_capture.frames(pcap(packets, order, magic))
                self.assertEqual((linktype, len(found), found[0].packet, found[1].length), (1, 2, packets[0], 42))
        self.assertEqual(vpn_capture.frames(pcap([]))[1], [])
        self.assertEqual(vpn_capture.stamp(vpn_capture.frames(pcap(packets))[1][1]), "2026-11-13T00:00:01.001001Z")

    def test_missing_unreadable_and_truncated_captures_are_errors(self):
        whole = pcap([OUT_TUNNEL[0], IN_TUNNEL[0]])
        for name, data in (("empty", b""), ("header only in part", whole[:20]), ("not a pcap", b"\0" * 64),
                           ("pcapng", b"\x0a\x0d\x0d\x0a" + b"\0" * 60), ("cut in a packet header", whole[:24 + 16 + 42 + 7]),
                           ("cut inside a packet", whole[:-5])):
            with self.subTest(capture=name), self.assertRaises(CaptureError):
                vpn_capture.frames(data)

    def test_the_copied_archive_must_be_one_regular_file(self):
        self.assertEqual(vpn_capture.single_file(tar([("egress.pcap", b"data")])), b"data")
        for name, archive in (("nothing", b""), ("not an archive", b"plain text"), ("a directory", tar([("egress.pcap", None)])),
                              ("two files", tar([("a", b"1"), ("b", b"2")])),
                              ("cut short", tar([("egress.pcap", b"x" * 4000)])[:1500])):
            with self.subTest(archive=name), self.assertRaises(CaptureError):
                vpn_capture.single_file(archive)


class StatisticsTests(unittest.TestCase):
    CAPTURED, RECEIVED, DROPPED = "packets captured", "packets received by filter", "packets dropped by kernel"

    def test_singular_and_plural_counters_are_read_under_the_same_names(self):
        self.assertEqual(vpn_capture.statistics("5 packets captured\n7 packets received by filter\n0 packets dropped by kernel\n"),
                         {self.CAPTURED: 5, self.RECEIVED: 7, self.DROPPED: 0})
        self.assertEqual(vpn_capture.statistics("1 packet captured\n1 packet received by filter\n1 packet dropped by kernel\n"),
                         {self.CAPTURED: 1, self.RECEIVED: 1, self.DROPPED: 1})
        self.assertEqual(vpn_capture.statistics("1 packet captured\n2 packets received by filter\n0 packets dropped by kernel\n"),
                         {self.CAPTURED: 1, self.RECEIVED: 2, self.DROPPED: 0})
        self.assertEqual(vpn_capture.statistics("0 packets captured\n0 packets received by filter\n1 packet dropped by kernel\n"),
                         {self.CAPTURED: 0, self.RECEIVED: 0, self.DROPPED: 1})
        # The one-line form tcpdump prints when asked for its counters while running.
        self.assertEqual(vpn_capture.statistics("tcpdump: 1 packet captured, 12 packets received by filter, 1 packet dropped by kernel\n"),
                         {self.CAPTURED: 1, self.RECEIVED: 12, self.DROPPED: 1})
        self.assertEqual(vpn_capture.statistics(statistics(1, 3, 1).decode()), {self.CAPTURED: 1, self.RECEIVED: 3, self.DROPPED: 1})
        self.assertEqual(vpn_capture.statistics("2 packets captured\r\n2 packets received by filter\r\n0 packets dropped by kernel\r\n"),
                         {self.CAPTURED: 2, self.RECEIVED: 2, self.DROPPED: 0})

    def test_a_missing_or_malformed_counter_is_left_out_and_never_read_as_zero(self):
        self.assertEqual(vpn_capture.statistics(""), {})
        self.assertEqual(vpn_capture.statistics("tcpdump: listening on egr0\n"), {})
        self.assertEqual(vpn_capture.statistics("3 packets captured\n3 packets received by filter\n"),
                         {self.CAPTURED: 3, self.RECEIVED: 3})
        for name, line in (("no number", "packets dropped by kernel"), ("a word", "no packets dropped by kernel"),
                           ("negative", "-1 packets dropped by kernel"), ("a fraction", "1.5 packets dropped by kernel"),
                           ("hexadecimal", "0x0 packets dropped by kernel"), ("joined to the number", "0packets dropped by kernel"),
                           ("number after the label", "packets dropped by kernel: 0"),
                           ("two spaces", "0  packets dropped by kernel"), ("a longer word", "0 packets dropped by kernels"),
                           ("contradicting itself", "0 packets dropped by kernel\n2 packets dropped by kernel"),
                           ("valid once and malformed once", "0 packets dropped by kernel\n? packets dropped by kernel")):
            with self.subTest(counter=name):
                self.assertEqual(vpn_capture.statistics(f"4 packets captured\n4 packets received by filter\n{line}\n"),
                                 {self.CAPTURED: 4, self.RECEIVED: 4})
        self.assertEqual(vpn_capture.statistics("0 packets dropped by kernel\n0 packets dropped by kernel\n"), {self.DROPPED: 0})


class DirectionTests(unittest.TestCase):
    def directions(self, record, own=OWN, linktype=1):
        parsed = vpn_capture.frames(pcap([record[0]], linktype=linktype))[1][0]
        return vpn_capture.direction(parsed, linktype, own, record[1], VPN)

    def test_measured_from_the_link_layer_when_it_is_available(self):
        self.assertEqual(self.directions(OUT_TUNNEL), ("outbound", "measured"))
        self.assertEqual(self.directions(IN_TUNNEL), ("inbound", "measured"))
        # A packet leaving with the tunnel's address is outbound by measurement, though no fixture address says so.
        self.assertEqual(self.directions(UNMATCHED["outbound from the tunnel address"]), ("outbound", "measured"))
        self.assertEqual(self.directions(UNMATCHED["IPv6"]), ("inbound", "measured"))
        self.assertEqual(self.directions(UNMATCHED["non-IP"]), ("inbound", "measured"))

    def test_inferred_from_fixture_addresses_only_when_there_is_no_measurement(self):
        for own, linktype in ((None, 1), (OWN, 113)):
            with self.subTest(own=own, linktype=linktype):
                self.assertEqual(self.directions(OUT_TUNNEL, own, linktype), ("outbound", "inferred"))
                self.assertEqual(self.directions(UNMATCHED["inbound to the egress address"], own, linktype), ("inbound", "inferred"))

    def test_unknown_when_neither_establishes_it(self):
        for kind in ("outbound from the tunnel address", "inbound broadcast", "IPv6", "non-IP", "unparseable"):
            with self.subTest(kind=kind):
                self.assertEqual(self.directions(UNMATCHED[kind], own=None), ("unknown", ""))
        described = vpn_capture.describe(0, vpn_capture.frames(pcap([UNMATCHED["non-IP"][0]]))[1][0], 1, None,
                                         UNMATCHED["non-IP"][1], VPN)
        self.assertIn(" unknown ", described)
        self.assertIn("ethertype 0x88cc | 00:04:11.000008 LLDP", described)


class WindowTests(CaptureCase):
    def test_an_accepted_window_prints_the_original_message_and_keeps_its_evidence(self):
        capture = self.capture()
        window = capture.open("normal operation")
        self.assertIsNone(capture.check(window))
        self.assertIn("PASS  normal operation: all 2 packets on the egress interface were WireGuard to or from the peer", self.lines)
        self.assertEqual(self.printed("DIAG"), [])
        self.assertEqual(self.files(), ["01-normal-operation/" + name for name in sorted(vpn_capture.WINDOW_FILES)] + ["run.json"])
        manifest = self.manifest("01-normal-operation")
        self.assertEqual(manifest["counts"], {"captured_packets": 2, "decoded_lines": 2, "inbound_router_solicitations": 0,
                                               "rejected": 0, "rejected_by_direction": {}})
        self.assertEqual(manifest["status"]["verdict"], "accepted")
        self.assertEqual(manifest["fixture"], {"vpn_address": VPN, "vpn_link_address": OWN, "peer_address": PEER, "wireguard_port": 51820})
        self.assertEqual((self.directory / "01-normal-operation/capture.pcap").read_bytes(), pcap([OUT_TUNNEL[0], IN_TUNNEL[0]]))

    def test_the_capture_and_decode_commands_are_the_ones_the_suite_always_used(self):
        capture = self.capture()
        capture.check(capture.open("normal operation"))
        started = self.docker.calls[self.docker.index("docker", "run", "--detach")]
        self.assertEqual(started[4:], ("fixture-sniff-01", "--network", "container:fixture-vpn", "--cap-drop", "ALL", "--cap-add",
                                       "NET_RAW", "--cap-add", "NET_ADMIN", "--user", "0", "--entrypoint", "tcpdump",
                                       "fixture-peer:test", "-Z", "root", "-i", "egr0", "-nn", "-U", "-w", "/tmp/egress.pcap",
                                       "not", "arp"))
        decoded = self.docker.calls[self.docker.index("docker", "run", "--rm")]
        self.assertEqual(decoded[decoded.index("tcpdump"):], ("tcpdump", "fixture-peer:test", "-Z", "root", "-nn", "-q", "-r", "-"))
        self.assertIn(("--network", "none"), list(zip(decoded, decoded[1:])))

    def test_rejected_packets_are_reported_before_the_original_failure_is_raised(self):
        for kind, record in UNMATCHED.items():
            with self.subTest(kind=kind):
                self.lines.clear()
                capture = self.capture(Docker({1: [OUT_TUNNEL, record, IN_TUNNEL]}), directory=None)
                window = capture.open("route loss")
                with self.assertRaises(RuntimeError) as failure:
                    capture.check(window)
                self.assertNotIsInstance(failure.exception, CaptureError)
                self.assertEqual(str(failure.exception),
                                 "route loss: all 3 packets on the egress interface were WireGuard to or from the peer")
                self.assertEqual(self.printed("PASS  route loss"), [])
                report = "\n".join(self.printed("DIAG"))
                self.assertIn('capture window 01-route-loss (scenario "route loss", expecting tunnel traffic only) on egr0: '
                              "3 packets decoded, 1 rejected", report)
                self.assertIn(f"VPN container {VPN} (link address {OWN}), WireGuard peer {PEER}, expected UDP port 51820", report)
                self.assertIn("rejected  [2] 2026-11-13T00:00:01.001001Z ", report)
                self.assertIn(record[1], report)
                self.assertEqual(len(self.printed("DIAG  rejected  ")), 1)
                self.assertIn(f"evidence: not kept: rerun with {vpn_capture.VARIABLE} set", report)

    def test_confirmed_inbound_solicitations_are_logged_and_kept_in_the_capture(self):
        # Two valid eight-byte solicitations omit the link-layer option, with independently calculated checksums.
        short = RS_PACKET[:18] + bytes.fromhex("0008") + RS_PACKET[20:54] + bytes.fromhex("85008aeb00000000")
        unspecified = short[:22] + bytes(16) + short[38:54] + bytes.fromhex("85007bb800000000")
        short_line = RS_LINE.replace("length 16", "length 8")
        packets = [OUT_TUNNEL, INBOUND_RS, (short, short_line),
                   (unspecified, short_line.replace("fe80::5065:a0ff:fecb:21b", "::"))]
        capture = self.capture(Docker({1: packets}))
        capture.check(capture.open("route loss"))
        capture.finish()
        run = json.loads((self.directory / "run.json").read_text())
        self.assertEqual((run["outcome"], run["windows"][0]["inbound_router_solicitations"]), ("passed", 3))
        counts = self.manifest("01-route-loss")["counts"]
        self.assertEqual((counts["captured_packets"], counts["inbound_router_solicitations"], counts["rejected"]), (4, 3, 0))
        self.assertTrue(any("solicitation" in line.lower() for line in self.printed("INFO")))
        folder = self.directory / "01-route-loss"
        self.assertEqual((folder / "capture.pcap").read_bytes(), pcap([packet for packet, _ in packets]))
        self.assertIn(RS_LINE, (folder / "decoded.txt").read_text())
        self.assertNotIn(RS_LINE, (folder / "rejected.txt").read_text())

    def test_solicitations_alone_cannot_prove_tunnel_traffic_or_a_positive_control(self):
        capture = self.capture(Docker({1: [INBOUND_RS], 2: [INBOUND_RS], 3: [INBOUND_RS]}))
        with self.assertRaises(RuntimeError):
            capture.check(capture.open("route loss"))
        capture.check(capture.open("after restart"), quiet=True)
        control = capture.close(capture.open("positive control", expect=vpn_capture.DELIBERATE_LEAK))
        self.assertEqual(control.rejected_lines(), [])
        self.assertIs(control.as_expected(), False)

    def test_mixed_capture_rejects_every_other_kind_of_traffic(self):
        records = list(UNMATCHED.values())
        capture = self.capture(Docker({1: [INBOUND_RS, *records]}))
        window = capture.open("route loss")
        with self.assertRaises(RuntimeError):
            capture.check(window)
        self.assertEqual(window.rejected_lines(), [line for _, line in records])
        self.assertEqual(self.manifest("01-route-loss")["counts"]["inbound_router_solicitations"], 1)

    def test_a_solicitation_requires_consistent_measured_direction_headers_and_decode(self):
        own = bytes.fromhex(OWN.replace(":", ""))
        malformed = {
            "outbound": RS_PACKET[:6] + own + RS_PACKET[12:],
            "multicast source": RS_PACKET[:6] + b"\x53" + RS_PACKET[7:],
            "wrong destination MAC": own + RS_PACKET[6:],
            "wrong EtherType": RS_PACKET[:12] + b"\x08\x00" + RS_PACKET[14:],
            "fragment header": RS_PACKET[:20] + b"\x2c" + RS_PACKET[21:],
            "wrong hop limit": RS_PACKET[:21] + b"\x40" + RS_PACKET[22:],
            "another ICMPv6 type": RS_PACKET[:54] + b"\x86" + RS_PACKET[55:],
            "nonzero code": RS_PACKET[:55] + b"\x01" + RS_PACKET[56:],
            "bad checksum": RS_PACKET[:56] + b"\0\0" + RS_PACKET[58:],
            "truncated option": RS_PACKET[:-1],
            "wrong option MAC": RS_PACKET[:6] + bytes.fromhex("5265a0cb021c") + RS_PACKET[12:],
        }
        cases = [(label, (raw, RS_LINE), {}) for label, raw in malformed.items()]
        cases += [("different decode", (RS_PACKET, RS_LINE.replace("solicitation", "advertisement")), {}),
                  ("no interface MAC", INBOUND_RS, {"no_link_address": True}),
                  ("unknown link type", INBOUND_RS, {"capture": pcap([OUT_TUNNEL[0], RS_PACKET], linktype=113),
                                                    "decoded": f"{OUT_TUNNEL[1]}\n{RS_LINE}\n".encode()})]
        for label, record, settings in cases:
            with self.subTest(label=label):
                capture = self.capture(Docker({1: [OUT_TUNNEL, record]}, **settings), directory=None)
                window = capture.open("route loss")
                with self.assertRaises(RuntimeError):
                    capture.check(window)
                self.assertEqual(window.rejected_lines(), [record[1]])

    def test_a_measured_direction_never_rescues_or_condemns_a_packet(self):
        inbound_leak = UNMATCHED["inbound to the egress address"]
        tunnel_line_from_a_stranger = (frame(OTHER_LINK, BROADCAST, 0x86dd), OUT_TUNNEL[1])
        capture = self.capture(Docker({1: [OUT_TUNNEL, inbound_leak], 2: [tunnel_line_from_a_stranger, IN_TUNNEL]}))
        with self.assertRaises(RuntimeError):
            capture.check(capture.open("inbound only"))
        self.assertIn("inbound[measured]", "\n".join(self.printed("DIAG  rejected")))
        self.assertEqual(self.manifest("01-inbound-only")["counts"]["rejected_by_direction"], {"inbound (measured)": 1})
        capture.check(capture.open("judged by the line alone"))
        self.assertEqual(self.manifest("02-judged-by-the-line-alone")["status"]["verdict"], "accepted")
        self.assertIn("[1] 2026-11-13T00:00:00.001000Z inbound[measured]",
                      (self.directory / "02-judged-by-the-line-alone/decoded.txt").read_text())

    def test_console_output_is_bounded_and_the_artifact_is_complete(self):
        long_line = "00:04:12.000000 IP " + "x" * 600
        leaks = [(frame(OWN, OTHER_LINK), f"00:04:11.{n:06d} IP {TUNNEL}.{40000 + n} > 203.0.113.10.80: tcp 0") for n in range(54)]
        capture = self.capture(Docker({1: [OUT_TUNNEL, (frame(OWN, OTHER_LINK), long_line), *leaks, IN_TUNNEL, IN_TUNNEL]}))
        with self.assertRaises(RuntimeError) as failure:
            capture.check(capture.open("route loss"))
        self.assertIn("all 58 packets", str(failure.exception))
        self.assertEqual(len(self.printed("DIAG  rejected  ")), vpn_capture.CONSOLE_LIMIT)
        self.assertIn("58 packets decoded, 55 rejected", self.printed("DIAG  capture window")[0])
        self.assertIn(f"DIAG  15 more rejected lines are not shown here; all 55 are in {self.directory}/01-route-loss/rejected.txt",
                      self.lines)
        first = self.printed("DIAG  rejected  ")[0]
        self.assertLess(len(first), vpn_capture.LINE_LIMIT + 80)
        self.assertIn("more characters]", first)
        kept = [line for line in (self.directory / "01-route-loss/rejected.txt").read_text().splitlines() if not line.startswith("#")]
        self.assertEqual(len(kept), 55)
        self.assertTrue(kept[0].endswith(long_line) and kept[-1].endswith(leaks[-1][1]))
        self.assertEqual(len([line for line in (self.directory / "01-route-loss/decoded.txt").read_text().splitlines()
                              if not line.startswith("#")]), 58)
        self.assertEqual(self.manifest("01-route-loss")["counts"]["rejected"], 55)
        self.assertEqual(self.manifest("01-route-loss")["counts"]["rejected_by_direction"], {"outbound (measured)": 55})

    def test_an_empty_window_keeps_the_quiet_rule(self):
        capture = self.capture(Docker({1: [], 2: []}))
        with self.assertRaises(RuntimeError) as failure:
            capture.check(capture.open("normal operation"))
        self.assertEqual(str(failure.exception),
                         "normal operation: all 0 packets on the egress interface were WireGuard to or from the peer")
        self.assertIn("0 packets decoded, 0 rejected; capture complete, decoding complete, verdict rejected",
                      self.printed("DIAG  capture window")[0])
        capture.check(capture.open("after restart"), quiet=True)
        self.assertIn("PASS  after restart: all 0 packets on the egress interface were WireGuard to or from the peer", self.lines)
        self.assertEqual(self.manifest("02-after-restart")["status"]["empty_window_allowed"], True)

    def test_a_capture_that_cannot_be_trusted_never_passes(self):
        whole = pcap([OUT_TUNNEL[0], IN_TUNNEL[0]])
        broken = {
            "the capture container does not start": dict(start_exit=125),
            "tcpdump never opens the interface": dict(never_ready=True),
            "the capture file cannot be copied": dict(cp_exit=1),
            "the capture file is empty": dict(capture=b""),
            "the capture file is truncated": dict(capture=whole[:-9]),
            "the capture file is not a pcap": dict(capture=b"\0" * 80),
            "the copied archive is damaged": dict(archive=b"not a tar stream"),
            "tcpdump was killed": dict(tcpdump_exit=137),
            "docker stop failed": dict(stop_exit=1),
            "docker stop timed out": dict(raises=("docker", "stop")),
            "the kernel dropped packets": dict(dropped=3),
            "tcpdump cannot decode the capture": dict(decode_exit=1),
            "decoding printed nothing for captured packets": dict(decoded=b""),
            "decoding lost a packet": dict(decoded=(OUT_TUNNEL[1] + "\n").encode()),
            "decoding printed an extra line": dict(decoded=f"{OUT_TUNNEL[1]}\n{IN_TUNNEL[1]}\n{IN_TUNNEL[1]}\n".encode()),
            "decoded output is not text": dict(decoded=b"\xff\xfe\xfd\n\xff\n"),
        }
        for problem, settings in broken.items():
            for quiet in (False, True):
                with self.subTest(problem=problem, quiet=quiet):
                    self.lines.clear()
                    capture = self.capture(Docker(**settings), directory=None)
                    with self.assertRaises(CaptureError):
                        capture.check(capture.open("after restart"), quiet=quiet)
                    self.assertEqual(self.printed("PASS  after restart"), [])
                    self.assertNotIn("accepted", " ".join(window.verdict for window in capture.windows))

    def test_a_broken_capture_is_recorded_as_broken_not_as_empty(self):
        capture = self.capture(Docker(capture=pcap([OUT_TUNNEL[0], IN_TUNNEL[0]])[:-9]))
        with self.assertRaises(CaptureError) as failure:
            capture.check(capture.open("peer outage"), quiet=True)
        self.assertIn("capture window 01-peer-outage: the capture file is truncated inside packet 2", str(failure.exception))
        manifest = self.manifest("01-peer-outage")
        self.assertEqual(manifest["status"]["capture"], "unreadable")
        self.assertEqual(manifest["status"]["verdict"], "no verdict: the capture cannot be trusted")
        self.assertEqual(manifest["counts"]["decoded_lines"], None)
        self.assertIn("decoding not attempted", (self.directory / "01-peer-outage/decoded.txt").read_text())
        self.assertIn("DIAG  problem: capture window 01-peer-outage: the capture file is truncated inside packet 2", self.lines)
        self.assertEqual(json.loads((self.directory / "run.json").read_text())["windows"][0]["verdict"],
                         "no verdict: the capture cannot be trusted")

    def test_windows_are_separate_and_the_next_records_before_the_last_stops(self):
        leak = UNMATCHED["outbound from the egress address"]
        capture = self.capture(Docker({1: [OUT_TUNNEL], 2: [OUT_TUNNEL, IN_TUNNEL, OUT_TUNNEL], 3: [IN_TUNNEL], 4: [OUT_TUNNEL, leak]}))
        first = capture.open("route loss")
        second = capture.check(first, then="route restoration")
        third = capture.check(second, then="route loss")  # the same scenario a second time
        fourth = capture.check(third, then="positive control")
        names = [window.name for window in capture.windows]
        self.assertEqual(names, ["01-route-loss", "02-route-restoration", "03-route-loss", "04-positive-control"])
        self.assertEqual(len({window.container for window in capture.windows}), 4)
        self.assertLess(self.docker.index("docker", "run", "--detach", "--name", "fixture-sniff-02"),
                        self.docker.index("docker", "stop", "--time", "10", "fixture-sniff-01"))
        self.assertLess(self.docker.index("docker", "exec", "fixture-sniff-02", "test"),
                        self.docker.index("docker", "stop", "--time", "10", "fixture-sniff-01"))
        self.assertEqual([self.manifest(name)["counts"]["captured_packets"] for name in names[:3]], [1, 3, 1])
        self.assertEqual(len({(self.directory / name / "capture.pcap").read_bytes() for name in names[:3]}), 3)
        with self.assertRaises(RuntimeError):
            capture.check(fourth)
        self.assertEqual(self.manifest("04-positive-control")["counts"]["rejected"], 1)
        self.assertEqual(self.files(), sorted(f"{name}/{file}" for name in names for file in vpn_capture.WINDOW_FILES) + ["run.json"])
        index = json.loads((self.directory / "run.json").read_text())["windows"]
        self.assertEqual([entry["verdict"] for entry in index], ["accepted", "accepted", "accepted", "rejected"])
        self.assertEqual([entry["as_expected"] for entry in index], [True, True, True, False])

    def test_evidence_is_saved_before_the_capture_container_is_removed(self):
        capture = self.capture()
        self.docker.probe = lambda container: sorted(path.name for path in self.directory.glob("01-*/*"))
        capture.check(capture.open("normal operation"))
        removals = [saved for container, saved in self.docker.probes if container == "fixture-sniff-01"]
        self.assertEqual(removals, [[], sorted(vpn_capture.WINDOW_FILES)])  # before it started, then after the export

    def test_the_positive_control_reports_rejected_traffic_without_failing(self):
        leaks = [(frame(OWN, OTHER_LINK), f"00:04:11.{n:06d} IP {VPN}.40002 > {OBSERVER}.80: tcp 0") for n in range(14)]
        capture = self.capture(Docker({1: [OUT_TUNNEL, *leaks, UNMATCHED["inbound to the egress address"]]}))
        closed = capture.close(capture.open("positive control", expect=vpn_capture.DELIBERATE_LEAK))
        self.assertEqual(len(closed.rejected_lines()), 15)
        self.assertTrue(any(OBSERVER in line for line in closed.rejected_lines()))
        self.assertEqual(len(self.printed("DIAG  rejected  ")), vpn_capture.CONTROL_LIMIT)
        self.assertIn("expecting deliberate leak: rejected traffic is required", self.printed("DIAG  capture window")[0])
        manifest = self.manifest("01-positive-control")
        self.assertEqual((manifest["status"]["verdict"], manifest["counts"]["rejected"]), ("rejected", 15))
        self.assertIs(manifest["status"]["as_expected"], True)  # a control that showed no leak would be False
        clean = capture.close(capture.open("positive control", expect=vpn_capture.DELIBERATE_LEAK))
        self.assertEqual((clean.rejected_lines(), clean.verdict, clean.as_expected()), ([], "accepted", False))
        self.assertEqual(manifest["counts"]["rejected_by_direction"], {"outbound (measured)": 14, "inbound (measured)": 1})


class CompletenessTests(CaptureCase):
    """A capture is complete only when tcpdump's own closing statistics confirm it. Two packets are in every file here."""

    CAPTURED, RECEIVED, DROPPED = StatisticsTests.CAPTURED, StatisticsTests.RECEIVED, StatisticsTests.DROPPED
    # The three windows that used to be accepted: (stand-in settings, recorded status, part of the explanation).
    ONE_DROPPED = (dict(dropped=1), "incomplete", "the kernel dropped 1 packet before tcpdump saw them")
    LOGS_FAILED = (dict(logs_exit=1), "unverified", "closing statistics could not be read (docker logs exit 1)")
    FIVE_FOR_TWO = (dict(reported=5), "incomplete",
                    "tcpdump reported 5 packets captured, but the capture file holds 2 complete records")
    OTHERS = {
        "several packets dropped": (dict(dropped=3), "incomplete", "the kernel dropped 3 packets before"),
        "docker logs timed out": (dict(raises=("docker", "logs")), "unverified", "docker logs exit -1"),
        "docker logs failed and printed nothing": (dict(logs_exit=1, logs=b""), "unverified", "docker logs exit 1"),
        "no output at all": (dict(logs=b""), "unverified", "packets captured or packets dropped by kernel"),
        "no statistics": (dict(logs=b"tcpdump: listening on egr0\n"), "unverified", "packets captured or packets dropped by kernel"),
        "no captured count": (dict(logs=b"2 packets received by filter\n0 packets dropped by kernel\n"), "unverified",
                              "readable count of packets captured,"),
        "no dropped count": (dict(logs=b"2 packets captured\n2 packets received by filter\n"), "unverified",
                             "readable count of packets dropped by kernel,"),
        "only the filter count": (dict(logs=b"2 packets received by filter\n"), "unverified",
                                  "packets captured or packets dropped by kernel"),
        "malformed captured count": (dict(logs=b"two packets captured\n2 packets received by filter\n0 packets dropped by kernel\n"),
                                     "unverified", "readable count of packets captured,"),
        "malformed dropped count": (dict(logs=b"2 packets captured\n2 packets received by filter\n? packets dropped by kernel\n"),
                                    "unverified", "readable count of packets dropped by kernel,"),
        "negative dropped count": (dict(logs=b"2 packets captured\n2 packets received by filter\n-1 packets dropped by kernel\n"),
                                   "unverified", "readable count of packets dropped by kernel,"),
        "captured count contradicts itself": (dict(logs=b"2 packets captured\n3 packets captured\n0 packets dropped by kernel\n"),
                                              "unverified", "readable count of packets captured,"),
        "statistics are not text": (dict(logs=b"\xff\xfe 2 packets\xff captured\n\xff"), "unverified", "packets captured or"),
        "one reported for two in the file": (dict(reported=1), "unverified",
                                             "tcpdump reported 1 packet captured, but the capture file holds 2 complete records"),
        "none reported for two in the file": (dict(reported=0), "unverified", "tcpdump reported 0 packets captured"),
        "three reported for two in the file": (dict(reported=3), "incomplete", "tcpdump reported 3 packets captured"),
    }

    def refused(self, settings, status, explanation, quiet, traffic=None):
        """One window with these statistics is checked: it must fail as a capture, be kept, and never be called complete."""
        self.lines.clear()
        self.directory = self.directory.parent / f"evidence-{len(list(self.directory.parent.iterdir()))}"
        capture = self.capture(Docker(traffic, **settings))
        self.docker.probe = lambda container: self.files()
        window = capture.open("after restart")
        with self.assertRaises(CaptureError) as failure:
            capture.check(window, quiet=quiet)
        self.assertIn("capture window 01-after-restart: ", str(failure.exception))
        self.assertIn(explanation, str(failure.exception))
        self.assertEqual(self.printed("PASS  after restart"), [])
        self.assertEqual((window.capture, window.decoding, window.verdict),
                         (status, "not attempted", "no verdict: the capture cannot be trusted"))
        manifest = self.manifest("01-after-restart")
        self.assertEqual(manifest["status"]["capture"], status)
        self.assertEqual(manifest["status"]["problem"], str(failure.exception))
        self.assertIsNone(manifest["status"]["as_expected"])
        self.assertNotIn("complete", json.loads((self.directory / "run.json").read_text())["windows"][0]["capture"].split())
        return capture, window, manifest

    def test_one_packet_dropped_by_the_kernel_is_an_incomplete_capture(self):
        for quiet in (False, True):
            with self.subTest(quiet=quiet):
                _, window, manifest = self.refused(*self.ONE_DROPPED, quiet)
                self.assertEqual(window.statistics, {self.CAPTURED: 2, self.RECEIVED: 2, self.DROPPED: 1})
                self.assertEqual(manifest["tcpdump_statistics"][self.DROPPED], 1)

    def test_a_failed_docker_logs_is_never_a_complete_capture(self):
        for quiet in (False, True):
            with self.subTest(quiet=quiet):
                # The stand-in still prints two captured, none dropped: plausible, and from a command that failed.
                _, window, manifest = self.refused(*self.LOGS_FAILED, quiet)
                self.assertEqual((window.statistics, manifest["tcpdump_statistics"]), ({}, {}))

    def test_more_packets_reported_than_recorded_is_an_incomplete_capture(self):
        for quiet in (False, True):
            with self.subTest(quiet=quiet):
                _, window, manifest = self.refused(*self.FIVE_FOR_TWO, quiet)
                self.assertEqual((manifest["tcpdump_statistics"][self.CAPTURED], manifest["counts"]["captured_packets"]), (5, 2))

    def test_missing_malformed_and_contradictory_statistics_all_fail_quiet_or_not(self):
        for problem, (settings, status, explanation) in self.OTHERS.items():
            for quiet in (False, True):
                with self.subTest(problem=problem, quiet=quiet):
                    self.refused(settings, status, explanation, quiet)

    def test_an_empty_capture_passes_only_when_quiet_and_only_when_confirmed_empty(self):
        capture = self.capture(Docker({1: [], 2: []}))
        with self.assertRaises(RuntimeError) as failure:
            capture.check(capture.open("normal operation"))
        self.assertNotIsInstance(failure.exception, CaptureError)  # a whole capture, rejected because it is empty
        self.assertEqual(self.manifest("01-normal-operation")["status"]["capture"], "complete")
        capture.check(capture.open("after restart"), quiet=True)
        manifest = self.manifest("02-after-restart")
        self.assertEqual(manifest["tcpdump_statistics"], {self.CAPTURED: 0, self.RECEIVED: 0, self.DROPPED: 0})
        self.assertEqual((manifest["status"]["capture"], manifest["status"]["verdict"], manifest["counts"]["captured_packets"]),
                         ("complete", "accepted", 0))
        self.assertEqual((self.directory / "02-after-restart/capture.pcap").read_bytes(), pcap([]))
        # An empty file is not an empty capture unless the statistics say nothing was captured and nothing dropped.
        for problem, (settings, status, explanation) in {
                "one packet dropped": (dict(dropped=1), "incomplete", "the kernel dropped 1 packet before"),
                "one packet reported": (dict(reported=1), "incomplete", "reported 1 packet captured, but the capture file holds 0 complete records"),
                "docker logs failed": (dict(logs_exit=1), "unverified", "docker logs exit 1"),
                "no statistics": (dict(logs=b""), "unverified", "packets captured or packets dropped by kernel")}.items():
            for quiet in (True, False):
                with self.subTest(problem=problem, quiet=quiet):
                    self.refused(settings, status, explanation, quiet, traffic={1: []})

    def test_a_valid_one_packet_capture_passes(self):
        capture = self.capture(Docker({1: [OUT_TUNNEL]}))
        capture.check(capture.open("after restart"))
        self.assertIn("PASS  after restart: all 1 packets on the egress interface were WireGuard to or from the peer", self.lines)
        manifest = self.manifest("01-after-restart")
        self.assertEqual(manifest["tcpdump_statistics"], {self.CAPTURED: 1, self.RECEIVED: 1, self.DROPPED: 0})
        self.assertEqual((manifest["status"]["capture"], manifest["status"]["decoding"], manifest["status"]["verdict"]),
                         ("complete", "complete", "accepted"))
        self.assertEqual(self.printed("DIAG"), [])

    def test_the_filter_count_need_not_equal_the_captured_count(self):
        for received in (18, 3, 1, 0):
            with self.subTest(received=received):
                self.directory = self.directory.parent / f"received-{received}"
                capture = self.capture(Docker(received=received))
                capture.check(capture.open("route restoration"))
                manifest = self.manifest("01-route-restoration")
                self.assertEqual(manifest["tcpdump_statistics"], {self.CAPTURED: 2, self.RECEIVED: received, self.DROPPED: 0})
                self.assertEqual((manifest["status"]["capture"], manifest["status"]["verdict"]), ("complete", "accepted"))
        # A filter count is not a substitute for either required counter.
        self.refused(dict(logs=b"2 packets received by filter\n"), "unverified", "packets captured or packets dropped", False)

    def test_what_was_captured_is_kept_before_the_container_is_removed(self):
        whole = pcap([OUT_TUNNEL[0], IN_TUNNEL[0]])
        for settings, status, explanation in (self.ONE_DROPPED, self.LOGS_FAILED, self.FIVE_FOR_TWO):
            with self.subTest(status=status, explanation=explanation):
                self.refused(settings, status, explanation, quiet=True)
                kept = sorted(f"01-after-restart/{name}" for name in vpn_capture.WINDOW_FILES)
                removals = [seen for container, seen in self.docker.probes if container == "fixture-sniff-01"]
                self.assertEqual(removals, [["run.json"], kept + ["run.json"]])  # before it started, then after the export
                self.assertEqual(self.docker.calls[-1], ("docker", "rm", "--force", "fixture-sniff-01"))
                self.assertEqual((self.directory / "01-after-restart/capture.pcap").read_bytes(), whole)
                self.assertIn(f"capture {status}, decoding not attempted", (self.directory / "01-after-restart/decoded.txt").read_text())
                report = self.printed("DIAG")
                self.assertIn(f"capture {status}, decoding not attempted, verdict no verdict", report[0])
                self.assertTrue(any(line.startswith("DIAG  problem: capture window 01-after-restart: ") and explanation in line
                                    for line in report))
                self.assertIn(f"DIAG  evidence: kept in {self.directory}/01-after-restart", report)
                self.assertLessEqual(len(report), 4)  # bounded: nothing is decoded, so no packet lines


class FailureTests(CaptureCase):
    @staticmethod
    def unwritable(folder, name, data):
        raise PermissionError(13, "Permission denied", f"{folder}/{name}")

    def fail(self, capture, **options):
        """What tests/integration_vpn.py does around the suite: export, then re-raise, then clean up."""
        try:
            try:
                raise RuntimeError("the original failure")
            except BaseException as error:
                capture.failed(error, **options)
                raise
            finally:
                capture.cleanup()
        except RuntimeError as error:
            return error

    def test_the_active_capture_and_the_fixture_state_are_exported_before_cleanup(self):
        capture = self.capture(Docker({2: [OUT_TUNNEL, UNMATCHED["IPv6"]]}))
        capture.check(capture.open("normal operation"), then="route loss")
        self.docker.probe = lambda container: self.files()
        error = self.fail(capture)
        self.assertEqual(str(error), "the original failure")
        seen_at_removal = dict(self.docker.probes)["fixture-sniff-02"]
        self.assertTrue({f"02-route-loss/{name}" for name in vpn_capture.WINDOW_FILES} <= set(seen_at_removal))
        manifest = self.manifest("02-route-loss")
        self.assertEqual(manifest["status"]["verdict"], "not checked: the suite failed while this window was open")
        self.assertEqual((manifest["counts"]["captured_packets"], manifest["counts"]["rejected"]), (2, 1))
        self.assertIn(UNMATCHED["IPv6"][1], "\n".join(self.printed("DIAG  rejected")))
        state = sorted(path.name for path in (self.directory / "failure-state").iterdir())
        self.assertEqual(state, sorted(vpn_capture.STATE_FILES))
        self.assertLess(self.docker.index("docker", "exec", "fixture-vpn", "iptables", "-S"), len(self.docker.calls) - 2)
        self.assertEqual(self.docker.calls[-2:], [("docker", "rm", "--force", "fixture-sniff-01"), ("docker", "rm", "--force", "fixture-sniff-02")])
        index = json.loads((self.directory / "run.json").read_text())
        self.assertEqual((index["outcome"], index["failure"], index["failure_state"]),
                         ("failed", "RuntimeError: the original failure", "8 of 8 listings saved"))
        self.assertEqual(capture.active, [])

    def test_an_incomplete_capture_during_a_failing_run_is_kept_and_changes_nothing_else(self):
        for name, settings, status in (("dropped", dict(dropped=1), "incomplete"), ("logs", dict(logs_exit=1), "unverified"),
                                       ("count", dict(reported=5), "incomplete")):
            with self.subTest(statistics=name):
                self.lines.clear()
                self.directory = self.directory.parent / f"failing-{name}"
                capture = self.capture(Docker(**settings))
                first = capture.open("normal operation")
                with self.assertRaises(CaptureError) as problem:  # the next window is recording before this one is judged
                    capture.check(first, then="route loss")
                self.assertEqual([window.name for window in capture.active], ["02-route-loss"])
                self.docker.probe = lambda container: self.files()
                try:
                    try:
                        raise problem.exception
                    except BaseException as error:
                        capture.failed(error)
                        raise
                    finally:
                        capture.cleanup()
                except CaptureError as error:
                    self.assertIs(error, problem.exception)  # the suite's own failure, unchanged
                for window in ("01-normal-operation", "02-route-loss"):
                    manifest = self.manifest(window)
                    self.assertEqual(manifest["status"]["capture"], status)
                    self.assertIn(f"capture window {window}: ", manifest["status"]["problem"])
                    self.assertEqual((self.directory / window / "capture.pcap").read_bytes(), pcap([OUT_TUNNEL[0], IN_TUNNEL[0]]))
                self.assertEqual(self.manifest("02-route-loss")["status"]["verdict"],
                                 "not checked: the suite failed while this window was open")
                seen_at_removal = dict(self.docker.probes)["fixture-sniff-02"]
                self.assertTrue({f"02-route-loss/{name}" for name in vpn_capture.WINDOW_FILES} <= set(seen_at_removal))
                self.assertEqual(sorted(path.name for path in (self.directory / "failure-state").iterdir()),
                                 sorted(vpn_capture.STATE_FILES))
                self.assertEqual(self.docker.calls[-2:], [("docker", "rm", "--force", "fixture-sniff-01"),
                                                          ("docker", "rm", "--force", "fixture-sniff-02")])
                index = json.loads((self.directory / "run.json").read_text())
                self.assertEqual((index["outcome"], index["failure"], index["export_errors"]),
                                 ("failed", f"CaptureError: {problem.exception}", []))
                self.assertEqual([entry["capture"] for entry in index["windows"]], [status, status])
                self.assertEqual(capture.active, [])

    def test_state_listings_are_read_only_and_an_unavailable_one_is_recorded_as_such(self):
        for name, argv in vpn_capture.STATE_COMMANDS:
            self.assertTrue(argv[:1] in (("ip",), ("iptables",), ("iptables-save",), ("ip6tables-save",)), name)
            self.assertFalse({"add", "del", "delete", "flush", "replace", "change", "set", "-A", "-I", "-D", "-F", "-X",
                              "-P", "-R", "-Z", "-N", "restore"} & set(argv), name)
        capture = self.capture(Docker(state_exit=127))
        capture.open("normal operation")
        self.fail(capture)
        listings = {entry["file"]: entry for entry in json.loads(
            (self.directory / "failure-state/manifest.json").read_text())["listings"]}
        self.assertEqual((listings["failure-state/firewall-ipv6.txt"]["exit"], listings["failure-state/firewall-ipv6.txt"]["saved"]),
                         (127, False))
        self.assertFalse((self.directory / "failure-state/firewall-ipv6.txt").exists())
        self.assertEqual((self.directory / "failure-state/firewall-rules.txt").read_text(), "output of iptables -S\n")
        self.assertIn("7 of 8 listings saved", "\n".join(self.printed("DIAG")))
        for call in self.docker.calls:
            if call[:3] == ("docker", "exec", "fixture-vpn"):
                self.assertIn(call[3:], [argv for _, argv in vpn_capture.STATE_COMMANDS])

    def test_an_export_error_does_not_replace_the_original_failure_or_stop_cleanup(self):
        capture = self.capture()
        capture.open("route loss")
        capture.store.write = self.unwritable
        error = self.fail(capture)
        self.assertEqual((type(error), str(error)), (RuntimeError, "the original failure"))
        self.assertTrue(self.printed("WARN  diagnostic artifact not saved: 01-route-loss: PermissionError"))
        self.assertIn("the failure above is the suite's own and is unchanged", "\n".join(self.printed("WARN")))
        self.assertEqual(self.docker.calls[-1], ("docker", "rm", "--force", "fixture-sniff-01"))
        self.assertIn("evidence: not kept", "\n".join(self.printed("DIAG")))

    def test_a_crash_inside_the_diagnostics_is_reported_and_swallowed(self):
        capture = self.capture()
        capture.open("route loss")
        capture.vpn_address = None
        capture._state = lambda: (_ for _ in ()).throw(ValueError("diagnostics bug"))
        error = self.fail(capture)
        self.assertEqual(str(error), "the original failure")
        self.assertIn("WARN  diagnostics could not be completed: ValueError: diagnostics bug", self.lines)
        self.assertEqual(self.docker.calls[-1], ("docker", "rm", "--force", "fixture-sniff-01"))

    def test_an_interrupted_or_crashing_step_still_retains_the_window(self):
        capture = self.capture()
        capture.open("peer outage")
        try:
            try:
                raise KeyboardInterrupt()
            except BaseException as error:
                capture.failed(error)
                raise
            finally:
                capture.cleanup()
        except KeyboardInterrupt:
            pass
        self.assertTrue((self.directory / "01-peer-outage/capture.pcap").is_file())
        self.assertEqual(json.loads((self.directory / "run.json").read_text())["outcome"], "failed")

    def test_without_a_destination_nothing_is_written_and_the_status_says_what_to_do(self):
        capture = self.capture(Docker({1: [OUT_TUNNEL, UNMATCHED["non-IP"]]}), directory=None)
        self.assertIn(f"INFO  capture evidence is not kept: set {vpn_capture.VARIABLE} to an empty absolute directory", self.lines[0])
        capture.open("route loss")
        self.fail(capture)
        self.assertFalse(self.directory.exists())
        report = "\n".join(self.printed("DIAG"))
        self.assertIn(UNMATCHED["non-IP"][1], report)
        self.assertIn(f"evidence: not kept: rerun with {vpn_capture.VARIABLE} set to an empty absolute directory", report)
        self.assertIn(f"were not collected: {vpn_capture.VARIABLE} is not set", report)
        self.assertFalse(any(call[:3] == ("docker", "exec", "fixture-vpn") for call in self.docker.calls))
        self.assertEqual(self.docker.calls[-1], ("docker", "rm", "--force", "fixture-sniff-01"))  # nothing left running

    def test_a_passing_run_must_have_checked_every_window_and_written_what_was_asked_for(self):
        capture = self.capture()
        window = capture.open("normal operation")
        with self.assertRaises(CaptureError) as unchecked:
            capture.finish()
        self.assertIn("never checked: 01-normal-operation", str(unchecked.exception))
        capture.check(window)
        capture.finish()
        self.assertEqual(json.loads((self.directory / "run.json").read_text())["outcome"], "passed")

        second = self.directory.parent / "second"
        capture = self.capture(directory=second)
        capture.store.write = self.unwritable
        capture.check(capture.open("normal operation"))
        with self.assertRaises(CaptureError) as unwritten:
            capture.finish()
        self.assertIn("diagnostic artifacts could not be written", str(unwritten.exception))

    def test_a_run_that_never_finished_is_not_recorded_as_a_pass(self):
        capture = self.capture()
        capture.open("normal operation")
        index = json.loads((self.directory / "run.json").read_text())
        self.assertEqual((index["outcome"], index["finished"], index["windows"][0]["capture"]), ("running", None, "recording"))
        self.assertIn("not a pass", index["note"])


class StoreTests(CaptureCase):
    def test_only_named_artifacts_are_written(self):
        store = vpn_capture.Store(self.directory.parent)
        self.assertEqual(store.write("01-window", "decoded.txt", "line\n")["bytes"], 5)
        self.assertEqual(store.write("", "run.json", "{}")["file"], "run.json")
        for folder, name in (("01-window", "wg0.conf"), ("01-window", ".env"), ("01-window", "post-rules.txt"),
                             ("failure-state", "capture.pcap"), ("failure-state", "inspect.json"), ("", "manifest.json"),
                             ("../outside", "decoded.txt"), ("01-window/nested", "decoded.txt"), ("01-window", "../run.json"),
                             ("/absolute", "decoded.txt"), ("", "decoded.txt")):
            with self.subTest(folder=folder, name=name), self.assertRaises(CaptureError):
                store.write(folder, name, "text")
        self.assertEqual(sorted(path.name for path in self.directory.parent.iterdir()), ["01-window", "run.json"])

    def test_key_material_is_never_written_or_printed(self):
        leaked = (frame(OWN, OTHER_LINK, body=KEY.encode()), f"00:04:11.000001 IP {VPN}.40002 > {OBSERVER}.80: tcp 0")
        capture = self.capture(Docker({1: [OUT_TUNNEL, leaked]}, state=f"-A OUTPUT -m comment --comment {KEY}"), secrets=[KEY])
        capture.open("route loss")
        capture.failed(RuntimeError(f"a message quoting {KEY}"))
        written = b"".join(path.read_bytes() for path in self.directory.rglob("*") if path.is_file())
        self.assertNotIn(KEY.encode(), written)
        self.assertNotIn(KEY, "\n".join(self.lines))
        self.assertFalse((self.directory / "01-route-loss/capture.pcap").exists())
        self.assertTrue(self.printed("WARN  diagnostic artifact not saved: 01-route-loss: CaptureError: refused to write"))
        self.assertEqual(json.loads((self.directory / "run.json").read_text())["failure"], "<withheld: it contained key material>")

    def test_the_destination_must_be_absolute_empty_and_outside_the_checkout(self):
        base = self.directory.parent
        self.assertIsNone(vpn_capture.destination(""))
        self.assertIsNone(vpn_capture.destination(None))
        created = vpn_capture.destination(str(base / "new/evidence"), outside=(ROOT,))
        self.assertTrue(created.is_dir() and created.is_absolute())
        self.assertEqual(vpn_capture.destination(str(created)), created)  # empty: usable again
        (created / "old.txt").write_text("from another run")
        (base / "file").write_text("x")
        (base / "link").symlink_to(base / "new")
        for value, outside in (("relative/evidence", ()), (str(created), ()), (str(base / "file"), ()), (str(base / "link"), ()),
                               (str(base / "inside/evidence"), (base / "inside",)), (str(base / "same"), (base / "same",))):
            with self.subTest(value=value), self.assertRaises(CaptureError):
                vpn_capture.destination(value, outside=outside)


class SuiteWiringTests(unittest.TestCase):
    """The real suite uses these helpers the way the regressions above assume."""

    def setUp(self):
        self.source = (ROOT / "tests/integration_vpn.py").read_text()

    def test_every_scenario_has_its_own_window(self):
        opened = re.findall(r'capture\.open\("([^"]+)"', self.source) + re.findall(r'then="([^"]+)"', self.source)
        self.assertEqual(sorted(opened), sorted([
            "normal operation", "secret handling and resume", "route loss", "route restoration",
            "interface removal and reconnect", "peer outage", "peer recovery", "after restart", "positive control"]))
        self.assertEqual(len(re.findall(r"capture\.check\(", self.source)), 8)
        self.assertEqual(len(re.findall(r"quiet=True", self.source)), 1)
        self.assertIn("capture.check(window, quiet=True)", self.source)
        self.assertIn('capture.open("positive control", expect=vpn_capture.DELIBERATE_LEAK)', self.source)
        self.assertIn('any(observer_ip in line for line in other)', self.source)
        for removed in ("def captured", "def capture_start", "def only_tunnel_traffic", "tunnel = re.compile"):
            self.assertNotIn(removed, self.source)

    def test_a_window_is_recording_before_each_fault_is_injected(self):
        order = ['capture.check(window, then="route loss")', '"ip", "route", "del", "default"',
                 'capture.check(window, then="route restoration")', '"ip", "route", "add", "default"',
                 'capture.check(window, then="interface removal and reconnect")', '"ip", "link", "del"',
                 'capture.check(window, then="peer outage")', '"docker", "stop", "--time", "1", project + "-peer"',
                 'capture.check(window, then="peer recovery")', '"docker", "start", project + "-peer"',
                 "capture.check(window)\n", '"docker", "restart", "--time", "2", session.vpn',
                 'capture.open("after restart")', 'capture.open("positive control"', '"iptables", "-I", "OUTPUT"',
                 "capture.close(control)"]
        positions = [self.source.index(marker) for marker in order]
        self.assertEqual(positions, sorted(positions))

    def test_failure_evidence_is_exported_before_anything_is_removed(self):
        handler = self.source.index("except BaseException as error:\n            # Before anything is removed")
        exported, cleaned = self.source.index("capture.failed(error)\n", handler), self.source.index("capture.cleanup()", handler)
        down = self.source.index('command(*vpn_compose, "down"', handler)
        self.assertLess(handler, exported)
        self.assertLess(exported, self.source.index("finally:", handler))
        self.assertLess(self.source.index("finally:", handler), cleaned)
        self.assertLess(cleaned, down)
        self.assertIn("capture.finish()", self.source[down:])
        self.assertIn("with capture.record(), tempfile.TemporaryDirectory(", self.source[:handler])

    def test_a_run_that_fails_outside_the_fixture_is_still_recorded_as_failed(self):
        case = CaptureCase("setUp")
        case.setUp()
        self.addCleanup(case.temporary.cleanup)
        capture = case.capture()
        with self.assertRaises(RuntimeError), capture.record():
            raise RuntimeError("an early requirement")
        index = json.loads((case.directory / "run.json").read_text())
        self.assertEqual((index["outcome"], index["failure"]), ("failed", "RuntimeError: an early requirement"))
        self.assertFalse(any(call[:2] == ("docker", "exec") for call in case.docker.calls))
        capture = case.capture(directory=case.directory.parent / "passing")
        with capture.record():
            capture.check(capture.open("normal operation"))
            capture.finish()
        self.assertEqual(json.loads((case.directory.parent / "passing/run.json").read_text())["outcome"], "passed")

    def test_the_destination_is_a_test_only_environment_variable(self):
        self.assertIn("vpn_capture.destination(os.environ.get(vpn_capture.VARIABLE), outside=(ROOT,))", self.source)
        self.assertEqual(vpn_capture.VARIABLE, "SAFEBROWSE_VPN_DIAGNOSTICS_DIR")
        for name in ("scripts/safebrowse.py", "scripts/vpn.py", "scripts/verify.py", "run.sh", "stop.sh", "verify.sh",
                     "docker-compose.vpn.yml", "compose.services.yml"):
            self.assertNotIn("DIAGNOSTICS", (ROOT / name).read_text(), name)


if __name__ == "__main__":
    unittest.main()
