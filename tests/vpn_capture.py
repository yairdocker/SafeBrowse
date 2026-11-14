"""Packet-capture windows for tests/integration_vpn.py. Test-side only: nothing here ships.

The VPN suite proves the kill switch by recording every non-ARP packet on the VPN
container's egress interface and accepting only WireGuard to or from the fixture
peer. This module keeps that rule exactly as it was and adds what a failure needs:

* one capture per scenario ("window"), so a rejected packet belongs to a scenario;
* the rejected tcpdump lines, each with its capture timestamp and a direction;
* the raw capture, the decoded and rejected summaries and a manifest, written to
  the directory named by SAFEBROWSE_VPN_DIAGNOSTICS_DIR when that is set.

A direction is diagnostic only. It is "measured" when the frame's link-layer source
is compared with the interface's own address, "inferred" when only the fixture's
IPv4 addresses are available, and otherwise "unknown". No direction, protocol or
address is consulted when a window is accepted or rejected: see split() and
acceptable(), which are the whole of that decision.

A capture that is missing, unreadable, truncated or cannot be decoded raises
CaptureError. So does one that tcpdump's own closing statistics do not show to
be whole: the statistics must be readable, report no packet dropped by the
kernel, and count as many captured packets as the file holds. It is never
treated as an empty capture.
"""
from collections import namedtuple
import contextlib
import datetime
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import tarfile
import time

VARIABLE = "SAFEBROWSE_VPN_DIAGNOSTICS_DIR"
WIREGUARD_PORT = 51820
CAPTURE_FILTER = ("not", "arp")
CAPTURE_FILE = "/tmp/egress.pcap"
READY_SECONDS, STOP_SECONDS, STATE_SECONDS = 20, 10, 15
CONSOLE_LIMIT, CONTROL_LIMIT, LINE_LIMIT = 40, 10, 300
TUNNEL_ONLY, DELIBERATE_LEAK = "tunnel traffic only", "deliberate leak: rejected traffic is required"

# The only files this module ever writes. Nothing is copied from the fixture directory.
INDEX = "run.json"
WINDOW_FILES = ("capture.pcap", "decoded.txt", "rejected.txt", "manifest.json")
STATE = "failure-state"
# Read-only listings taken inside the fixture's VPN container when the suite fails.
STATE_COMMANDS = (
    ("routes-ipv4.txt", ("ip", "-4", "route", "show", "table", "all")),
    ("routes-ipv6.txt", ("ip", "-6", "route", "show", "table", "all")),
    ("policy-rules-ipv4.txt", ("ip", "-4", "rule", "show")),
    ("policy-rules-ipv6.txt", ("ip", "-6", "rule", "show")),
    ("firewall-rules.txt", ("iptables", "-S")),
    ("firewall-counters.txt", ("iptables", "-L", "-v", "-n", "-x")),
    ("firewall-all-tables.txt", ("iptables-save", "-c")),
    ("firewall-ipv6.txt", ("ip6tables-save", "-c")),
)
STATE_FILES = tuple(name for name, _ in STATE_COMMANDS) + ("manifest.json",)

ETHERNET = 1
MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 10**6), b"\xa1\xb2\xc3\xd4": (">", 10**6),
         b"\x4d\x3c\xb2\xa1": ("<", 10**9), b"\xa1\xb2\x3c\x4d": (">", 10**9)}
ADDRESSES = re.compile(r"\bIP (?P<source>\d+\.\d+\.\d+\.\d+)(?:\.\d+)? > (?P<target>\d+\.\d+\.\d+\.\d+)(?:\.\d+)?:")
Frame = namedtuple("Frame", "seconds fraction unit link length")
Failed = namedtuple("Failed", "returncode stdout stderr")


class CaptureError(RuntimeError):
    """The capture itself cannot be trusted. Always a failure; never an empty pass."""


# ---------------------------------------------------------------------------------------- the verdict
def tunnel_pattern(vpn_ip, peer_ip):
    """The one accepted shape: WireGuard between the VPN container and the fixture peer, either way."""
    return re.compile(rf"IP ({re.escape(vpn_ip)}\.\d+ > {re.escape(peer_ip)}\.{WIREGUARD_PORT}|"
                      rf"{re.escape(peer_ip)}\.{WIREGUARD_PORT} > {re.escape(vpn_ip)}\.\d+): UDP")


def split(text, vpn_ip, peer_ip):
    """Every non-blank tcpdump line, and the positions of those that are not tunnel traffic."""
    tunnel = tunnel_pattern(vpn_ip, peer_ip)
    lines = [line for line in text.splitlines() if line.strip()]
    return lines, [index for index, line in enumerate(lines) if not tunnel.search(line)]


def acceptable(total, rejected, quiet=False):
    """A window passes when nothing was rejected and, unless it may be quiet, something was captured."""
    return (total > 0 or quiet) and not rejected


# ---------------------------------------------------------------------------------------- reading a capture
def single_file(archive):
    """The one regular file inside the tar stream that `docker cp CONTAINER:FILE -` writes."""
    try:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            members = tar.getmembers()
            if len(members) != 1 or not members[0].isfile():
                raise CaptureError("the copied capture is not a single regular file")
            return tar.extractfile(members[0]).read()
    except (tarfile.TarError, EOFError, OSError) as error:
        raise CaptureError(f"the copied capture could not be read ({type(error).__name__})") from None


def frames(data):
    """(link type, frames) of a classic pcap file. Raises CaptureError unless every record is complete."""
    if len(data) < 24:
        raise CaptureError(f"the capture file holds {len(data)} bytes: it is empty or shorter than a pcap header")
    if data[:4] not in MAGIC:
        raise CaptureError("the capture file is not a pcap file tcpdump wrote (unrecognised header)")
    order, unit = MAGIC[data[:4]]
    linktype = struct.unpack(order + "I", data[20:24])[0]
    offset, found = 24, []
    while offset < len(data):
        if len(data) - offset < 16:
            raise CaptureError(f"the capture file is truncated in the header of packet {len(found) + 1}")
        seconds, fraction, captured, original = struct.unpack(order + "IIII", data[offset:offset + 16])
        offset += 16
        if len(data) - offset < captured:
            raise CaptureError(f"the capture file is truncated inside packet {len(found) + 1}")
        found.append(Frame(seconds, fraction, unit, data[offset:offset + 14], original))
        offset += captured
    return linktype, found


# What tcpdump prints when it stops, under the names used in every manifest. tcpdump writes "1 packet" and
# "N packets"; both are read. The first and the last are required before a capture is called complete.
COUNTERS = ("packets captured", "packets received by filter", "packets dropped by kernel")
REQUIRED = ("packets captured", "packets dropped by kernel")


def statistics(output):
    """The counters tcpdump prints when it stops, each under its plural name.

    A counter is returned only when every mention of it is one whole number and all mentions agree. One that is
    absent, malformed or contradictory is left out: it is never reported as zero.
    """
    found = {}
    for label in COUNTERS:
        phrase = label.replace("packets", "packets?", 1)
        counts = [int(count) for count in re.findall(rf"(?<!\S)(\d+) {phrase}(?![^\s,])", output)]
        if counts and len(counts) == len(re.findall(phrase, output)) and len(set(counts)) == 1:
            found[label] = counts[0]
    return found


# ---------------------------------------------------------------------------------------- describing packets
def link_address(octets):
    return ":".join(f"{octet:02x}" for octet in octets)


def stamp(frame):
    moment = datetime.datetime.fromtimestamp(frame.seconds, datetime.timezone.utc)
    return f"{moment:%Y-%m-%dT%H:%M:%S}.{frame.fraction * 10**6 // frame.unit:06d}Z"


def iso(seconds):
    if seconds is None:
        return None
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).isoformat(timespec="milliseconds")


def direction(frame, linktype, own, line, vpn_ip):
    """(direction, basis) of one packet. Diagnostic only: the verdict never looks at it."""
    if frame is not None and linktype == ETHERNET and own and len(frame.link) >= 12:
        return ("outbound" if link_address(frame.link[6:12]) == own.lower() else "inbound"), "measured"
    found = ADDRESSES.search(line)
    if found and vpn_ip and found["source"] == vpn_ip:
        return "outbound", "inferred"
    if found and vpn_ip and found["target"] == vpn_ip:
        return "inbound", "inferred"
    return "unknown", ""


def describe(index, frame, linktype, own, line, vpn_ip):
    """One packet: its number, capture time, direction, link-layer addresses and tcpdump's own summary line."""
    where, basis = direction(frame, linktype, own, line, vpn_ip)
    link = "link layer not decoded"
    if linktype == ETHERNET and len(frame.link) >= 14:
        link = (f"{link_address(frame.link[6:12])} > {link_address(frame.link[0:6])} "
                f"ethertype 0x{struct.unpack('!H', frame.link[12:14])[0]:04x}")
    return f"[{index + 1}] {stamp(frame)} {where}{f'[{basis}]' if basis else ''} {link} | {line}"


LEGEND = ("direction: [measured] compares each frame's link-layer source with the interface's own address; [inferred] "
          "uses the fixture's IPv4 addresses because no link-layer measurement was available; otherwise unknown. "
          "It is recorded for diagnosis and never affects the verdict.")


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:48] or "window"


def shown(line):
    return line if len(line) <= LINE_LIMIT else f"{line[:LINE_LIMIT]}... [{len(line) - LINE_LIMIT} more characters]"


def console(window, interface, peer_ip, limit=CONSOLE_LIMIT):
    """What is printed for a window that rejected packets or could not be trusted. Bounded; never packet contents."""
    retained = (f"kept in {window.evidence}" if window.evidence else
                f"not kept: rerun with {VARIABLE} set to an empty absolute directory outside the checkout "
                "to keep each window's pcap, summaries and manifest")
    lines = [f"capture window {window.name} (scenario \"{window.scenario}\", expecting {window.expect}) on {interface}: "
             f"{len(window.lines)} packets decoded, {len(window.rejected)} rejected; capture {window.capture}, "
             f"decoding {window.decoding}, verdict {window.verdict}",
             f"fixture: VPN container {window.vpn_ip or 'unknown'} (link address {window.own or 'unknown'}), WireGuard "
             f"peer {peer_ip}, expected UDP port {WIREGUARD_PORT}; capture filter \"{' '.join(CAPTURE_FILTER)}\""]
    if window.problem:
        lines.append(f"problem: {window.problem}")
    if window.rejected:
        lines.append(LEGEND)
        rejected = [window.summaries[index] if window.summaries else window.lines[index] for index in window.rejected]
        lines += [f"rejected  {shown(line)}" for line in rejected[:limit]]
        if len(rejected) > limit:
            where = f"all {len(rejected)} are in {window.evidence}/rejected.txt" if window.evidence else \
                f"all {len(rejected)} would be in rejected.txt if evidence were kept"
            lines.append(f"{len(rejected) - limit} more rejected lines are not shown here; {where}")
    lines.append(f"evidence: {retained}")
    return [f"DIAG  {line}" for line in lines]


# ---------------------------------------------------------------------------------------- keeping evidence
def destination(value, outside=()):
    """The directory evidence is kept in, or None. It must be absolute, empty, and outside the given directories."""
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        raise CaptureError(f"{VARIABLE} must be an absolute path")
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise CaptureError(f"{VARIABLE} must name a directory, not a link or a file")
    if path.is_dir() and any(path.iterdir()):
        raise CaptureError(f"{VARIABLE} names a directory that is not empty: evidence from another run would be "
                           "mixed with this one")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = path.resolve()
    for other in outside:
        other = Path(other).resolve()
        if path == other or other in path.parents:
            raise CaptureError(f"{VARIABLE} must be outside {other}")
    return path


class Store:
    """Writes named artifacts under one directory. A name that is not on the list is refused."""

    def __init__(self, root, secrets=()):
        self.root, self.secrets = Path(root), secrets

    def write(self, folder, name, data):
        allowed = (INDEX,) if not folder else STATE_FILES if folder == STATE else WINDOW_FILES
        if name not in allowed or (folder and not re.fullmatch(r"[a-z0-9][a-z0-9-]*", folder)):
            raise CaptureError(f"refused to write {folder}/{name}: it is not a diagnostic artifact")
        data = data.encode("utf-8") if isinstance(data, str) else data
        if any(secret and secret.encode("utf-8") in data for secret in self.secrets):
            raise CaptureError(f"refused to write {folder}/{name}: it contains key material")
        target = self.root / folder / name
        target.parent.mkdir(mode=0o700, exist_ok=True)
        target.write_bytes(data)
        return {"file": f"{folder}/{name}" if folder else name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class Window:
    def __init__(self, sequence, scenario, project, expect):
        self.sequence, self.scenario, self.expect = sequence, scenario, expect
        self.name = f"{sequence:02d}-{slug(scenario)}"
        self.container = f"{project}-sniff-{sequence:02d}"
        self.requested = self.recording = self.stopped = None
        self.own = self.vpn_ip = self.pcap = self.linktype = self.problem = self.evidence = None
        self.frames, self.lines, self.rejected, self.summaries, self.files = [], [], [], [], []
        self.statistics, self.quiet = {}, False
        self.capture, self.decoding, self.verdict = "not started", "not attempted", "not checked"

    def rejected_lines(self):
        return [self.lines[index] for index in self.rejected]

    def as_expected(self):
        """Whether the window showed what its scenario requires. None until it has a verdict."""
        if self.verdict not in ("accepted", "rejected"):
            return None
        return bool(self.rejected) if self.expect == DELIBERATE_LEAK else self.verdict == "accepted"


class Capture:
    """Named capture windows on one interface of one container's network namespace.

    `run(*args, input=None, timeout=60)` runs a command and returns its returncode with stdout and stderr as
    bytes. `vpn_address()` returns the namespace's address on the captured network. Everything else is a name.
    """

    def __init__(self, run, project, namespace, image, interface, peer_ip, vpn_address, directory=None, secrets=(),
                 emit=None, clock=time.time, sleep=time.sleep, console_limit=CONSOLE_LIMIT):
        self.run, self.project, self.namespace, self.image = run, project, namespace, image
        self.interface, self.peer_ip, self.vpn_address = interface, peer_ip, vpn_address
        self.secrets = list(secrets)
        self.store = Store(directory, self.secrets) if directory else None
        self.emit = emit or (lambda line: print(line, flush=True))
        self.clock, self.sleep, self.console_limit = clock, sleep, console_limit
        self.windows, self.active, self.export_errors = [], [], []
        self.sequence, self.started, self.finished = 0, clock(), None
        self.outcome, self.failure, self.state = "running", None, "not collected: the suite has not failed"
        self.emit(f"INFO  capture evidence is kept in {self.store.root}" if self.store else
                  f"INFO  capture evidence is not kept: set {VARIABLE} to an empty absolute directory to keep each "
                  "window's pcap, summaries and manifest")
        self._index()

    # ------------------------------------------------------------------ the suite's three verbs
    def open(self, scenario, expect=TUNNEL_ONLY):
        """Start recording a new window and return it once tcpdump has the interface open."""
        self.sequence += 1
        window = Window(self.sequence, scenario, self.project, expect)
        self.windows.append(window)
        self.active.append(window)
        try:
            window.requested = self.clock()
            self._run("docker", "rm", "--force", window.container)
            started = self._run(
                "docker", "run", "--detach", "--name", window.container, "--network", "container:" + self.namespace,
                "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN", "--user", "0",
                "--entrypoint", "tcpdump", self.image, "-Z", "root", "-i", self.interface, "-nn", "-U",
                "-w", CAPTURE_FILE, *CAPTURE_FILTER)
            if started.returncode:
                raise CaptureError(f"capture window {window.name}: the capture container did not start "
                                   f"(exit {started.returncode})")
            deadline = self.clock() + READY_SECONDS
            # tcpdump writes the file header only after it has opened the interface and set its filter.
            while self._run("docker", "exec", window.container, "test", "-s", CAPTURE_FILE).returncode:
                if self.clock() >= deadline:
                    raise CaptureError(f"capture window {window.name}: tcpdump was not recording on {self.interface} "
                                       f"within {READY_SECONDS} seconds")
                self.sleep(0.25)
            window.own = self._own_address(window.container)
            window.vpn_ip = self.vpn_address()
            window.recording = self.clock()
            window.capture = "recording"
        except BaseException as error:
            window.problem = window.problem or self._clean(f"{type(error).__name__}: {error}")
            raise
        finally:
            self._index()
        self.emit(f"PASS  capture window {window.name} is recording on {self.interface}")
        return window

    def close(self, window, quiet=False):
        """Stop a window, keep its evidence, remove its container and return it decoded.

        Raises CaptureError when the capture is missing, incomplete, not shown to be complete or cannot be decoded.
        """
        window.quiet = quiet
        try:
            self._collect(window)
            window.verdict = "accepted" if acceptable(len(window.lines), window.rejected, quiet) else "rejected"
        except CaptureError as error:
            window.problem = str(error)
            window.verdict = "no verdict: the capture cannot be trusted"
            raise
        finally:
            self._settle(window)
        return window

    def check(self, window, quiet=False, then=None):
        """The suite's assertion: every packet in the window was WireGuard to or from the peer.

        `then` names the next window. It is opened, and recording, before this one is stopped, so no packet
        falls between two windows.
        """
        following = self.open(then) if then else None
        self.close(window, quiet)
        total = len(window.lines)
        message = f"{window.scenario}: all {total} packets on the egress interface were WireGuard to or from the peer"
        if not acceptable(total, window.rejected, quiet):
            raise RuntimeError(message)
        self.emit(f"PASS  {message}")
        return following

    # ------------------------------------------------------------------ the end of a run
    @contextlib.contextmanager
    def record(self):
        """Around the whole suite: a run that leaves by an exception is recorded as failed, whatever it reached."""
        try:
            yield self
        except BaseException as error:
            if self.outcome == "running":
                self.failed(error, state=False)  # nothing of the fixture is left to list
            raise

    def failed(self, error, state=True):
        """The suite is failing. Keep what is still being captured and the state that explains it. Never raises."""
        try:
            self.outcome, self.failure = "failed", self._clean(f"{type(error).__name__}: {error}")
            for window in list(self.active):
                try:
                    self._collect(window)
                except CaptureError as problem:
                    window.problem = str(problem)
                window.verdict = "not checked: the suite failed while this window was open"
                self._settle(window, announce=True)
            if state:
                self._state()
            self.finished = self.clock()
            self._index()
            if self.export_errors:
                self.emit(f"WARN  {len(self.export_errors)} diagnostic artifacts could not be saved; the failure "
                          "above is the suite's own and is unchanged")
        except Exception as problem:  # diagnostics must not replace the failure being reported
            self.emit(f"WARN  diagnostics could not be completed: {self._clean(f'{type(problem).__name__}: {problem}')}")

    def finish(self):
        """The suite passed. Every window must have been checked, and requested evidence must have been written."""
        if self.active:
            raise CaptureError("capture windows were opened and never checked: " + ", ".join(w.name for w in self.active))
        self.outcome, self.finished = "passed", self.clock()
        self._index()
        if self.export_errors:
            self.outcome = "failed"
            self.failure = "diagnostic evidence was requested and could not be written"
            self._index()
            raise CaptureError(f"{VARIABLE} was set, but {len(self.export_errors)} diagnostic artifacts could not be "
                               f"written: {'; '.join(self.export_errors[:3])}")

    def cleanup(self):
        """Remove every capture container this run started. Never raises."""
        for window in self.windows:
            self._run("docker", "rm", "--force", window.container)

    # ------------------------------------------------------------------ internals
    def _run(self, *args, **options):
        try:
            return self.run(*args, **options)
        except Exception as error:  # a timeout or a missing docker is a failed command, not a crash
            return Failed(-1, b"", f"{type(error).__name__}".encode())

    def _clean(self, text):
        return "<withheld: it contained key material>" if any(s and s in text for s in self.secrets) else text

    def _own_address(self, container):
        listed = self._run("docker", "exec", container, "ip", "-o", "link", "show", "dev", self.interface)
        found = re.search(r"link/ether ([0-9a-fA-F:]{17})", listed.stdout.decode("utf-8", "replace"))
        return found[1].lower() if listed.returncode == 0 and found else None

    def _collect(self, window):
        """Stop tcpdump, copy the capture out, check it is whole and decode it. Fills in the window."""
        name = window.name
        if window.capture != "recording":
            raise CaptureError(f"capture window {name} never started recording")
        self.sleep(1)  # as before: the kernel hands captured packets to tcpdump in blocks, up to a second late
        stopped = self._run("docker", "stop", "--time", str(STOP_SECONDS), window.container, timeout=STOP_SECONDS + 30)
        window.stopped = self.clock()
        state = self._run("docker", "inspect", "--format", "{{.State.ExitCode}}", window.container)
        code = state.stdout.decode("utf-8", "replace").strip() if state.returncode == 0 else "unknown"
        logs = self._run("docker", "logs", window.container)
        # Statistics from a command that failed are not evidence, however plausible they look.
        window.statistics = {} if logs.returncode else statistics((logs.stdout + logs.stderr).decode("utf-8", "replace"))
        copied = self._run("docker", "cp", f"{window.container}:{CAPTURE_FILE}", "-")
        if copied.returncode:
            window.capture = "missing"
            raise CaptureError(f"capture window {name}: the capture file could not be copied out of its container "
                               f"(exit {copied.returncode})")
        try:
            window.pcap = single_file(copied.stdout)
            window.linktype, window.frames = frames(window.pcap)
        except CaptureError as error:
            window.capture = "unreadable"
            raise CaptureError(f"capture window {name}: {error}") from None
        if stopped.returncode or code != "0":
            window.capture = "interrupted"
            raise CaptureError(f"capture window {name}: tcpdump did not stop cleanly (docker stop exit "
                               f"{stopped.returncode}, tcpdump exit {code}), so the capture may be incomplete")
        # The file is kept in the window from here on, whatever follows. It is called complete only when tcpdump's
        # own closing statistics say so: readable, nothing dropped, and as many packets captured as the file holds.
        if logs.returncode:
            window.capture = "unverified"
            raise CaptureError(f"capture window {name}: tcpdump's closing statistics could not be read (docker logs "
                               f"exit {logs.returncode}), so the capture cannot be shown to be complete")
        unread = [label for label in REQUIRED if label not in window.statistics]
        if unread:
            window.capture = "unverified"
            raise CaptureError(f"capture window {name}: tcpdump's closing statistics do not give a readable count of "
                               f"{' or '.join(unread)}, so the capture cannot be shown to be complete")
        dropped, reported = window.statistics["packets dropped by kernel"], window.statistics["packets captured"]
        if dropped:
            window.capture = "incomplete"
            raise CaptureError(f"capture window {name}: the kernel dropped {dropped} "
                               f"packet{'' if dropped == 1 else 's'} before tcpdump saw them")
        if reported != len(window.frames):
            window.capture = "incomplete" if reported > len(window.frames) else "unverified"
            raise CaptureError(f"capture window {name}: tcpdump reported {reported} "
                               f"packet{'' if reported == 1 else 's'} captured, but the capture file holds "
                               f"{len(window.frames)} complete record{'' if len(window.frames) == 1 else 's'}")
        window.capture = "complete"
        decoded = self._run("docker", "run", "--rm", "-i", "--network", "none", "--cap-drop", "ALL", "--user", "0",
                            "--entrypoint", "tcpdump", self.image, "-Z", "root", "-nn", "-q", "-r", "-",
                            input=window.pcap)
        if decoded.returncode:
            window.decoding = f"failed (tcpdump exit {decoded.returncode})"
            raise CaptureError(f"capture window {name}: tcpdump could not decode the capture (exit {decoded.returncode})")
        try:
            text = decoded.stdout.decode("utf-8")
        except UnicodeDecodeError:
            window.decoding = "failed (output is not text)"
            raise CaptureError(f"capture window {name}: tcpdump's decoded output is not text") from None
        window.lines, window.rejected = split(text, window.vpn_ip, self.peer_ip)
        if len(window.lines) != len(window.frames):
            window.decoding = f"failed ({len(window.lines)} lines for {len(window.frames)} packets)"
            raise CaptureError(f"capture window {name}: tcpdump decoded {len(window.lines)} lines for "
                               f"{len(window.frames)} captured packets")
        window.summaries = [describe(index, frame, window.linktype, window.own, line, window.vpn_ip)
                            for index, (frame, line) in enumerate(zip(window.frames, window.lines))]
        window.decoding = "complete"

    def _settle(self, window, announce=False):
        """Keep the window's evidence, then remove its container, then say what was found. Never raises."""
        try:
            self._export(window)
            self._run("docker", "rm", "--force", window.container)
            if window in self.active:
                self.active.remove(window)
            self._index()
            if announce or window.problem or window.rejected or window.verdict == "rejected":
                limit = min(self.console_limit, CONTROL_LIMIT) if window.expect == DELIBERATE_LEAK else self.console_limit
                for line in console(window, self.interface, self.peer_ip, limit):
                    self.emit(line)
        except Exception as problem:
            self.emit(f"WARN  diagnostics for capture window {window.name} could not be completed: "
                      f"{self._clean(f'{type(problem).__name__}: {problem}')}")

    def _manifest(self, window):
        directions = {}
        for index in window.rejected if window.summaries else ():
            where, basis = direction(window.frames[index], window.linktype, window.own, window.lines[index], window.vpn_ip)
            key = f"{where} ({basis})" if basis else where
            directions[key] = directions.get(key, 0) + 1
        return {
            "window": window.name, "scenario": window.scenario, "sequence": window.sequence,
            "expectation": window.expect, "interface": self.interface, "capture_filter": " ".join(CAPTURE_FILTER),
            "times": {"requested": iso(window.requested), "recording": iso(window.recording),
                      "stopped": iso(window.stopped),
                      "first_packet": stamp(window.frames[0]) if window.frames else None,
                      "last_packet": stamp(window.frames[-1]) if window.frames else None},
            "fixture": {"vpn_address": window.vpn_ip, "vpn_link_address": window.own, "peer_address": self.peer_ip,
                        "wireguard_port": WIREGUARD_PORT},
            "counts": {"captured_packets": len(window.frames) if window.pcap is not None else None,
                       "decoded_lines": len(window.lines) if window.decoding != "not attempted" else None,
                       "rejected": len(window.rejected) if window.decoding != "not attempted" else None,
                       "rejected_by_direction": directions},
            "tcpdump_statistics": window.statistics,
            "status": {"capture": window.capture, "decoding": window.decoding, "verdict": window.verdict,
                       "as_expected": window.as_expected(), "empty_window_allowed": window.quiet,
                       "problem": window.problem},
            "direction_legend": LEGEND,
        }

    def _export(self, window):
        if not self.store:
            return
        try:
            files = []
            if window.pcap is not None:
                files.append(self.store.write(window.name, "capture.pcap", window.pcap))
            heading = (f"# capture window {window.name}: capture {window.capture}, decoding {window.decoding}\n"
                       f"# packet number, capture time (UTC), direction, link-layer addresses | tcpdump -nn -q line\n"
                       f"# {LEGEND}\n")
            body = window.summaries or window.lines  # without annotations when the packets could not be matched up
            files.append(self.store.write(window.name, "decoded.txt", heading + "".join(f"{line}\n" for line in body)))
            files.append(self.store.write(window.name, "rejected.txt", heading + "".join(
                f"{body[index]}\n" for index in window.rejected)))
            window.files = files
            self.store.write(window.name, "manifest.json", json.dumps(dict(self._manifest(window), files=files), indent=2) + "\n")
            window.evidence = str(self.store.root / window.name)
        except (OSError, CaptureError, ValueError) as error:
            self._export_error(f"{window.name}: {type(error).__name__}: {error}")

    def _export_error(self, text):
        text = self._clean(text)
        if text not in self.export_errors:
            self.export_errors.append(text)
            self.emit(f"WARN  diagnostic artifact not saved: {text}")

    def _state(self):
        """Read-only listings of the fixture's routes, policy rules and firewall, kept beside the captures."""
        if not self.store:
            self.state = f"not collected: {VARIABLE} is not set"
            self.emit(f"DIAG  fixture routes and firewall state at the failure were not collected: {VARIABLE} is not set")
            return
        records = []
        for name, argv in STATE_COMMANDS:
            result = self._run("docker", "exec", self.namespace, *argv, timeout=STATE_SECONDS)
            record = {"file": f"{STATE}/{name}", "command": " ".join(argv), "exit": result.returncode, "saved": False}
            if result.returncode == 0:
                try:
                    record.update(self.store.write(STATE, name, result.stdout), saved=True)
                except (OSError, CaptureError) as error:
                    self._export_error(f"{STATE}/{name}: {type(error).__name__}: {error}")
            records.append(record)
        saved = sum(record["saved"] for record in records)
        self.state = f"{saved} of {len(records)} listings saved"
        try:
            self.store.write(STATE, "manifest.json", json.dumps({
                "collected": iso(self.clock()), "container": "the fixture's VPN container", "read_only": True,
                "listings": records}, indent=2) + "\n")
        except (OSError, CaptureError) as error:
            self._export_error(f"{STATE}/manifest.json: {type(error).__name__}: {error}")
        self.emit(f"DIAG  fixture routes, policy rules and firewall at the failure: {self.state} in "
                  f"{self.store.root / STATE}")

    def _index(self):
        if not self.store:
            return
        try:
            self.store.write("", INDEX, json.dumps({
                "suite": "tests/integration_vpn.py", "fixture": self.project, "interface": self.interface,
                "started": iso(self.started), "finished": iso(self.finished), "outcome": self.outcome,
                "failure": self.failure,
                "note": "outcome 'running' in a finished job means the suite was interrupted; it is not a pass",
                "windows": [{"window": w.name, "scenario": w.scenario, "expectation": w.expect, "capture": w.capture,
                             "decoding": w.decoding, "verdict": w.verdict, "as_expected": w.as_expected(),
                             "packets": len(w.frames), "rejected": len(w.rejected)} for w in self.windows],
                "failure_state": self.state, "export_errors": self.export_errors}, indent=2) + "\n")
        except (OSError, CaptureError) as error:
            self._export_error(f"{INDEX}: {type(error).__name__}: {error}")
