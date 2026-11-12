#!/usr/bin/env python3
"""WireGuard configuration for SafeBrowse's VPN mode: parse, reduce, store, discard.

An imported file is data. It is read once, checked field by field, and never
executed, mounted or copied: what the VPN container receives is a new file
holding only the values below. Nothing in this module starts a process or
prints a key.
"""
import base64
import binascii
import contextlib
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import re
import stat
from typing import NamedTuple

SIZE_LIMIT = 65536
SESSION = re.compile(r"[0-9a-f]{16}")
FINGERPRINT = re.compile(r"[0-9a-f]{64}")
CONFIG, RULES = "wg0.conf", "post-rules.txt"
# Every name this module creates inside a session directory. Nothing else is ever deleted.
GENERATED = (CONFIG, RULES, "." + CONFIG + ".new", "." + RULES + ".new")
# The names docker-compose.vpn.yml gives the VPN container's two interfaces, and Gluetun's tunnel.
SANDBOX_INTERFACE, EGRESS_INTERFACE, TUNNEL_INTERFACE = "sbx0", "egr0", "tun0"
PROXY_PORT = 3128
DOCKER_RESOLVER = "127.0.0.11"
DEFAULT_MTU, MTU_RANGE, KEEPALIVE_RANGE = 1320, (1280, 1420), (0, 65535)
HOOKS = {"preup", "postup", "predown", "postdown"}
FIELDS = {"interface": {"privatekey", "address", "dns", "mtu"},
          "peer": {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"}}
ENDPOINT = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3}):([0-9]{1,5})")


class ConfigError(ValueError):
    """Why a configuration was refused. The message never contains a key or the file's text."""


class StorageError(Exception):
    """The place generated VPN secrets are kept is unsafe, unreadable or malformed.

    This is never the same as "nothing is stored": callers must stop, not carry on
    as if there were no VPN session. The message names a path and what to do, and
    never contains a key or file contents.
    """


class Tunnel(NamedTuple):
    private_key: str
    address: str          # one IPv4 host address, without a prefix
    public_key: str
    preshared_key: str    # "" when the peer has none
    endpoint: str         # literal IPv4 address
    port: int
    mtu: int
    keepalive: int        # seconds; 0 is off
    notices: tuple = ()   # what was recognised and deliberately left out


def key(value, name):
    """A WireGuard key: the canonical base64 encoding of exactly 32 bytes."""
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raw = b""
    if len(value) != 44 or len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
        raise ConfigError(f"{name} is not the base64 encoding of a 32-byte WireGuard key.")
    return value


def number(value, name, low, high):
    if not re.fullmatch(r"[0-9]{1,5}", value) or not low <= int(value) <= high:
        raise ConfigError(f"{name} must be a whole number from {low} to {high}.")
    return int(value)


def items(value, name):
    """A comma-separated list with no empty entries."""
    entries = [entry.strip() for entry in value.split(",")]
    if not all(entries):
        raise ConfigError(f"{name} has an empty entry.")
    return entries


def sections(text):
    """{'interface': {key: value}, 'peer': {...}} with every structural rule applied."""
    if text.startswith("﻿"):
        text = text[1:]
    found, current = {}, None
    for number_, line in enumerate(text.split("\n"), 1):
        if line.endswith("\r"):
            line = line[:-1]
        if any(ord(character) < 32 and character != "\t" or ord(character) == 127 for character in line):
            raise ConfigError(f"line {number_} contains a control character.")
        line = line.strip()
        if re.match(r"[#!@]?\s*include\b", line, re.IGNORECASE):
            raise ConfigError(f"line {number_} is an include; a configuration must be a single self-contained file.")
        if not line or line.startswith("#"):
            continue
        header = re.fullmatch(r"\[([A-Za-z]+)\]", line)
        if header:
            current = header[1].lower()
            if current not in FIELDS:
                raise ConfigError(f"line {number_} starts an unsupported section; only [Interface] and [Peer] are read.")
            if current in found:
                raise ConfigError(f"there is more than one [{current.capitalize()}] section; SafeBrowse uses exactly one "
                                  "interface and one peer.")
            found[current] = {}
            continue
        name, separator, value = line.partition("=")
        name, value = name.strip().lower(), value.strip()
        if not separator or not re.fullmatch(r"[a-z]+", name):
            raise ConfigError(f"line {number_} is not a 'Name = value' setting.")
        if current is None:
            raise ConfigError(f"line {number_} is a setting outside any section.")
        if name in HOOKS:
            raise ConfigError(f"line {number_} is a {name} command hook. SafeBrowse never runs commands from a "
                              "configuration; export the file again without a kill switch or other hooks "
                              "(SafeBrowse's own firewall does that job).")
        if name not in FIELDS[current]:
            raise ConfigError(f"line {number_} sets '{name}', which SafeBrowse does not support in "
                              f"[{current.capitalize()}].")
        if name in found[current]:
            raise ConfigError(f"'{name}' appears more than once in [{current.capitalize()}].")
        if not value:
            raise ConfigError(f"'{name}' has no value.")
        found[current][name] = value
    for required in FIELDS:
        if required not in found:
            raise ConfigError(f"there is no [{required.capitalize()}] section.")
    return found


def parse(text, allow_private_endpoint=False):
    """Check an imported or generated configuration and return its Tunnel.

    `allow_private_endpoint` exists for the test fixtures, whose WireGuard peer is
    another container. Only Python callers can set it; the command line never does.
    """
    if len(text) > SIZE_LIMIT:
        raise ConfigError("the file is too large to be a WireGuard configuration.")
    found = sections(text)
    interface, peer = found["interface"], found["peer"]
    for section, names in (("interface", ("privatekey", "address")), ("peer", ("publickey", "allowedips", "endpoint"))):
        for name in names:
            if name not in found[section]:
                raise ConfigError(f"[{section.capitalize()}] has no '{name}'.")
    notices = []

    addresses = []
    for entry in items(interface["address"], "Address"):
        try:
            address = ipaddress.ip_interface(entry)
        except ValueError:
            raise ConfigError("Address has an entry that is not an IP address.") from None
        if address.version == 6:
            notices.append("the IPv6 interface address was left out: this release tunnels IPv4 only")
        elif address.network.prefixlen != 32:
            raise ConfigError("the IPv4 Address must be a single host address (/32).")
        else:
            addresses.append(str(address.ip))
    if len(addresses) != 1:
        raise ConfigError("Address must contain exactly one IPv4 address.")

    full = False
    for entry in items(peer["allowedips"], "AllowedIPs"):
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            raise ConfigError("AllowedIPs has an entry that is not an IP network.") from None
        if network.prefixlen != 0:
            raise ConfigError("AllowedIPs must route everything (0.0.0.0/0); split or partial routes are not supported, "
                              "because traffic outside them would have nowhere safe to go.")
        if network.version == 6:
            notices.append("the IPv6 route (::/0) was left out: this release tunnels IPv4 only and blocks IPv6")
        else:
            full = True
    if not full:
        raise ConfigError("AllowedIPs must include 0.0.0.0/0 so that all IPv4 traffic uses the tunnel.")

    match = ENDPOINT.fullmatch(peer["endpoint"])
    try:
        endpoint = ipaddress.IPv4Address(match[1]) if match else None
    except ValueError:
        endpoint = None
    if endpoint is None:
        raise ConfigError("Endpoint must be a literal IPv4 address and port, such as 203.0.113.7:51820. Host names and "
                          "IPv6 endpoints are not supported: SafeBrowse connects to exactly the server in the file and "
                          "never resolves or selects one.")
    port = number(match[2], "the Endpoint port", 1, 65535)
    if endpoint.is_multicast or endpoint.is_reserved or endpoint.is_unspecified:
        raise ConfigError("Endpoint is not a public internet address.")
    if not endpoint.is_global and not allow_private_endpoint:
        raise ConfigError("Endpoint is not a public internet address.")

    if "dns" in interface:
        notices.append("the DNS setting was not used: SafeBrowse's gateway keeps its own filtering resolvers, "
                       "and their queries travel through the tunnel")
    return Tunnel(
        private_key=key(interface["privatekey"], "PrivateKey"), address=addresses[0],
        public_key=key(peer["publickey"], "PublicKey"),
        preshared_key=key(peer["presharedkey"], "PresharedKey") if "presharedkey" in peer else "",
        endpoint=str(endpoint), port=port,
        mtu=number(interface["mtu"], "MTU", *MTU_RANGE) if "mtu" in interface else DEFAULT_MTU,
        keepalive=number(peer["persistentkeepalive"], "PersistentKeepalive", *KEEPALIVE_RANGE)
        if "persistentkeepalive" in peer else 0,
        notices=tuple(dict.fromkeys(notices)))


def render(tunnel):
    """The only configuration the VPN container sees. parse(render(t)) gives t back, without notices."""
    lines = ["[Interface]", f"PrivateKey = {tunnel.private_key}", f"Address = {tunnel.address}/32", f"MTU = {tunnel.mtu}",
             "", "[Peer]", f"PublicKey = {tunnel.public_key}"]
    if tunnel.preshared_key:
        lines.append(f"PresharedKey = {tunnel.preshared_key}")
    lines += ["AllowedIPs = 0.0.0.0/0", f"Endpoint = {tunnel.endpoint}:{tunnel.port}"]
    if tunnel.keepalive:
        lines.append(f"PersistentKeepalive = {tunnel.keepalive}")
    return "\n".join(lines) + "\n"


def chain_rules(subnet, endpoint, port):
    """The two SafeBrowse chains, as `iptables -S` prints them."""
    subnet, port = str(ipaddress.IPv4Network(subnet)), int(port)
    endpoint = str(ipaddress.IPv4Address(endpoint))
    return {
        "SAFEBROWSE_INPUT": (
            "-A SAFEBROWSE_INPUT -i lo -j RETURN",
            f"-A SAFEBROWSE_INPUT -i {TUNNEL_INTERFACE} -j RETURN",
            f"-A SAFEBROWSE_INPUT -s {subnet} -i {SANDBOX_INTERFACE} -p tcp -m tcp --dport {PROXY_PORT} -j ACCEPT",
            f"-A SAFEBROWSE_INPUT -s {endpoint}/32 -i {EGRESS_INTERFACE} -p udp -m udp --sport {port} "
            "-m conntrack --ctstate ESTABLISHED -j ACCEPT",
            "-A SAFEBROWSE_INPUT -j DROP"),
        "SAFEBROWSE_OUTPUT": (
            f"-A SAFEBROWSE_OUTPUT -d {DOCKER_RESOLVER}/32 -j DROP",
            "-A SAFEBROWSE_OUTPUT -o lo -j RETURN",
            f"-A SAFEBROWSE_OUTPUT -o {TUNNEL_INTERFACE} -j RETURN",
            f"-A SAFEBROWSE_OUTPUT -d {subnet} -o {SANDBOX_INTERFACE} -p tcp -m tcp --sport {PROXY_PORT} "
            "-m conntrack --ctstate ESTABLISHED -j ACCEPT",
            f"-A SAFEBROWSE_OUTPUT -d {endpoint}/32 -o {EGRESS_INTERFACE} -p udp -m udp --dport {port} -j ACCEPT",
            "-A SAFEBROWSE_OUTPUT -j DROP"),
    }


def firewall_rules(subnet, tunnel):
    """Gluetun's post-rules file: both chains, then a jump to each ahead of every rule Gluetun adds.

    Anything that is not loopback or the tunnel must match an ACCEPT here or it is
    dropped, so Gluetun's own allowances for whole local networks never apply.
    """
    lines = []
    for chain, rules in chain_rules(subnet, tunnel.endpoint, tunnel.port).items():
        lines.append(f"iptables -N {chain}")
        lines += ["iptables " + rule for rule in rules]
        lines.append(f"iptables -I {chain.removeprefix('SAFEBROWSE_')} 1 -j {chain}")
    lines.append("iptables -I FORWARD 1 -j DROP")
    return "\n".join(lines) + "\n"


def fingerprint(tunnel):
    """SHA-256 of the exact generated configuration. It identifies the file; it does not reveal a key."""
    return hashlib.sha256(render(tunnel).encode("ascii")).hexdigest()


def environment(tunnel, directory):
    """Compose inputs for docker-compose.vpn.yml. None of them is secret."""
    return {"SAFEBROWSE_VPN_DIR": str(directory), "SAFEBROWSE_VPN_MTU": str(tunnel.mtu),
            "SAFEBROWSE_VPN_KEEPALIVE": f"{tunnel.keepalive}s" if tunnel.keepalive else "0",
            "SAFEBROWSE_VPN_FINGERPRINT": fingerprint(tunnel)}


# ---------------------------------------------------------------------------
# Files. Sources are only read; generated files live in <root>/.runtime/vpn/<session>/.
# ---------------------------------------------------------------------------
def read_source(path):
    """(text, notices) from a regular file. Links, devices and pipes are refused; the file is not changed."""
    path = Path(path)
    try:
        if stat.S_ISLNK(os.lstat(path).st_mode):
            raise ConfigError("the configuration path is a symbolic link; give the path of the file itself.")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        raise ConfigError("the configuration file could not be opened as a regular file.") from None
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise ConfigError("the configuration path is not a regular file.")
        if status.st_size > SIZE_LIMIT:
            raise ConfigError("the file is too large to be a WireGuard configuration.")
        data = b""
        while len(data) <= SIZE_LIMIT:
            piece = os.read(descriptor, SIZE_LIMIT + 1 - len(data))
            if not piece:
                break
            data += piece
    except OSError:
        raise ConfigError("the configuration file could not be read.") from None
    finally:
        os.close(descriptor)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError("the configuration file is not text.") from None
    notices = ()
    if status.st_mode & 0o077:
        notices = ("your WireGuard file is readable by other users of this computer; SafeBrowse did not change it "
                   "(chmod 600 would restrict it)",)
    return text, notices


# ---------------------------------------------------------------------------
# Generated files live in <root>/.runtime/vpn/<session>/. The checkout root is the
# trusted starting point; every directory below it is checked before anything is
# read, written or deleted through it, and (where the platform can) stays open so
# that each later step is relative to the directory that was checked rather than
# to a path that could be swapped in between.
# ---------------------------------------------------------------------------
ANCHORED = ({os.open, os.stat, os.mkdir, os.unlink, os.rmdir, os.rename} <= os.supports_dir_fd
            and os.listdir in os.supports_fd and os.stat in os.supports_follow_symlinks
            and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"))
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
OWNER = getattr(os, "geteuid", None)  # absent where ownership and mode bits mean something else


def unsafe(label, problem):
    return StorageError(f"{label} {problem}. SafeBrowse keeps generated VPN secrets under .runtime/vpn and will not "
                        "read, write or delete anything through that path. Check what it is; it must be an ordinary "
                        "directory or file that belongs to you and that no other user can change. Move it away or "
                        "correct it by hand, then retry.")


def acceptable(label, status, private):
    """Refuse an object owned by someone else, or one other users could change (or, if private, read)."""
    if OWNER is None:
        return
    if status.st_uid != OWNER():
        raise unsafe(label, "belongs to another user")
    if stat.S_IMODE(status.st_mode) & (0o077 if private else 0o022):
        raise unsafe(label, "can be read or changed by other users" if private else "can be changed by other users")


class Directory:
    """One directory that passed its checks. Every operation names an entry directly inside it."""

    def __init__(self, handle, path, label):
        self.handle, self.path, self.label = handle, str(path), label

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        if self.handle is not None:
            os.close(self.handle)
            self.handle = None

    def call(self, function, name, *arguments, **options):
        if os.sep in name or (os.altsep and os.altsep in name) or name in ("", ".", ".."):
            raise StorageError("internal error: a storage entry name is not a single path component.")
        if self.handle is None:
            return function(os.path.join(self.path, name), *arguments, **options)
        return function(name, *arguments, dir_fd=self.handle, **options)

    def lstat(self, name):
        return self.call(os.stat, name, follow_symlinks=False)

    def open(self, name, flags, mode=0o600):
        return self.call(os.open, name, flags | NOFOLLOW, mode)

    def mkdir(self, name, mode):
        self.call(os.mkdir, name, mode)

    def unlink(self, name):
        self.call(os.unlink, name)  # removes a link itself, never what it points to

    def rmdir(self, name):
        self.call(os.rmdir, name)

    def replace(self, source, target):
        if self.handle is None:
            os.replace(os.path.join(self.path, source), os.path.join(self.path, target))
        else:
            os.replace(source, target, src_dir_fd=self.handle, dst_dir_fd=self.handle)

    def names(self):
        return os.listdir(self.path if self.handle is None else self.handle)


def trusted_root(root):
    """The checkout itself, or None when it does not exist. It is the one path taken as given."""
    try:
        handle = os.open(root, os.O_RDONLY | os.O_DIRECTORY) if ANCHORED else None
        if not ANCHORED and not os.path.isdir(root):
            return None
    except FileNotFoundError:
        return None
    except OSError:
        raise StorageError("the SafeBrowse directory could not be opened, so its VPN storage cannot be checked.") from None
    return Directory(handle, root, "")


def enter(parent, name, private, create=False):
    """The checked directory `name` inside `parent`; None when it does not exist and is not to be created.

    A symbolic link (dangling or not), anything that is not a directory, another
    user's directory and one with loose permissions all raise StorageError. Nothing
    is repaired: permissions are never changed on something that failed a check.
    """
    label = f"{parent.label}/{name}" if parent.label else name
    try:
        try:
            found = parent.lstat(name)
        except FileNotFoundError:
            if not create:
                return None
            with contextlib.suppress(FileExistsError):
                parent.mkdir(name, 0o700 if private else 0o755)
            found = parent.lstat(name)
        if stat.S_ISLNK(found.st_mode):
            raise unsafe(label, "is a symbolic link")
        if not stat.S_ISDIR(found.st_mode):
            raise unsafe(label, "is not a directory")
        handle = parent.open(name, os.O_RDONLY | os.O_DIRECTORY) if ANCHORED else None
    except OSError:
        raise unsafe(label, "could not be opened as a directory") from None
    directory = Directory(handle, os.path.join(parent.path, name), label)
    try:
        if handle is not None:
            opened = os.fstat(handle)
            if (opened.st_dev, opened.st_ino) != (found.st_dev, found.st_ino) or not stat.S_ISDIR(opened.st_mode):
                raise unsafe(label, "changed while it was being checked")
            found = opened
        acceptable(label, found, private)
    except BaseException:
        directory.__exit__()
        raise
    return directory


@contextlib.contextmanager
def opened_store(root, create=False):
    """Yield the checked .runtime/vpn directory, or None when there is genuinely no VPN storage."""
    with contextlib.ExitStack() as stack:
        directory = trusted_root(root)
        for name, private in ((".runtime", False), ("vpn", True)):
            if directory is not None:
                directory = enter(stack.enter_context(directory), name, private, create)
        if directory is not None:
            stack.enter_context(directory)
        yield directory


def valid_session(session):
    if not SESSION.fullmatch(session or ""):
        raise ConfigError("the session identifier is not valid.")
    return session


@contextlib.contextmanager
def opened_session(root, session):
    """Yield one session's checked directory; ConfigError when it simply is not there."""
    valid_session(session)
    with opened_store(root) as storage:
        directory = enter(storage, session, private=True) if storage is not None else None
        if directory is None:
            raise ConfigError("the session's generated configuration is missing.")
        with directory:
            yield directory


def read_private(directory, name):
    """The bytes of one generated file, read through the checked directory; never more than SIZE_LIMIT."""
    label = f"{directory.label}/{name}"
    try:
        found = directory.lstat(name)
    except FileNotFoundError:
        raise ConfigError("the session's generated configuration is missing.") from None
    except OSError:
        raise unsafe(label, "could not be examined") from None
    if not stat.S_ISREG(found.st_mode):
        raise unsafe(label, "is a symbolic link" if stat.S_ISLNK(found.st_mode) else "is not a regular file")
    try:
        descriptor = directory.open(name, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        raise unsafe(label, "could not be opened as a regular file") from None
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (found.st_dev, found.st_ino) or not stat.S_ISREG(opened.st_mode):
            raise unsafe(label, "changed while it was being checked")
        acceptable(label, opened, private=True)
        if opened.st_size > SIZE_LIMIT:
            raise ConfigError("the session's generated configuration has been altered.")
        data = b""
        while len(data) <= SIZE_LIMIT:
            piece = os.read(descriptor, SIZE_LIMIT + 1 - len(data))
            if not piece:
                break
            data += piece
    except OSError:
        raise unsafe(label, "could not be read") from None
    finally:
        os.close(descriptor)
    return data


def write_private(directory, name, text):
    """Create or replace one 0600 file inside a checked directory, never exposing a partial or wider-mode version."""
    temporary = "." + name + ".new"
    with contextlib.suppress(FileNotFoundError):
        directory.unlink(temporary)
    descriptor = directory.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as file:
            if hasattr(os, "fchmod"):
                os.fchmod(file.fileno(), 0o600)
            file.write(text)
            file.flush()
            os.fsync(file.fileno())
        directory.replace(temporary, name)
    except BaseException:
        with contextlib.suppress(OSError):
            directory.unlink(temporary)
        raise


def store(root):
    return Path(root) / ".runtime" / "vpn"


def session_path(root, session):
    """Where a session's files are, as a path for Compose. Operations here never go through this path."""
    return store(root) / valid_session(session)


def stage(root, session, tunnel):
    """Write the reduced configuration for a new session into its own new directory and return that path.

    The directory is created exclusively, so an existing session's files are never
    reused or overwritten; the firewall rules follow once the subnet is known.
    """
    valid_session(session)
    with opened_store(root, create=True) as storage:
        storage.mkdir(session, 0o700)  # FileExistsError if it exists, whatever it is
        try:
            with enter(storage, session, private=True) as directory:
                write_private(directory, CONFIG, render(tunnel))
        except BaseException:
            leftover(storage, session)
            raise
    return session_path(root, session)


def write_rules(root, session, subnet, tunnel):
    with opened_session(root, session) as directory:
        write_private(directory, RULES, firewall_rules(subnet, tunnel))


def load(root, session, expected, allow_private_endpoint=False):
    """The Tunnel of an existing session's generated configuration, if it is still the file that session was given.

    `expected` is the fingerprint the session's containers were labelled with when
    they were created. A file that parses, and is even perfectly formatted, is still
    refused when it is not that file. Nothing here derives a fingerprint to trust
    from what is on disk.
    """
    if not FINGERPRINT.fullmatch(expected or ""):
        raise ConfigError("the session does not record which configuration it was started with.")
    with opened_session(root, session) as directory:
        data = read_private(directory, CONFIG)
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected):
        raise ConfigError("the stored configuration is not the one this session was started with; it was changed "
                          "after the session was created.")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise ConfigError("the session's generated configuration has been altered.") from None
    tunnel = parse(text, allow_private_endpoint)
    if tunnel.notices or render(tunnel) != text:
        raise ConfigError("the session's generated configuration has been altered.")
    return tunnel


def leftover(storage, session):
    """Delete one session's generated files and its directory. "" when it is gone, else why it is not.

    Only names this module creates are deleted, only inside a directory that passed
    the same checks as for reading. Anything else found there is left untouched.
    """
    try:
        directory = enter(storage, session, private=True)
    except StorageError as error:
        return str(error)
    if directory is None:
        return ""
    with directory:
        for name in GENERATED:
            try:
                directory.unlink(name)
            except FileNotFoundError:
                pass
            except OSError:
                return f"a generated file in {directory.label} could not be deleted. Delete that directory by hand."
        try:
            others = len(directory.names())
        except OSError:
            others = -1
    if others:
        count = "entries" if others < 0 else "1 entry" if others == 1 else f"{others} entries"
        return (f"{directory.label} still holds {count} "
                "that SafeBrowse did not create; they were left untouched. SafeBrowse's own generated files in it "
                "were deleted. Check them and delete that directory by hand.")
    try:
        storage.rmdir(session)
    except OSError:
        return f"{directory.label} could not be removed. Delete it by hand."
    return ""


def remove(root, session):
    """Delete one session's generated files. True when nothing of it is left. Never raises."""
    try:
        valid_session(session)
        with opened_store(root) as storage:
            return storage is None or not leftover(storage, session)
    except (ConfigError, StorageError, OSError):
        return False


def stored(storage):
    try:
        return sorted(name for name in storage.names() if SESSION.fullmatch(name))
    except OSError:
        raise unsafe(storage.label, "could not be listed") from None


def sessions(root):
    """Identifiers of the generated configurations present; [] only when there are none.

    Every level is checked on the way, including each session directory and the
    generated files in it, so that a link, a foreign file or an unreadable directory
    raises StorageError instead of being read as "no VPN session".
    """
    with opened_store(root) as storage:
        if storage is None:
            return []
        found = stored(storage)
        for session in found:
            with enter(storage, session, private=True) as directory:
                for name in GENERATED:
                    try:
                        status = directory.lstat(name)
                    except FileNotFoundError:
                        continue
                    except OSError:
                        raise unsafe(f"{directory.label}/{name}", "could not be examined") from None
                    if not stat.S_ISREG(status.st_mode):
                        raise unsafe(f"{directory.label}/{name}", "is a symbolic link" if stat.S_ISLNK(status.st_mode)
                                     else "is not a regular file")
                    acceptable(f"{directory.label}/{name}", status, private=True)
        return found


def discard(root, keep=()):
    """Remove every generated configuration except `keep`.

    Returns [(session, reason)] for each one that could not be removed completely.
    Raises StorageError, having deleted nothing, when the storage itself is unsafe.
    """
    with opened_store(root) as storage:
        if storage is None:
            return []
        problems = [(session, leftover(storage, session)) for session in stored(storage) if session not in keep]
        return [(session, reason) for session, reason in problems if reason]
