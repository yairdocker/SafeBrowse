#!/usr/bin/env python3
"""SafeBrowse host launcher: run, stop, verify, logs and pin.

The shell commands in the repository root are thin wrappers around this file.
Every process is started through Host.run and every desktop probe through
Host.fetch, so tests can record and replace all external actions.
"""
import argparse
import base64
import http.client
import io
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import time
from typing import NamedTuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
from open_url import validate_url  # pure validation; never contacts Docker
import vpn  # WireGuard configuration as data; never contacts Docker either

# The launcher owns these Compose inputs; inherited values are ignored. Every other COMPOSE_*
# variable is dropped as well, so the caller's shell cannot select another file, project or profile.
OWNED = ("SANDBOX_SUBNET", "SQUID_CONFIG_PATH", "SAFEBROWSE_SESSION", "SAFEBROWSE_VPN_DIR", "SAFEBROWSE_VPN_MTU",
         "SAFEBROWSE_VPN_KEEPALIVE", "SAFEBROWSE_VPN_FINGERPRINT")
MODES = ("direct", "vpn")
PROVIDERS = ("mullvad",)
# Labels are what a session declares about itself. The verifier checks the live topology against them.
SCHEMA = "1"
SESSION_LABEL = re.compile(r"[a-z0-9]{1,32}")
ROLES = ("browser", "gateway", "ui", "vpn")
# A VPN session's containers also carry the SHA-256 of the generated WireGuard configuration they were
# created with. It is what a stored configuration is checked against before it is ever reused.
FINGERPRINT_LABEL = "safebrowse.vpn-config-sha256"
DISCOVER = ('{{.Id}}|{{.State.Running}}|{{index .Config.Labels "safebrowse.schema"}}|'
            '{{index .Config.Labels "safebrowse.session"}}|{{index .Config.Labels "safebrowse.mode"}}|'
            '{{index .Config.Labels "' + FINGERPRINT_LABEL + '"}}')
NO_LABEL = "<no value>"
VPN_CAPABILITIES = {"NET_ADMIN", "DAC_OVERRIDE"}
# Mount target -> the generated file it must come from (None: a repository file, not a generated one).
VPN_MOUNTS = {"/run/secrets/wg0.conf": vpn.CONFIG, "/iptables/post-rules.txt": vpn.RULES,
              "/gluetun/auth/config.toml": None}
# The only upstream Docker's resolver is given for the browser: the browser container's own loopback.
BROWSER_DNS = "127.0.0.1"
# Compose requires a value to parse the file; teardown never starts a container with it.
TEARDOWN_PASSWORD = "unused-for-teardown"
USER_PATTERN = re.compile(r"[A-Za-z0-9_.-]+")
PASSWORD_PATTERN = re.compile(r"[A-Za-z0-9_+./:@%-]+")
POOL_COLLISION = re.compile(r"invalid pool request|pool overlaps", re.IGNORECASE)
BRIDGE_MODE = '{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}'
MINIMUM_PYTHON = (3, 12)
# Files Squid reads byte for byte through bind mounts. Git attributes keep them LF in a
# fresh checkout but cannot repair a file that was edited or checked out before they existed.
SECURITY_INPUTS = ("gateway/squid.conf", "gateway/blocklist.txt")

USAGE = """Usage: python3 scripts/safebrowse.py <command> [options]
  run [--fresh | --resume] [--direct | --vpn mullvad] [--vpn-config PATH] [--url URL]
                                         start or resume a session, verify it, then open the URL
  stop                                   destroy the session and its profile
  verify [--wait-browser]                rerun the automated checks
  logs [LINES]                           gateway and VPN diagnostics (default 50 lines)
  pin [--refresh]                        record image digests
The ./run.sh, ./stop.sh, ./verify.sh, ./logs.sh and ./pin.sh wrappers call these commands."""

RUN_USAGE = """Usage: ./run.sh [--fresh | --resume] [--direct | --vpn mullvad] [--vpn-config PATH] [--url https://example.com/]
  No session exists: build and start a new disposable session, in direct mode unless --vpn is given.
  --fresh        Build, then destroy any existing session and start with an empty profile. Without a mode
                 option the new session keeps the existing session's mode; it never drops a VPN silently.
  --resume       Verify and use the existing running session in the mode it was started in; do not
                 rebuild, restart or reconfigure it.
  --direct       The gateway reaches the internet through this computer's own connection.
  --vpn mullvad  The gateway reaches the internet only through a WireGuard tunnel; nothing else on this
                 computer uses it. A new VPN session needs --vpn-config.
  --vpn-config   Path to a WireGuard configuration file exported from your Mullvad account. The file is
                 read, never changed, and is not accepted with --resume.
  --url          Open one HTTP(S) URL inside Firefox after all automated checks pass.
  --help         Show this help without contacting Docker.
Changing modes always needs --fresh with --direct or --vpn mullvad. See VPN_SECURITY.md.
Equivalent: python3 scripts/safebrowse.py run [options]"""


class Session(NamedTuple):
    """What the launcher acts on. The command line always uses these defaults.

    Only Python callers can pass another Session, which is how the disposable
    integration fixture avoids the real containers, port and state files.
    """
    root: Path = ROOT
    compose: tuple = ("docker", "compose")
    browser: str = "safebrowse"
    gateway: str = "safebrowse-gw"
    ui: str = "safebrowse-ui"
    network: str = "safebrowse_sandbox"
    ui_port: int = 3011
    vpn: str = "safebrowse-vpn"
    egress: str = "safebrowse_egress"
    # One complete topology per mode, relative to root. Exactly one list is passed to Compose.
    direct_files: tuple = ("docker-compose.yml",)
    vpn_files: tuple = ("docker-compose.vpn.yml",)
    # Fixture-only settings. No command-line option or environment variable reaches them.
    fixture_services: tuple = ()
    private_vpn_endpoint: bool = False


class Options(NamedTuple):
    action: str = ""        # "", "--fresh" or "--resume"
    mode: str = ""          # "", "direct" or "vpn": only what the command line asked for
    vpn_config: str = ""
    url: str = None


class Container(NamedTuple):
    id: str
    running: bool
    schema: str
    session: str
    mode: str
    fingerprint: str = ""


class Existing(NamedTuple):
    """The session containers that exist, and the mode they declare: "", "direct", "vpn" or "unknown".

    `fingerprint` is the VPN configuration fingerprint every container agrees on, "" when
    none carries one (a VPN session from before fingerprints), or "invalid".
    """
    containers: dict
    mode: str = ""
    session: str = ""
    fingerprint: str = ""


class Fatal(Exception):
    """A failure with a sentence the user can act on. Never carries credentials."""


def run_command(args, env=None, cwd=None, capture=False, merge=False, timeout=None):
    """The only place this module starts a process: an argument list, never a shell."""
    return subprocess.run(list(args), env=env, cwd=cwd, timeout=timeout, text=True, errors="replace",
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture and merge else subprocess.PIPE if capture else None)


HEADER_LIMIT = 65536
END_OF_HEADERS = re.compile(rb"\n\r?\n")


class _Received:
    """Lets http.client parse a response head that has already been read in full."""

    def __init__(self, head):
        self.head = head

    def makefile(self, *args, **kwargs):
        return io.BytesIO(self.head)


def desktop_status(port, authorization=None, timeout=3):
    """Send one GET to the local desktop and return its HTTP status.

    `timeout` is a budget for the whole probe: connecting, the TLS handshake,
    sending the request and receiving the complete response head all share one
    monotonic deadline. Every blocking socket call below is given only the time
    that is left, so a desktop that keeps trickling bytes cannot hold the probe
    past it. Running out raises socket.timeout, an OSError like any other
    transport failure, and the connection is closed on the way out.

    The connection is a plain socket to 127.0.0.1, so proxy settings from the
    environment and the operating system play no part, and a redirect is only
    ever a status: nothing is followed and the Authorization header cannot be
    sent anywhere else. Certificate checks are off for this one loopback
    connection because the desktop's certificate is self-signed.
    """
    deadline = time.monotonic() + timeout

    def remaining():
        left = deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout("the desktop did not answer within %g seconds" % timeout)
        return left

    if authorization and ("\r" in authorization or "\n" in authorization):
        raise ValueError("Authorization must be a single header line.")
    request = "GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nAccept-Encoding: identity\r\n" % port
    if authorization:
        request += "Authorization: %s\r\n" % authorization
    unsent = memoryview((request + "\r\n").encode("latin-1"))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    head = b""
    with socket.create_connection(("127.0.0.1", port), timeout=remaining()) as plain:
        with context.wrap_socket(plain, do_handshake_on_connect=False) as desktop:
            desktop.settimeout(remaining())
            desktop.do_handshake()
            while unsent:
                desktop.settimeout(remaining())
                unsent = unsent[desktop.send(unsent):]
            while not END_OF_HEADERS.search(head):
                if len(head) > HEADER_LIMIT:
                    raise http.client.HTTPException("The desktop's response headers are too large.")
                desktop.settimeout(remaining())
                received = desktop.recv(4096)
                if not received:
                    break  # closed early: http.client decides below, as it did when it read the socket itself
                head += received
    response = http.client.HTTPResponse(_Received(head), method="GET")
    try:
        response.begin()
        return response.status
    finally:
        response.close()


def desktop_ready(fetch, port, user, password):
    """Authentication must be required, and these credentials must then be accepted."""
    try:
        if fetch(port) != 401:
            return False
        token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
        return fetch(port, "Basic " + token) == 200
    except (OSError, http.client.HTTPException):
        return False


class Host:
    """External boundaries: processes, the desktop probe, the environment and time."""

    def __init__(self, session=None, run=run_command, fetch=desktop_status, environ=None,
                 monotonic=time.monotonic, sleep=time.sleep, euid=None):
        self.session = session or Session()
        self.run, self.fetch, self.monotonic, self.sleep = run, fetch, monotonic, sleep
        # The effective user ID, or None where the platform has no such thing.
        self.euid = euid or getattr(os, "geteuid", lambda: None)
        inherited = dict(os.environ if environ is None else environ)
        # Names only: these select another Compose configuration, and are reported, never used.
        self.ignored = sorted(key for key in inherited if key in OWNED or key.startswith("COMPOSE_"))
        self.env = {key: value for key, value in inherited.items() if key not in self.ignored}
        self.mode = "direct"

    def command(self, args, **options):
        try:
            return self.run([str(arg) for arg in args], env=dict(self.env), cwd=str(self.session.root), **options)
        except FileNotFoundError:
            raise Fatal(f"{Path(str(args[0])).name} is required. Install it and retry.") from None
        except OSError as error:
            raise Fatal(f"could not run {Path(str(args[0])).name} ({type(error).__name__}).") from None

    def docker(self, *args, **options):
        return self.command(("docker",) + args, **options)

    def compose(self, *args, **options):
        """Compose with exactly one topology, named on the command line, for every lifecycle command."""
        files = self.session.vpn_files if self.mode == "vpn" else self.session.direct_files
        selection = tuple(value for name in files for value in ("-f", name))
        return self.command(tuple(self.session.compose) + selection + args, **options)

    def use_session(self, mode, session="", settings=None):
        """Select the topology and the launcher-owned inputs that go with it."""
        if mode not in MODES:
            raise Fatal("internal error: unknown session mode.")
        self.mode = mode
        for name in OWNED[2:]:
            self.env.pop(name, None)
        if session:
            self.env["SAFEBROWSE_SESSION"] = session
        self.env.update(settings or {})

    def script(self, name, *args, **options):
        return self.command((sys.executable, self.session.root / "scripts" / name) + args, **options)

    def use_network(self, subnet):
        self.env["SANDBOX_SUBNET"] = subnet
        self.env["SQUID_CONFIG_PATH"] = str(self.session.root / ".runtime" / "squid.conf")


def color(code, text):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text


def step(message):
    print(f"{color(36, '==>')} {message}", flush=True)


def warn(message):
    print(f"{color(33, 'WARNING')} {message}", flush=True)


def captured(result):
    """Like a shell $(...): keep stdout, let the command's own stderr through."""
    if result.stderr:
        sys.stderr.write(result.stderr)
        sys.stderr.flush()
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# Credentials for the remote-desktop login. .env is data, never shell input.
# ---------------------------------------------------------------------------
def parse_credentials(text):
    """Return (user, password), or raise ValueError without echoing the file."""
    patterns = {"SANDBOX_USER": USER_PATTERN, "SANDBOX_PASSWORD": PASSWORD_PATTERN}
    found = {}
    # Only "\n" ends a line and only one trailing "\r" is dropped; any other
    # whitespace stays in the value, where the patterns reject it.
    for line in text.split("\n"):
        if line.endswith("\r"):
            line = line[:-1]
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key not in patterns or key in found or not patterns[key].fullmatch(value):
            raise ValueError("invalid credentials file")
        found[key] = value
    if len(found) != len(patterns):
        raise ValueError("incomplete credentials file")
    return found["SANDBOX_USER"], found["SANDBOX_PASSWORD"]


def create_credentials(path):
    """Create .env exclusively with mode 0600; an existing file or link is never replaced."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as file:
            os.fchmod(file.fileno(), 0o600)
            file.write(f"SANDBOX_USER=sandbox\nSANDBOX_PASSWORD={secrets.token_hex(16)}\n")
    except BaseException:
        os.unlink(path)
        raise


def read_credentials(path):
    """Refuse links and special files, restrict the file, then parse that same open file."""
    try:
        mode = os.lstat(path).st_mode
        if stat.S_ISLNK(mode):
            raise Fatal(".env must be a regular file, not a symlink.")
        if not stat.S_ISREG(mode):
            raise Fatal(".env must be a regular file.")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise Fatal("could not read .env as a regular file.") from None
    with os.fdopen(descriptor, "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise Fatal(".env must be a regular file.")
        try:
            os.fchmod(file.fileno(), 0o600)
        except OSError:
            raise Fatal("could not restrict .env permissions.") from None
        data = file.read()
    try:
        return parse_credentials(data.decode("utf-8"))
    except ValueError:
        raise Fatal(".env must contain unquoted SANDBOX_USER and SANDBOX_PASSWORD values only; "
                    "shell syntax, whitespace and duplicate keys are rejected.") from None


def load_credentials(host, mode, create=True):
    """(user, password), or None when there is no .env yet and `create` is off."""
    path = host.session.root / ".env"
    if not os.path.lexists(path):
        if mode == "--resume":
            raise Fatal("cannot resume without the original .env credentials.")
        if not create:
            return None
        step("First run: generating .env with a random UI password")
        try:
            create_credentials(path)
        except OSError:
            raise Fatal(f"could not write .env - check permissions on {host.session.root}") from None
    user, password = read_credentials(path)
    # Compose must use the credentials the launcher displays, whatever the caller exported.
    host.env.update(SANDBOX_USER=user, SANDBOX_PASSWORD=password)
    return user, password


# ---------------------------------------------------------------------------
# Preflight: refuse configurations SafeBrowse has not been validated on, before
# anything is created, built, started or removed.
# ---------------------------------------------------------------------------
def require_unprivileged(host, command):
    if host.euid() == 0:
        raise Fatal(f"do not run '{command}' as root or with sudo; nothing was changed. SafeBrowse writes its "
                    "credentials, runtime state and image pins as your own user and reaches Docker with your "
                    "user's access (on Linux, membership of the docker group). Rerun it as that user.")


def check_security_inputs(host):
    for name in SECURITY_INPUTS:
        try:
            data = (host.session.root / name).read_bytes()
        except OSError:
            raise Fatal(f"could not read {name}; the gateway cannot filter without it. Nothing was changed.") from None
        if b"\r" in data:
            raise Fatal(f"{name} contains carriage returns (Windows line endings); nothing was changed. Squid reads "
                        "this file as it is, so its rules might not mean what they say. Convert the file to LF line "
                        "endings, for example with your editor or dos2unix, and check that Git is not converting "
                        "it (git config core.autocrlf).")


def check_vpn_inputs(host):
    """The one repository file only the VPN topology mounts; without it the control server would be open."""
    name = "security/gluetun-auth.toml"
    path = host.session.root / name
    try:
        regular = stat.S_ISREG(os.lstat(path).st_mode)
        data = path.read_bytes() if regular else b""
    except OSError:
        regular, data = False, b""
    if not regular or b"\r" in data or b'routes = ["GET /v1/version"]' not in data:
        raise Fatal(f"{name} is missing, is not a regular file, or is not the reviewed version with LF line endings; "
                    "the VPN container's control server would not be locked. Nothing was changed.")


def check_daemon_security(host):
    """Read the daemon's own security options; never infer them from socket paths or process names."""
    info = host.docker("info", "--format", "{{json .SecurityOptions}}", capture=True)
    try:
        options = json.loads(info.stdout) if info.returncode == 0 else None
    except ValueError:
        options = None
    if not isinstance(options, list) or not all(isinstance(option, str) for option in options):
        raise Fatal("could not read the Docker daemon's security options, so its confinement of containers is "
                    "unknown. Nothing was changed. Check 'docker info' and retry.")
    names = {field.partition("=")[2] for option in options for field in option.split(",") if field.startswith("name=")}
    if "rootless" in names:
        raise Fatal("this Docker daemon runs in rootless mode; nothing was changed. SafeBrowse's network isolation and "
                    "container hardening have only been validated with a rootful Docker Engine or Docker Desktop, so "
                    "a rootless daemon is outside the configuration it can vouch for. That is a statement about what "
                    "has been tested, not about rootless Docker's security. See LINUX_SECURITY.md.")
    if "seccomp" not in names:
        raise Fatal("this Docker daemon reports no seccomp support, so the browser container would run without a "
                    "syscall filter. Nothing was changed. See LINUX_SECURITY.md.")


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
def parse_run(args):
    """Return Options, or None for --help. Options must be spelled out exactly; nothing here contacts Docker."""
    action = mode = config = ""
    url = None
    args = list(args)
    while args:
        arg = args.pop(0)
        if arg in ("--fresh", "--resume"):
            if action:
                raise Fatal("choose --fresh or --resume once.")
            action = arg
        elif arg == "--url":
            if not args or not args[0] or url is not None:
                raise Fatal("--url requires one URL and may appear only once.")
            url = args.pop(0)
        elif arg in ("--direct", "--vpn"):
            if mode:
                raise Fatal("choose --direct or --vpn once; nothing was changed.")
            mode = arg[2:]
            if mode == "vpn" and (not args or args.pop(0) not in PROVIDERS):
                raise Fatal("--vpn must be followed by a supported provider: mullvad. Nothing was changed.")
        elif arg == "--vpn-config":
            if not args or not args[0] or config:
                raise Fatal("--vpn-config requires one file path and may appear only once.")
            config = args.pop(0)
        elif arg in ("--help", "-h"):
            return None
        else:
            print(RUN_USAGE, file=sys.stderr)
            raise Fatal("unknown argument; see usage above.")
    if config and mode != "vpn":
        raise Fatal("--vpn-config is only meaningful with --vpn mullvad; nothing was changed.")
    if config and action == "--resume":
        raise Fatal("--resume keeps the session's own VPN configuration and cannot replace it; nothing was changed. "
                    "Use --fresh --vpn mullvad --vpn-config PATH to start a new session with another configuration.")
    return Options(action, mode, config, url)


def check_docker(host, action):
    step("Checking Docker")
    if host.docker("info", capture=True, merge=True).returncode:
        raise Fatal("Docker is installed but the daemon isn't answering. Start Docker Desktop, wait for the "
                    "whale icon to stop animating, then re-run this script.")
    if host.compose("version", capture=True, merge=True).returncode:
        raise Fatal("'docker compose' (v2) isn't available. Update Docker Desktop.")
    version = host.docker("version", "--format", "{{.Server.Version}}", capture=True)
    major = captured(version).split(".")[0]
    if version.returncode:
        raise Fatal("could not read Docker Engine version.")
    if not re.fullmatch(r"[0-9]+", major) or int(major) < 28:
        raise Fatal("Docker Engine 28+ is required for isolated bridge mode and localhost port isolation.")
    check_daemon_security(host)
    # A pre-upgrade bridge cannot be changed in place. Never tear down a session
    # automatically just to migrate its network configuration.
    bridge = host.docker("network", "inspect", host.session.network, "-f", BRIDGE_MODE, capture=True)
    if bridge.returncode == 0 and bridge.stdout.strip() != "isolated" and action != "--fresh":
        raise Fatal("existing sandbox bridge needs migration: ./stop.sh discards the current session, "
                    "then rerun ./run.sh.")
    info = host.docker("info", "--format", "{{.MemTotal}}", capture=True)
    memory = info.stdout.strip() if info.returncode == 0 else ""
    memory = int(memory) if re.fullmatch(r"[0-9]+", memory) else 0
    if 0 < memory < 5500000000:
        warn(f"Docker has {memory // 1024 ** 3} GiB of RAM; the sandbox alone is capped at 4 GiB.")
        warn("If Firefox dies on startup, raise it in Docker Desktop > Settings > Resources > Memory.")


# ---------------------------------------------------------------------------
# Which session exists, and which mode the next one must have. Read-only.
# ---------------------------------------------------------------------------
def discover(host):
    """Inspect the four container names a session can use. Reads six fields of each and nothing else."""
    found = {}
    for role in ROLES:
        result = host.docker("inspect", "--type", "container", "--format", DISCOVER,
                             getattr(host.session, role), capture=True)
        fields = (result.stdout or "").strip().split("|")
        if result.returncode:
            if "no such" in (result.stderr or "").lower():
                continue
            raise Fatal("could not inspect the existing session; nothing was changed. Check that Docker is "
                        "answering and retry.")
        if len(fields) != 6 or fields[1] not in ("true", "false"):
            raise Fatal("could not read the existing session's containers; nothing was changed.")
        # Docker prints this placeholder for a label the container does not have.
        labels = ["" if value == NO_LABEL else value for value in fields[2:]]
        found[role] = Container(fields[0], fields[1] == "true", *labels)
    if not found:
        return Existing({})
    declared = {(c.schema, c.session, c.mode) for c in found.values()}
    fingerprints = {c.fingerprint for c in found.values()}
    schema, session, mode = next(iter(declared))
    if (len(declared) != 1 or schema != SCHEMA or mode not in MODES or not SESSION_LABEL.fullmatch(session)
            or ("vpn" in found and mode != "vpn") or (mode == "direct" and fingerprints != {""})):
        return Existing(found, "unknown")
    fingerprint = fingerprints.pop() if len(fingerprints) == 1 else "invalid"
    if fingerprint and not vpn.FINGERPRINT.fullmatch(fingerprint):
        fingerprint = "invalid"
    return Existing(found, mode, session, fingerprint)


UNKNOWN_MODE = ("the existing session does not say consistently whether it is a direct or a VPN session (it may "
                "have been started by an older SafeBrowse, or changed by hand), so its mode cannot be established "
                "safely. Nothing was changed. To replace it, choose the new session's mode explicitly: "
                "./run.sh --fresh --direct   or   ./run.sh --fresh --vpn mullvad --vpn-config PATH. "
                "./stop.sh still removes it.")


MIGRATION = ("the existing VPN session was started by an earlier SafeBrowse, which did not record which WireGuard "
             "configuration the session was given. Its stored configuration therefore cannot be checked, and it "
             "will not be resumed or reused. Nothing was changed. Start a new session from your WireGuard file: "
             "./run.sh --fresh --vpn mullvad --vpn-config PATH   (or ./run.sh --fresh --direct to leave the VPN "
             "deliberately). ./stop.sh still removes the session.")


def stored_sessions(host):
    """Identifiers of the generated VPN configurations on disk. Unsafe storage stops the command."""
    try:
        return vpn.sessions(host.session.root)
    except vpn.StorageError as error:
        raise Fatal(f"{error} Nothing was changed, and no session was started in either mode.") from None


def choose_mode(host, options, existing, stored):
    """The mode this command acts in. Never guesses direct when a VPN may have been intended."""
    if existing.containers and not options.action:
        raise Fatal("a session already exists. Use --resume to keep it or --fresh to discard its profile.")
    if options.action == "--resume":
        if not existing.containers:
            raise Fatal("no session exists to resume. Run ./run.sh to create one.")
        if existing.mode == "unknown":
            raise Fatal(UNKNOWN_MODE)
        if options.mode and options.mode != existing.mode:
            raise Fatal(f"the existing session is a {existing.mode} session and --resume never changes the mode; "
                        "nothing was changed. Use --fresh with --direct or --vpn mullvad to replace it.")
        return existing.mode
    if options.mode:
        return options.mode
    if existing.mode == "unknown":
        raise Fatal(UNKNOWN_MODE)
    if existing.mode:
        return existing.mode  # --fresh keeps the mode of the session it replaces
    if stored:
        raise Fatal("no session exists, but a generated VPN configuration from an earlier session is still stored, "
                    "so the last session was probably a VPN session. SafeBrowse will not guess. Nothing was "
                    "changed. Choose: ./run.sh --vpn mullvad --vpn-config PATH   or   ./run.sh --direct. "
                    "(./stop.sh removes the stored configuration.)")
    return "direct"


def choose_tunnel(host, options, existing):
    """The WireGuard settings for a new VPN session: a file named now, or the replaced session's own."""
    private = host.session.private_vpn_endpoint
    try:
        if options.vpn_config:
            text, notices = vpn.read_source(options.vpn_config)
            tunnel = vpn.parse(text, private)
            for notice in notices + tunnel.notices:
                step("Note: " + notice)
            return tunnel
    except vpn.ConfigError as error:
        raise Fatal(f"the WireGuard configuration was not accepted; nothing was changed. {error}") from None
    if existing.mode != "vpn":
        raise Fatal("a new VPN session needs a configuration: --vpn mullvad --vpn-config PATH. Nothing was changed.")
    return stored_tunnel(host, existing)


def stored_tunnel(host, existing):
    """An existing VPN session's own configuration, only if it is still the file that session was created with."""
    if not existing.fingerprint:
        raise Fatal(MIGRATION)
    if existing.fingerprint == "invalid":
        raise Fatal("the existing VPN session's containers do not agree on one valid configuration fingerprint, so "
                    "its stored configuration cannot be checked and will not be resumed or reused. Nothing was "
                    "changed. Start a new session from your WireGuard file: ./run.sh --fresh --vpn mullvad "
                    "--vpn-config PATH   (or ./run.sh --fresh --direct). ./stop.sh still removes the session.")
    try:
        return vpn.load(host.session.root, existing.session, existing.fingerprint, host.session.private_vpn_endpoint)
    except vpn.StorageError as error:
        raise Fatal(f"{error} Nothing was changed.") from None
    except vpn.ConfigError as error:
        raise Fatal(f"the existing VPN session's stored configuration cannot be reused ({error}) Nothing was "
                    "changed. Supply it again with --fresh --vpn mullvad --vpn-config PATH, or use "
                    "--fresh --direct to switch to a direct session deliberately.") from None


def check_model(host, mode, session):
    """Refuse an effective Compose model that is not the topology this mode means.

    The output of `compose config` contains the desktop password, so it is parsed
    in memory and never printed.
    """
    result = host.compose("config", "--format", "json", capture=True)
    try:
        model = json.loads(result.stdout) if result.returncode == 0 else None
        services, networks = model["services"], model["networks"]
        names = {key: network.get("name") for key, network in networks.items()}
        sandbox = [key for key, name in names.items() if name == host.session.network]
        egress = [key for key, name in names.items() if name == host.session.egress]
        problems = []

        def attached(service):
            return set(services[service].get("networks") or {})

        def require(condition, message):
            if not condition:
                problems.append(message)

        expected = {"gateway", "uiproxy", "safebrowse"} | ({"vpn"} if mode == "vpn" else set())
        # Direct sessions carry no fingerprint; a VPN session carries the one computed for its staged file.
        fingerprint = host.env.get("SAFEBROWSE_VPN_FINGERPRINT") if mode == "vpn" else None
        require(mode != "vpn" or vpn.FINGERPRINT.fullmatch(fingerprint or ""),
                "no configuration fingerprint was computed for this VPN session")
        require(len(sandbox) == 1 and len(egress) == 1, "the sandbox and egress networks are not defined once each")
        require(expected <= set(services) and set(services) - expected <= set(host.session.fixture_services),
                "the services are not exactly those of this mode")
        for name in expected & set(services):
            service = services[name]
            labels = service.get("labels") or {}
            require(labels.get("safebrowse.mode") == mode and labels.get("safebrowse.session") == session
                    and labels.get("safebrowse.schema") == SCHEMA and labels.get(FINGERPRINT_LABEL) == fingerprint,
                    f"{name} does not carry this session's labels")
            require(not service.get("privileged") and service.get("restart", "no") == "no"
                    and service.get("cap_drop") == ["ALL"] and not service.get("devices")
                    and (service.get("network_mode") is None or (name, mode) == ("gateway", "vpn")),
                    f"{name} has privileges, a restart policy or a network mode outside the reviewed set")
            if name != "uiproxy":
                require(not service.get("ports"), f"{name} publishes a port")
        require(attached("safebrowse") == set(sandbox) and not services["safebrowse"].get("volumes")
                and not services["safebrowse"].get("network_mode"),
                "the browser is not confined to the sandbox network, or has a mount")
        require(services["safebrowse"].get("dns") == [BROWSER_DNS],
                "the browser's DNS forwarding is not restricted to its own loopback address")
        ports = [(port.get("host_ip"), str(port.get("published")), port.get("target"))
                 for port in services["uiproxy"].get("ports") or []]
        require(ports == [("127.0.0.1", str(host.session.ui_port), 3001)] and attached("uiproxy") == set(sandbox + egress),
                "the desktop relay is not published on localhost only, outside the gateway's namespace")
        gateway = services["gateway"]
        if mode == "direct":
            require(set(sandbox + egress) <= attached("gateway") and not gateway.get("network_mode"),
                    "the gateway is not attached to the sandbox and egress networks")
        else:
            tunnel = services["vpn"]
            attachments = tunnel.get("networks") or {}
            require(gateway.get("network_mode") == "service:vpn" and not gateway.get("networks")
                    and not gateway.get("hostname"),
                    "the gateway has a network of its own instead of the VPN container's namespace")
            require(set(attachments) == set(sandbox + egress) and not tunnel.get("network_mode"),
                    "the VPN container is not attached to exactly the sandbox and egress networks")
            for key, alias, interface in ((sandbox, ["gateway"], vpn.SANDBOX_INTERFACE), (egress, None, vpn.EGRESS_INTERFACE)):
                attachment = attachments.get(key[0] if key else "") or {}
                require(attachment.get("aliases") == alias and (attachment.get("driver_opts") or {}).get(
                    "com.docker.network.endpoint.ifname") == interface,
                        "the VPN container's network aliases or interface names are not the reviewed ones")
            require(set(tunnel.get("cap_add") or []) == VPN_CAPABILITIES, "the VPN container's capabilities differ")
            mounts = tunnel.get("volumes") or []
            require({mount.get("target") for mount in mounts} == set(VPN_MOUNTS) and len(mounts) == len(VPN_MOUNTS)
                    and all(mount.get("type") == "bind" and mount.get("read_only") is True for mount in mounts),
                    "the VPN container's mounts are not the three reviewed read-only files")
            # Only the checkout itself is resolved; the path below it must be spelled exactly, link-free.
            base = Path(host.session.root).resolve()

            def generated(mount):
                parts = Path(mount.get("source", "")).parts
                return (len(parts) > 4 and parts[-4:] == (".runtime", "vpn", session, VPN_MOUNTS[mount.get("target")])
                        and Path(*parts[:-4]).resolve() == base)

            require(all(generated(mount) for mount in mounts if VPN_MOUNTS.get(mount.get("target"))),
                    "the VPN container would not read this session's generated configuration")
    except (ValueError, KeyError, TypeError, AttributeError, IndexError):
        raise Fatal("the Compose configuration could not be read; existing session was not discarded.") from None
    if problems:
        raise Fatal(f"the effective Compose configuration is not SafeBrowse's {mode} topology "
                    f"({'; '.join(problems)}). Existing session was not discarded.")
    return model


def prepare_images(host, model):
    """Build and fetch everything the new session needs while the old one still exists."""
    step("Building image (first build pulls ~1.5 GB and takes a few minutes)")
    if host.compose("build").returncode:
        raise Fatal("build failed; existing session was not discarded. Check the output above.")
    services = model["services"].values()
    built = {service.get("image") for service in services if service.get("build")}
    for image in sorted({service.get("image") for service in services} - built - {None}):
        if host.docker("image", "inspect", "--format", "{{.Id}}", image, capture=True).returncode == 0:
            continue
        step(f"Fetching {image.split('@')[0]}")
        if host.docker("pull", "--quiet", image, capture=True, merge=True).returncode:
            raise Fatal(f"could not fetch {image.split('@')[0]}; existing session was not discarded.")


def select_network(host, action, skipped=()):
    arguments = [action] + [value for subnet in skipped for value in ("--skip", subnet)]
    result = host.script("network.py", *arguments, capture=True)
    subnet = captured(result)
    if result.returncode or not subnet:
        raise Fatal("could not prepare the isolated sandbox network.")
    host.use_network(subnet)
    return subnet


def saved_network(host):
    """Use the generated configuration when it is intact; otherwise Compose's fallback applies.

    This state is optional. If it cannot even be examined (Python 3.12 raises for a file
    under a directory that cannot be searched, where later versions answer "no"), it is
    treated as absent: nothing is created or repaired, and teardown still goes ahead.
    """
    try:
        present = (host.session.root / ".runtime" / "network.json").is_file()
    except OSError:
        present = False
    if present:
        saved = host.script("network.py", "current", capture=True)
        if saved.returncode == 0 and saved.stdout.strip():
            host.use_network(saved.stdout.strip())


def discard_configurations(host, keep=()):
    """Remove generated VPN configurations whose session is gone; return how many could not be removed."""
    remaining = vpn.discard(host.session.root, keep)
    for session, reason in remaining:
        warn(f"a generated VPN configuration from an earlier session (.runtime/vpn/{session}) was not removed "
             f"completely: {reason}")
    return len(remaining)


def remaining_containers(host):
    """Names of the session containers that still exist, or None when that cannot be established."""
    try:
        return sorted(getattr(host.session, role) for role in discover(host).containers)
    except Fatal:
        return None


def start_session(host, action, mode, tunnel):
    """Replace whatever exists with a new session. Returns its identifier if it has generated VPN secrets, else ""."""
    session = secrets.token_hex(8)
    staged = None
    try:
        # The replacement's secrets get their own new directory; the existing session's stay usable.
        if mode == "vpn":
            check_vpn_inputs(host)
            try:
                staged = vpn.stage(host.session.root, session, tunnel)
            except vpn.StorageError as error:
                raise Fatal(f"{error} Existing session was not discarded.") from None
            except (vpn.ConfigError, OSError) as error:
                detail = str(error) if isinstance(error, vpn.ConfigError) else type(error).__name__
                raise Fatal(f"could not store the VPN configuration privately ({detail}); "
                            "existing session was not discarded.") from None
        host.use_session(mode, session, vpn.environment(tunnel, staged) if staged else None)
        saved_network(host)
        prepare_images(host, check_model(host, mode, session))
    except BaseException:
        if staged:
            vpn.remove(host.session.root, session)
        raise
    created = []  # non-empty once Compose has been asked to create this session's containers
    try:
        replace_session(host, action, mode, tunnel, session, staged, created)
    except BaseException as error:
        note = staged_note(host, session, bool(created)) if staged else ""
        if note and isinstance(error, Fatal):
            raise Fatal(f"{error} {note}") from None
        if note:
            warn(note)
        raise
    return session if staged else ""


def staged_note(host, session, in_use):
    """What to say about the new session's generated secrets after a launch that failed past teardown.

    Before any container was created nothing can be using them, so they are removed.
    Afterwards containers kept for diagnosis may mount them: they stay, and the user
    is told where they are and what removes them. The contents are never printed.
    """
    place = f".runtime/vpn/{session}/"
    if in_use:
        return (f"The new session's generated VPN configuration, which contains the WireGuard private key, was kept in "
                f"{place} because containers that were created may be using it. ./stop.sh removes those containers "
                "and then that directory.")
    if vpn.remove(host.session.root, session):
        return ""
    return (f"The VPN configuration generated for the new session, which contains the WireGuard private key, could not "
            f"be removed and is still in {place}. No container uses it. Run ./stop.sh, which removes it or says why "
            "it cannot.")


def retained_note(session):
    """What to say when a launch stops after the new VPN session's containers have started.

    Nothing is stopped or deleted on that path. `session` is the identifier this launch
    generated and started the containers with; storage is never searched for it, and
    the contents of the directory are never printed.
    """
    return (f"The new session's containers were started and were left as they are. .runtime/vpn/{session}/ holds its "
            "generated VPN configuration, which contains the WireGuard private key, and those containers may still "
            "need it, so it was kept. ./stop.sh removes the containers and then attempts to remove that directory.")


def replace_session(host, action, mode, tunnel, session, staged, created):
    """Everything after the point of no return: tear down, confirm, discard old secrets, start."""
    if action == "--fresh":
        step("Discarding the previous session and its profile")
        if host.compose("down", "--volumes", "--remove-orphans").returncode:
            raise Fatal("could not discard the previous session. Its stored VPN configuration, if it has one, was kept.")
    # A failed earlier launch may have left Compose networks but no containers.
    elif host.compose("down", "--volumes", "--remove-orphans").returncode:
        raise Fatal("could not clear partial Compose networks.")
    # A teardown that reports success has only removed this checkout's own Compose project. Nothing that
    # belongs to an earlier session is deleted until its containers are seen to be gone.
    remaining = remaining_containers(host)
    if remaining is None:
        raise Fatal("teardown ran, but whether the previous session's containers are gone could not be checked "
                    "(Docker did not answer). No new session was started, and the stored VPN configuration of any "
                    "earlier session was left in place. Check Docker, then rerun the command.")
    if remaining:
        raise Fatal(f"teardown ran, but these containers still exist: {', '.join(remaining)}. They do not belong to "
                    "this checkout's Compose project (for example, the checkout directory was renamed or copied "
                    "after they were started), so Compose did not remove them, and SafeBrowse does not remove "
                    "another project's containers. No new session was started, and the stored VPN configuration "
                    "those containers may be using was left in place. If another copy of this checkout started "
                    "them, run ./stop.sh there; otherwise remove them yourself with 'docker rm --force' and the "
                    "names above. Then rerun the command.")
    # Whatever session those files belonged to no longer exists.
    try:
        discard_configurations(host, keep=(session,) if staged else ())
    except vpn.StorageError as error:
        raise Fatal(f"{error} The previous session has been removed and no new session was started.") from None
    skipped = []
    for attempt in (1, 2, 3):
        subnet = select_network(host, "select", skipped)
        if staged:
            try:
                vpn.write_rules(host.session.root, session, subnet, tunnel)
            except vpn.StorageError as error:
                raise Fatal(f"{error} Nothing was started.") from None
            except (OSError, ValueError):
                raise Fatal("could not write the VPN firewall rules; nothing was started.") from None
        step(f"Starting a fresh {'VPN' if mode == 'vpn' else 'direct'} session on {subnet}")
        created.append(subnet)
        up = host.compose("up", "-d", capture=True, merge=True)
        print(up.stdout, end="", flush=True)
        if up.returncode == 0:
            return
        if attempt < 3 and POOL_COLLISION.search(up.stdout):
            warn(f"Docker rejected {subnet}; trying another subnet.")
            if host.compose("down", "--volumes", "--remove-orphans").returncode:
                raise Fatal("could not clean up the failed network attempt.")
            skipped.append(subnet)
        else:
            host.compose("logs", "--tail", "40")
            if mode == "vpn":
                raise Fatal("containers failed to start (logs above). If the VPN container is unhealthy, the tunnel "
                            "did not come up: check the configuration file and your connection. Nothing was sent "
                            "outside the tunnel and SafeBrowse did not fall back to a direct session. The containers "
                            "remain for diagnosis; ./stop.sh removes them.")
            raise Fatal("containers failed to start (logs above).")


def require_running_session(host, existing):
    select_network(host, "current")
    # Never let Compose recreate an existing profile while claiming to resume it.
    needed = ROLES if existing.mode == "vpn" else ROLES[:3]
    if any(role not in existing.containers for role in needed):
        raise Fatal("session is incomplete; use --fresh to replace it.")
    if not all(existing.containers[role].running for role in needed):
        raise Fatal("session is not running; use --fresh to create a new profile.")
    step(f"Resuming the existing {'VPN' if existing.mode == 'vpn' else 'direct'} session, profile and tabs")


def wait_until(host, seconds, ready, interval=2):
    deadline = host.monotonic() + seconds
    while host.monotonic() < deadline:
        if ready():
            return True
        host.sleep(interval)
    return False


def run_session(host, options):
    action, url = options.action, options.url
    step("Checking prerequisites")
    require_unprivileged(host, "run")
    if url is not None:
        try:
            validate_url(url)
        except argparse.ArgumentTypeError as error:
            raise Fatal(f"invalid --url; session unchanged. {error}") from None
    selecting = [name for name in host.ignored if name.startswith("COMPOSE_")]
    if selecting:
        warn(f"ignoring {', '.join(selecting)} from your environment: SafeBrowse selects its own Compose "
             "files and project.")
    check_security_inputs(host)
    # Before credentials exist, anything is staged or Docker is asked to change anything: where VPN
    # secrets are kept must be safe to read. Unsafe storage is never treated as "no VPN session".
    stored = stored_sessions(host)
    check_docker(host, action)
    # An existing .env is checked first, as it always was. A missing one is only created once the
    # session and mode questions below are settled, so that a refusal leaves no trace.
    credentials = load_credentials(host, action, create=False)
    existing = discover(host)
    mode = choose_mode(host, options, existing, stored)
    tunnel = None
    if mode == "vpn":
        # A resumed session is only trusted while its stored configuration is still the one it was created with.
        tunnel = stored_tunnel(host, existing) if action == "--resume" else choose_tunnel(host, options, existing)
    user, password = credentials or load_credentials(host, action)

    if action == "--resume":
        settings = vpn.environment(tunnel, vpn.session_path(host.session.root, existing.session)) if tunnel else None
        host.use_session(mode, existing.session, settings)
        require_running_session(host, existing)
        note = ""  # a resumed session is not a new one: its stored configuration is neither reported nor touched
    else:
        started = start_session(host, action, mode, tunnel)
        note = retained_note(started) if started else ""
    # From here on the session's containers exist. A failure leaves them, and a new VPN session's generated
    # configuration, in place: the user is told once where that configuration is and what removes it.
    try:
        code = finish_launch(host, mode, url, user, password)
    except BaseException as error:
        if note and isinstance(error, Fatal):
            raise Fatal(f"{error} {note}") from None
        if note:
            warn(note)
        raise
    if code and note:
        print(f"{note}\n", file=sys.stderr)  # the incomplete-verification message is already on stderr
    return code


def finish_launch(host, mode, url, user, password):
    """Wait for the desktop, verify, then open the URL. Returns 0, or 2 when verification is incomplete."""
    port = host.session.ui_port
    step("Waiting for the remote desktop (up to 3 minutes)")
    if not wait_until(host, 180, lambda: desktop_ready(host.fetch, port, user, password)):
        print("\n" + color(33, "The desktop did not come up. Recent logs:") + "\n", flush=True)
        host.compose("logs", "--tail", "40")
        raise Fatal("not ready in time. Check Firefox startup, UI authentication and the "
                    "Troubleshooting section of README.md.")
    step("Desktop running; checking containment and browser controls")
    # A blank tab creates content processes without visiting the requested site.
    step("Waiting for Firefox (up to 60 seconds)")
    if not wait_until(host, 60, lambda: host.script("open_url.py", "--initialize",
                                                    capture=True, merge=True).returncode == 0):
        raise Fatal("desktop is running but Firefox could not initialize; requested URL was not opened.")
    verification = host.script("verify.py", "--wait-browser").returncode
    if verification == 2:
        print("\nVerification incomplete; requested URL was not opened. Run ./verify.sh or ./stop.sh.\n",
              file=sys.stderr)
        return 2
    if verification:
        raise Fatal("verification failed; requested URL was not opened. Run ./verify.sh or ./stop.sh. "
                    "A session is never repaired in place: ./run.sh --fresh starts a new one in the same mode.")
    step("All automated checks passed")
    if url is not None:
        # The URL stays one argument all the way into Firefox.
        if host.script("open_url.py", url).returncode:
            raise Fatal("checks passed, but Firefox could not open the requested URL.")
        step("Requested URL sent to Firefox")
    route = "VPN: the gateway's only route out is the WireGuard tunnel" if mode == "vpn" else \
        "direct: the gateway uses this computer's own connection"
    print(f"""
  {color(32, 'safebrowse is running; automated checks passed.')}

    URL       https://127.0.0.1:{port}/     (self-signed cert - accept the warning)
    user      {user}
    password  {password}
    mode      {route}

  Next:  ./run.sh --resume --url https://example.com/   keep this session
         ./run.sh --fresh                               discard it and start fresh in the same mode
         ./stop.sh                                     destroy the session
""", flush=True)
    return 0


# ---------------------------------------------------------------------------
# stop, logs, verify, pin
# ---------------------------------------------------------------------------
def stop_session(host):
    """Tear down in either mode, even if .env, the runtime state or the VPN configuration was lost. Creates nothing."""
    saved_network(host)
    host.env["SANDBOX_PASSWORD"] = TEARDOWN_PASSWORD
    try:
        existing = discover(host)
    except Fatal:
        existing = Existing({}, "unknown")  # teardown is still attempted
    host.use_session("vpn" if existing.mode == "vpn" or "vpn" in existing.containers else "direct")
    code = host.compose("down", "--volumes", "--remove-orphans").returncode
    if code:
        return code
    remaining = remaining_containers(host)
    if remaining is None:
        remaining = ["(could not be checked)"]
    if remaining:
        print(f"\n{color(31, 'ERROR')}  teardown ran, but these containers still exist: {', '.join(remaining)}. They "
              "do not belong to this checkout's Compose project. Remove them with 'docker rm --force', then rerun "
              "./stop.sh.\n", file=sys.stderr)
        return 1
    try:
        remaining = discard_configurations(host)
    except vpn.StorageError as error:
        print(f"\n{color(31, 'ERROR')}  the session's containers and profile were removed, but generated VPN "
              f"configuration could not be cleaned up. {error}\n", file=sys.stderr)
        return 1
    if remaining:
        print(f"\n{color(31, 'ERROR')}  the session's containers and profile were removed, but generated VPN "
              "configuration was not removed completely (see the warnings above). It may still hold a WireGuard "
              "private key. Delete what is left by hand, then rerun ./stop.sh to confirm.\n", file=sys.stderr)
        return 1
    print("==> Sandbox destroyed. Session containers, profile and any generated VPN configuration removed; "
          "this is not secure disk erasure.")
    return 0


def show_logs(host, count):
    gateway = host.session.gateway
    status = host.docker("inspect", "-f", "{{.State.Status}}", gateway, capture=True)
    if status.returncode or status.stdout.strip() != "running":
        print("Gateway is not running. Check configuration with:")
        print("  docker compose run --rm --no-deps gateway squid -k parse")
        code = 1
    else:
        print("=== gateway diagnostics (memory-backed) ===", flush=True)
        code = host.docker("exec", gateway, "tail", "-n", count, "/var/log/squid/cache.log").returncode
        if code == 0:
            print("=== optional access log (disabled by default) ===", flush=True)
            access = host.docker("exec", gateway, "tail", "-n", count, "/var/log/squid/access.log", capture=True)
            if access.returncode:
                print("No access log. See README.md to enable temporary diagnostics.")
            else:
                print(access.stdout, end="", flush=True)
    # A VPN session's tunnel diagnostics. Gluetun runs at the warn level, which never prints key material.
    tunnel = host.docker("inspect", "--type", "container", "-f", "{{.State.Status}}", host.session.vpn, capture=True)
    if tunnel.returncode == 0:
        print(f"=== VPN diagnostics (container is {tunnel.stdout.strip()}; warnings and errors only) ===", flush=True)
        code = host.docker("logs", "--tail", count, host.session.vpn).returncode or code
    return code


def main(argv=None, host=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if tuple(sys.version_info[:2]) < MINIMUM_PYTHON:
            raise Fatal("Python %d.%d or newer is required; this is Python %d.%d. Nothing was changed."
                        % (MINIMUM_PYTHON + tuple(sys.version_info[:2])))
        if not argv or argv[0] in ("--help", "-h"):
            print(USAGE, file=sys.stdout if argv else sys.stderr)
            return 0 if argv else 1
        command, args = argv[0], argv[1:]
        if command == "run":
            options = parse_run(args)
            if options is None:
                print(RUN_USAGE)
                return 0
            return run_session(host or Host(), options)
        if command == "stop":
            if args:
                print("Usage: ./stop.sh   (destroys the session; takes no arguments)",
                      file=sys.stdout if args[0] in ("--help", "-h") else sys.stderr)
                return 0 if args[0] in ("--help", "-h") else 1
            return stop_session(host or Host())
        if command == "logs":
            if len(args) > 1 or (args and not re.fullmatch(r"[1-9][0-9]*", args[0])):
                print("Usage: ./logs.sh [positive line count]",
                      file=sys.stdout if args[0] in ("--help", "-h") else sys.stderr)
                return 0 if args[0] in ("--help", "-h") else 1
            return show_logs(host or Host(), args[0] if args else "50")
        if command in ("verify", "pin"):
            host = host or Host()
            # Pinning rewrites tracked files; verification only reads, so it stays available for diagnosis.
            if command == "pin" and not {"--help", "-h"} & set(args):
                require_unprivileged(host, "pin")
            # These scripts keep their own argument handling, guards and exit codes.
            return host.script(command + ".py", *args).returncode
        print(USAGE, file=sys.stderr)
        raise Fatal(f"unknown command {command!r}; see usage above.")
    except Fatal as error:
        print(f"\n{color(31, 'ERROR')}  {error}\n", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
