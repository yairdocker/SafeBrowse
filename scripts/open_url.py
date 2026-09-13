#!/usr/bin/env python3
"""Send one validated URL to the existing Firefox process without a shell."""
import argparse
import subprocess
import sys
from urllib.parse import urlsplit


def validate_url(value):
    try:
        if not value or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
            raise ValueError
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None:
            raise ValueError
        # Accessing port also rejects malformed and out-of-range port numbers.
        if parsed.port is not None and parsed.port == 0:
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError("URL must be an absolute HTTP(S) URL without credentials, whitespace or backslashes") from None
    return value


# docker exec's display defaults can differ from the running desktop. Read only
# the parent Firefox's display/session variables; never copy its credentials.
OPEN_PROBE = r'''import glob, os, subprocess, sys
keys = {b"DISPLAY", b"WAYLAND_DISPLAY", b"XDG_RUNTIME_DIR", b"DBUS_SESSION_BUS_ADDRESS", b"XAUTHORITY"}
for path in glob.glob("/proc/[0-9]*/cmdline"):
    try:
        args = open(path, "rb").read().replace(b"\0", b" ").split()
        if not args or b"firefox" not in os.path.basename(args[0]) or b"-contentproc" in args:
            continue
        if os.stat(path).st_uid != os.getuid():
            continue
        entries = open(path.replace("cmdline", "environ"), "rb").read().split(b"\0")
        display = dict(e.split(b"=", 1) for e in entries if b"=" in e and e.split(b"=", 1)[0] in keys)
        if b"DISPLAY" not in display and b"WAYLAND_DISPLAY" not in display:
            continue
        env = {"PATH": os.environ["PATH"], "HOME": "/config"}
        env.update({k.decode(): v.decode() for k, v in display.items()})
        result = subprocess.run(["firefox", "--new-tab", sys.argv[1]], env=env, timeout=15,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sys.exit(result.returncode)
    except (FileNotFoundError, ProcessLookupError):
        continue
sys.exit("No running Firefox desktop was found")
'''


def open_url(url, browser="safebrowse"):
    # The URL is a separate argv entry all the way into Firefox. It is never
    # interpolated into FIREFOX_CLI, shell code, or the Python probe source.
    return subprocess.run(["docker", "exec", "-i", "--user", "1000:1000", browser,
                           "python3", "-c", OPEN_PROBE, url],
                          capture_output=True, text=True, timeout=25).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true", help="validate without contacting Docker")
    parser.add_argument("--initialize", action="store_true", help="open a blank tab for startup probes")
    parser.add_argument("url", nargs="?", type=validate_url)
    args = parser.parse_args()
    if args.initialize and (args.url or args.validate):
        parser.error("--initialize cannot be combined with a URL or --validate")
    if not args.initialize and not args.url:
        parser.error("a URL is required")
    if args.validate:
        return 0
    try:
        code = open_url("about:blank" if args.initialize else args.url)
    except (OSError, subprocess.SubprocessError):
        code = 1
    if code:
        print("Could not open a tab in the running Firefox desktop.", file=sys.stderr)
    return 1 if code else 0


if __name__ == "__main__":
    sys.exit(main())
