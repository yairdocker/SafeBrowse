#!/usr/bin/env python3
"""Choose and persist an unused Docker subnet for the isolated bridge."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
RUNTIME = ROOT / ".runtime"
STATE = RUNTIME / "network.json"
SQUID = RUNTIME / "squid.conf"
SOURCE = ROOT / "gateway/squid.conf"
DEFAULT_ACL = re.compile(r"(?m)^acl sandbox src 172\.28\.0\.0/24(?=\s|$)")
POOLS = (ipaddress.ip_network("172.31.0.0/16"),
         ipaddress.ip_network("10.231.0.0/16"),
         ipaddress.ip_network("172.16.0.0/12"))


def docker_subnets():
    ids = subprocess.run(["docker", "network", "ls", "--quiet"], check=True,
                         capture_output=True, text=True).stdout.split()
    if not ids:
        return []
    networks = json.loads(subprocess.run(["docker", "network", "inspect", *ids], check=True,
                                         capture_output=True, text=True).stdout)
    return [ipaddress.ip_network(config["Subnet"], strict=False)
            for network in networks for config in (network.get("IPAM", {}).get("Config") or [])
            if config.get("Subnet")]


def choose(used, skipped=()):
    excluded = [network for network in (*used, *skipped) if network.version == 4]
    seen = set()
    for pool in POOLS:
        for candidate in pool.subnets(new_prefix=24):
            if candidate in seen:
                continue
            seen.add(candidate)
            if not any(candidate.overlaps(other) for other in excluded):
                return candidate
    raise RuntimeError("no unused private /24 is available for the sandbox")


def atomic_write(path, contents, mode):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=RUNTIME,
                                     prefix=".network-", delete=False) as file:
        temporary = Path(file.name)
        try:
            file.write(contents)
            file.flush()
            os.fchmod(file.fileno(), mode)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def squid_config(subnet):
    source = SOURCE.read_text()
    if len(DEFAULT_ACL.findall(source)) != 1:
        raise RuntimeError("expected exactly one sandbox source ACL in gateway/squid.conf")
    return DEFAULT_ACL.sub(f"acl sandbox src {subnet}", source)


def select(skipped=()):
    subnet = choose(docker_subnets(), skipped)
    if RUNTIME.is_symlink() or (RUNTIME.exists() and not RUNTIME.is_dir()):
        raise RuntimeError(".runtime must be a directory, not a symlink")
    RUNTIME.mkdir(mode=0o755, exist_ok=True)
    atomic_write(SQUID, squid_config(subnet), 0o644)
    atomic_write(STATE, json.dumps({"subnet": str(subnet)}) + "\n", 0o600)
    return subnet


def current():
    if RUNTIME.is_symlink() or STATE.is_symlink() or SQUID.is_symlink():
        raise RuntimeError("runtime network files must not be symlinks")
    data = json.loads(STATE.read_text())
    if set(data) != {"subnet"}:
        raise ValueError("invalid runtime network state")
    subnet = ipaddress.ip_network(data["subnet"], strict=True)
    if subnet.version != 4 or subnet.prefixlen != 24 or not any(subnet.subnet_of(pool) for pool in POOLS):
        raise ValueError("invalid runtime sandbox subnet")
    if SQUID.read_text() != squid_config(subnet):
        raise ValueError("runtime Squid configuration does not match the selected subnet")
    return subnet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("select", "current"))
    parser.add_argument("--skip", action="append", default=[], metavar="CIDR")
    args = parser.parse_args()
    if args.action == "current" and args.skip:
        parser.error("--skip applies only to select")
    try:
        skipped = [ipaddress.ip_network(value, strict=True) for value in args.skip]
        print(select(skipped) if args.action == "select" else current())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"network setup: {error}\n")


if __name__ == "__main__":
    main()
