#!/usr/bin/env python3
"""Resolve all images before rewriting any pins. Refresh is an explicit choice."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
IMAGES = (("lscr.io/linuxserver/firefox", "Dockerfile", "FROM"),
          ("ubuntu/squid", "docker-compose.yml", "image:"),
          ("alpine/socat", "docker-compose.yml", "image:"))


def resolve(repo, refresh):
    tag = repo + ":latest"
    if refresh:
        print("Refreshing " + tag, flush=True)
        subprocess.run(["docker", "pull", tag], check=True)
    result = subprocess.run(["docker", "image", "inspect", tag], check=True,
                            capture_output=True, text=True)
    refs = json.loads(result.stdout)[0].get("RepoDigests") or []
    matches = [r for r in refs if re.fullmatch(re.escape(repo) + r"@sha256:[0-9a-f]{64}", r)]
    if len(matches) != 1:
        raise ValueError("Expected exactly one digest for " + tag)
    return matches[0]


def rewrite(text, repo, directive, ref):
    pattern = (r"^(\s*" + re.escape(directive) + r"\s+)" + re.escape(repo) +
               r"(?::[\w.-]+|@sha256:[0-9a-f]{64})(\s*)$")
    text, count = re.subn(pattern, lambda m: m[1] + ref + m[2], text, flags=re.M)
    if count != 1:
        raise ValueError("Expected one image reference for " + repo)
    return text


def pin(root, refresh):
    # Network/inspection/parsing failures leave all original files untouched.
    original = {name: (root / name).read_bytes() for name in ("Dockerfile", "docker-compose.yml", "PINS.txt")}
    updated = {name: data.decode() for name, data in original.items()}
    refs = []
    for repo, name, directive in IMAGES:
        ref = resolve(repo, refresh)
        updated[name] = rewrite(updated[name], repo, directive, ref)
        refs.append(ref)
    updated["PINS.txt"] = "# Image digests; refresh deliberately with ./pin.sh --refresh, then rebuild and verify.\n" + "\n".join(refs) + "\n"
    staged = {}
    replaced = []
    try:
        for name, text in updated.items():
            with tempfile.NamedTemporaryFile(dir=root, prefix=".pin-", delete=False) as f:
                staged[name] = Path(f.name)
                f.write(text.encode())
            os.chmod(staged[name], (root / name).stat().st_mode & 0o777)
        for name, path in staged.items():
            if (root / name).read_bytes() != original[name]:
                raise RuntimeError("File changed during pinning: " + name)
            os.replace(path, root / name)
            replaced.append(name)
    except Exception:
        for name in replaced:
            (root / name).write_bytes(original[name])
        raise
    finally:
        for path in staged.values():
            path.unlink(missing_ok=True)
    print("Image pins recorded. Running containers have not changed.")
    print("Next: ./run.sh, open a page, then ./verify.sh. Review the diff before committing.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", action="store_true", help="pull every upstream :latest before resolving pins")
    args = parser.parse_args()
    try:
        pin(ROOT, args.refresh)
    except (OSError, ValueError, KeyError, IndexError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Pinning failed ({type(error).__name__}). Check Docker and local :latest images; use --refresh to fetch updates.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
