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
# (repository, the one file that references it, directive, the tag a refresh resolves).
# These are the images SafeBrowse pins. scripts/verify.py fails if a file in SOURCES has an
# image reference, in a form REFERENCE reads, that is not listed here, or if PINS.txt disagrees.
IMAGES = (("lscr.io/linuxserver/firefox", "Dockerfile", "FROM", "latest"),
          ("ubuntu/squid", "compose.services.yml", "image:", "latest"),
          ("alpine/socat", "compose.services.yml", "image:", "latest"),
          # A reviewed Gluetun release. Its :latest tag follows the development branch, so a
          # refresh re-resolves this tag; moving to another release means editing it here.
          ("qmcgaw/gluetun", "docker-compose.vpn.yml", "image:", "v3.41.3"))
# Every file that can name an image, and the image this repository builds itself.
SOURCES = ("Dockerfile", "compose.services.yml", "docker-compose.yml", "docker-compose.vpn.yml")
BUILT = ("safebrowse:latest",)
# The forms that are read: a line that starts, after spaces or tabs, with `FROM` (as written here, in
# capitals) or `image:`, followed by the reference. This is a line pattern, not a Dockerfile or YAML
# parser. It does not see a lower-case `from`, `COPY --from=`, a quoted or spaced key (`"image":`,
# `image :`), flow-style YAML, or a reference built from a variable, so it is a check on the reviewed
# files as they are written, not a guarantee that no other image can be named.
REFERENCE = re.compile(r"^[ \t]*(FROM|image:)[ \t]+(\S+)", re.M)
DIGEST = r"@sha256:[0-9a-f]{64}"


def resolve(repo, refresh, tag="latest"):
    name = repo + ":" + tag
    if refresh:
        print("Refreshing " + name, flush=True)
        subprocess.run(["docker", "pull", name], check=True)
    result = subprocess.run(["docker", "image", "inspect", name], check=True,
                            capture_output=True, text=True)
    refs = json.loads(result.stdout)[0].get("RepoDigests") or []
    matches = [r for r in refs if re.fullmatch(re.escape(repo) + DIGEST, r)]
    if len(matches) != 1:
        raise ValueError("Expected exactly one digest for " + name)
    return matches[0]


def rewrite(text, repo, directive, ref):
    pattern = (r"^(\s*" + re.escape(directive) + r"\s+)" + re.escape(repo) +
               r"(?::[\w.-]+|@sha256:[0-9a-f]{64})(\s*)$")
    text, count = re.subn(pattern, lambda m: m[1] + ref + m[2], text, flags=re.M)
    if count != 1:
        raise ValueError("Expected one image reference for " + repo)
    return text


def inventory(root):
    """What the repository pins: ({repository: digest reference or None}, recognised references outside IMAGES)."""
    found = [(name, match[1], match[2]) for name in SOURCES
             for match in REFERENCE.finditer((root / name).read_text(encoding="utf-8"))]
    pinned = {}
    for repo, name, directive, _ in IMAGES:
        refs = [ref for source, kind, ref in found if source == name and kind == directive
                and (ref == repo or ref.startswith((repo + ":", repo + "@")))]
        pinned[repo] = refs[0] if len(refs) == 1 and re.fullmatch(re.escape(repo) + DIGEST, refs[0]) else None
    expected = {(name, directive, repo) for repo, name, directive, _ in IMAGES}
    unlisted = sorted({ref for source, kind, ref in found if ref not in BUILT and not any(
        (source, kind, repo) in expected and (ref == repo or ref.startswith((repo + ":", repo + "@")))
        for repo, _, _, _ in IMAGES)})
    return pinned, unlisted


def manifest(refs):
    release = ", ".join(f"{repo} is held at release {tag}" for repo, _, _, tag in IMAGES if tag != "latest")
    return ("# Image digests; refresh deliberately with ./pin.sh --refresh, then rebuild and verify.\n"
            + (f"# {release}; change the release in scripts/pin.py.\n" if release else "")
            + "\n".join(refs) + "\n")


def pin(root, refresh):
    # Network/inspection/parsing failures leave all original files untouched.
    names = list(dict.fromkeys([name for _, name, _, _ in IMAGES] + ["PINS.txt"]))
    original = {name: (root / name).read_bytes() for name in names}
    updated = {name: data.decode() for name, data in original.items()}
    refs = []
    for repo, name, directive, tag in IMAGES:
        ref = resolve(repo, refresh, tag)
        updated[name] = rewrite(updated[name], repo, directive, ref)
        refs.append(ref)
    updated["PINS.txt"] = manifest(refs)
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
    parser.add_argument("--refresh", action="store_true",
                        help="pull every image's upstream tag (a fixed release for Gluetun) before resolving pins")
    args = parser.parse_args()
    try:
        pin(ROOT, args.refresh)
    except (OSError, ValueError, KeyError, IndexError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Pinning failed ({type(error).__name__}). Check Docker and the local image tags; use --refresh to fetch updates.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
