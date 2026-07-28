#!/usr/bin/env python3
"""Build the Arbiter release artifacts.

Produces, in dist/:

    arbiter-<version>.pyz   the whole product as one runnable zipapp
    install.sh              Linux/macOS bootstrap (copied from packaging/)
    install.ps1             Windows bootstrap (copied from packaging/)
    SHA256SUMS              checksums for all of the above

The zipapp is deliberately a *transparent* artifact: it is a plain zip of
readable Python source (ADR-002). `unzip -l arbiter-x.y.z.pyz` shows every
file that will run on the customer's machine. No compiled blob, nothing
hidden — that inspectability is the product argument.

Usage:
    python tools/build_release.py [--out dist] [--clean]
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "arbiter"
PACKAGING = ROOT / "packaging"

# Everything the shipped artifact does NOT need. Keeping this explicit (rather
# than shipping the whole tree) means the release contains only runtime code.
EXCLUDE_DIRS = {"__pycache__", ".git", ".github", "tests", "dist", "build"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo", ".db", ".db-journal", ".jsonl"}

# The web frontend was removed on 2026-07-26 for a from-scratch rebuild, so
# there is no compiled front end to bundle. When the new frontend + server
# land, reinstate a build-output check here.

# Top-level __main__.py for the zipapp. Routes lifecycle flags to the
# installer and everything else to the normal CLI, so one artifact is both
# "the installer" and "the product".
LAUNCHER = '''\
"""Arbiter zipapp entry point (built by tools/build_release.py)."""
import sys

INSTALL_FLAGS = {"--install", "--upgrade", "--uninstall", "--status"}

if INSTALL_FLAGS & set(sys.argv[1:]):
    from arbiter.install.cli import main
else:
    from arbiter.cli import main

raise SystemExit(main())
'''


def read_version() -> str:
    """Single source of truth: arbiter/__init__.py __version__."""
    text = (PKG / "__init__.py").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("__version__"):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit("could not find __version__ in arbiter/__init__.py")


def stage_source(stage: Path) -> int:
    """Copy the runtime package into the staging dir. Returns file count."""
    count = 0
    for src in sorted(PKG.rglob("*")):
        rel = src.relative_to(PKG)
        if any(part in EXCLUDE_DIRS for part in rel.parts):
            continue
        if src.is_dir():
            continue
        if src.suffix in EXCLUDE_SUFFIXES:
            continue
        dest = stage / "arbiter" / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        count += 1
    # Sample events ship too: they make `--install` able to demo immediately
    # on a machine with no log collector wired up yet.
    samples = ROOT / "samples"
    if samples.is_dir():
        for src in sorted(samples.glob("*.jsonl")):
            dest = stage / "samples" / src.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
            count += 1
    (stage / "__main__.py").write_text(LAUNCHER, encoding="utf-8")
    return count + 1


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="build Arbiter release artifacts")
    ap.add_argument("--out", default="dist", help="output directory")
    ap.add_argument("--clean", action="store_true", help="wipe the output dir first")
    args = ap.parse_args()

    version = read_version()

    out = (ROOT / args.out).resolve()
    if args.clean and out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    stage = out / ".stage"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    n = stage_source(stage)
    pyz = out / f"arbiter-{version}.pyz"
    if pyz.exists():
        pyz.unlink()
    # No shebang: the bootstrap scripts always invoke it as
    # `python arbiter-x.y.z.pyz`, which works identically on Windows.
    zipapp.create_archive(stage, target=pyz, compressed=True)
    shutil.rmtree(stage)

    artifacts = [pyz]
    for name in ("install.sh", "install.ps1"):
        src = PACKAGING / name
        if src.exists():
            dest = out / name
            shutil.copy2(src, dest)
            artifacts.append(dest)
        else:
            print(f"  warning: {src} missing, not included", file=sys.stderr)

    sums = out / "SHA256SUMS"
    sums.write_text(
        "".join(f"{sha256(a)}  {a.name}\n" for a in artifacts), encoding="utf-8"
    )

    print(f"Arbiter {version} — {n} source files -> {pyz.name} "
          f"({pyz.stat().st_size / 1024:.0f} KB)")
    for a in artifacts:
        print(f"  {a.name}")
    print(f"  SHA256SUMS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
