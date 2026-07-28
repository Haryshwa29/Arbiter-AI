#!/bin/sh
# Arbiter bootstrap installer — Linux / macOS
#
# This script is deliberately short so you can read all of it before running
# it. It does four things:
#
#   1. checks for Python 3.10+
#   2. downloads the release zipapp and its SHA256SUMS from GitHub Releases
#   3. verifies the checksum
#   4. hands over to the real installer inside the zipapp
#
# It is NOT meant to be piped into a shell. Arbiter's own triage engine
# escalates `curl ... | sh` as an attack pattern, and we are not going to ask
# you to do something we flag as malicious. Download, read, then run:
#
#   curl -fsSLO https://github.com/Haryshwa29/arbiter/releases/latest/download/install.sh
#   less install.sh
#   sh install.sh
#
# Pass any extra flags straight through to the installer, e.g.:
#   sh install.sh --dry-run
#   sh install.sh --scope user --port 9000 --backend mock

set -eu

REPO="${ARBITER_REPO:-Haryshwa29/arbiter}"
BASE="${ARBITER_BASE_URL:-https://github.com/$REPO/releases/latest/download}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- 1. Python ---------------------------------------------------------------
find_python() {
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,10) else 1)' 2>/dev/null; then
        printf '%s' "$candidate"
        return 0
      fi
    fi
  done
  return 1
}

PYTHON="$(find_python)" || {
  say "Python 3.10 or newer is required and was not found."
  say ""
  say "Install it with your package manager, then re-run this script:"
  say "  Debian/Ubuntu   sudo apt install python3"
  say "  Fedora/RHEL     sudo dnf install python3"
  say "  Arch            sudo pacman -S python"
  say "  macOS           brew install python@3.12"
  exit 1
}
say "Using $("$PYTHON" --version 2>&1)"

# --- 2. Download -------------------------------------------------------------
fetch() {
  url="$1"; dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url"
  else
    die "neither curl nor wget is available"
  fi
}

say "Downloading Arbiter from $BASE ..."
fetch "$BASE/SHA256SUMS" "$WORKDIR/SHA256SUMS" || die "could not download SHA256SUMS"

# The checksum file names the exact artifact, so the version is discovered
# rather than hardcoded — this script keeps working across releases.
PYZ_NAME="$(awk '$2 ~ /\.pyz$/ { print $2; exit }' "$WORKDIR/SHA256SUMS")"
[ -n "$PYZ_NAME" ] || die "no .pyz listed in SHA256SUMS"

fetch "$BASE/$PYZ_NAME" "$WORKDIR/$PYZ_NAME" || die "could not download $PYZ_NAME"

# --- 3. Verify ---------------------------------------------------------------
EXPECTED="$(awk -v n="$PYZ_NAME" '$2 == n { print $1; exit }' "$WORKDIR/SHA256SUMS")"
ACTUAL="$("$PYTHON" - "$WORKDIR/$PYZ_NAME" <<'PYEOF'
import hashlib, sys
h = hashlib.sha256()
with open(sys.argv[1], "rb") as fh:
    for chunk in iter(lambda: fh.read(1 << 20), b""):
        h.update(chunk)
print(h.hexdigest())
PYEOF
)"

if [ "$EXPECTED" != "$ACTUAL" ]; then
  say "CHECKSUM MISMATCH — refusing to run this file."
  say "  expected $EXPECTED"
  say "  actual   $ACTUAL"
  say "The download was corrupted or tampered with. Nothing was installed."
  exit 1
fi
say "Checksum verified: $PYZ_NAME"

# --- 4. Hand off to the real installer ---------------------------------------
say ""
"$PYTHON" "$WORKDIR/$PYZ_NAME" --install "$@"
