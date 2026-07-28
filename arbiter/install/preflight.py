"""Preflight checks — refuse to install onto a machine that can't run it.

Each check returns a `Check`: ok/warn/fail plus a sentence the operator can
act on. Failures stop the install; warnings are printed and continue, because
a warning here ("only 6 GB RAM — pick a smaller model") is guidance, not a
blocker.
"""

from __future__ import annotations

import platform
import shutil
import socket
import sys
from dataclasses import dataclass
from pathlib import Path

MIN_PYTHON = (3, 10)
MIN_DISK_MB = 500
# Rough floor for a 4B-parameter local model at q4; below this, MockBackend
# or a smaller model is the honest recommendation.
RECOMMENDED_RAM_GB = 8


@dataclass
class Check:
    name: str
    status: str  # "ok" | "warn" | "fail"
    detail: str


def _total_ram_gb() -> float | None:
    try:
        if platform.system() == "Linux":
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) / (1024 * 1024)
        elif platform.system() == "Windows":
            import ctypes

            class MemoryStatusEx(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong),
                            ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

            stat = MemoryStatusEx()
            stat.dwLength = ctypes.sizeof(MemoryStatusEx)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            return stat.ullTotalPhys / (1024 ** 3)
    except Exception:
        return None
    return None


def port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) != 0


def ollama_present() -> bool:
    return shutil.which("ollama") is not None


def run_checks(data_dir: Path, host: str, port: int) -> list[Check]:
    checks: list[Check] = []

    v = sys.version_info
    checks.append(Check(
        "python",
        "ok" if v[:2] >= MIN_PYTHON else "fail",
        f"{v.major}.{v.minor}.{v.micro} (need >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})",
    ))

    probe = data_dir
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    try:
        free_mb = shutil.disk_usage(probe).free / (1024 * 1024)
        checks.append(Check(
            "disk",
            "ok" if free_mb >= MIN_DISK_MB else "fail",
            f"{free_mb:.0f} MB free at {probe} (need >= {MIN_DISK_MB} MB; "
            f"a local model needs several GB more)",
        ))
    except OSError as e:
        checks.append(Check("disk", "warn", f"could not measure free space: {e}"))

    ram = _total_ram_gb()
    if ram is None:
        checks.append(Check("memory", "warn", "could not determine total RAM"))
    else:
        checks.append(Check(
            "memory",
            "ok" if ram >= RECOMMENDED_RAM_GB else "warn",
            f"{ram:.1f} GB total"
            + ("" if ram >= RECOMMENDED_RAM_GB
               else f" — under {RECOMMENDED_RAM_GB} GB, prefer a smaller model "
                    "or the mock backend"),
        ))

    checks.append(Check(
        "port",
        "ok" if port_free(host, port) else "fail",
        f"{host}:{port} " + ("available" if port_free(host, port)
                             else "already in use — pass --port"),
    ))

    checks.append(Check(
        "ollama",
        "ok" if ollama_present() else "warn",
        "found on PATH" if ollama_present()
        else "not installed — Arbiter will run on the mock backend "
             "(heuristics only) until you install it",
    ))

    return checks


def report(checks: list[Check], stream=sys.stdout) -> bool:
    """Print the checks. Returns False if any check failed."""
    print("Preflight:", file=stream)
    glyph = {"ok": "ok  ", "warn": "warn", "fail": "FAIL"}
    for c in checks:
        print(f"  [{glyph[c.status]}] {c.name:8} {c.detail}", file=stream)
    print(file=stream)
    return not any(c.status == "fail" for c in checks)
