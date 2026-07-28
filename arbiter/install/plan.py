"""Install layout and the executable plan primitive.

A `Plan` is an ordered list of `Action`s. Each Action carries a human
sentence describing what it will do; `--dry-run` prints those sentences and
executes nothing. This is why the dry run can be trusted to match the real
run: both walk the same list, the only difference is whether `.run()` is
called.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

WINDOWS = platform.system() == "Windows"
MACOS = platform.system() == "Darwin"


@dataclass
class Layout:
    """Where Arbiter's files live on this machine."""

    scope: str          # "system" or "user"
    app_dir: Path       # the .pyz and any static assets
    data_dir: Path      # SQLite DBs, audit JSONL — the state worth keeping
    config_path: Path
    log_dir: Path

    @property
    def pyz_path(self) -> Path:
        return self.app_dir / "arbiter.pyz"

    @property
    def memory_db(self) -> Path:
        # Never pruned; this is the analyst's accumulated learning.
        return self.data_dir / "arbiter_memory.db"

    @property
    def audit_db(self) -> Path:
        return self.data_dir / "arbiter_audit.db"

    @property
    def iam_db(self) -> Path:
        return self.data_dir / "arbiter_iam.db"

    def dirs(self) -> list[Path]:
        return [self.app_dir, self.data_dir, self.log_dir, self.config_path.parent]


def _is_admin() -> bool:
    if WINDOWS:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def layout_for(scope: str | None = None, prefix: str | Path | None = None) -> Layout:
    """Resolve the install layout.

    `scope=None` picks "system" when running with admin/root, else "user" —
    a non-admin install is a first-class path, not a failure, so that
    evaluating Arbiter never requires handing it root.
    """
    if scope is None:
        scope = "system" if _is_admin() else "user"

    if prefix is not None:
        # Used by tests and by `--prefix` for sandboxed installs: everything
        # under one root, no system paths touched.
        root = Path(prefix).expanduser().resolve()
        return Layout(
            scope=scope,
            app_dir=root / "app",
            data_dir=root / "data",
            config_path=root / "config" / "arbiter.conf",
            log_dir=root / "logs",
        )

    if WINDOWS:
        if scope == "system":
            program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
            base = program_data / "Arbiter"
            return Layout(scope, base / "app", base / "data",
                          base / "config" / "arbiter.conf", base / "logs")
        local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        base = local / "Arbiter"
        return Layout(scope, base / "app", base / "data",
                      base / "config" / "arbiter.conf", base / "logs")

    if scope == "system":
        return Layout(scope, Path("/opt/arbiter"), Path("/var/lib/arbiter"),
                      Path("/etc/arbiter/arbiter.conf"), Path("/var/log/arbiter"))

    xdg_data = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    xdg_conf = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    base = xdg_data / "arbiter"
    return Layout(scope, base / "app", base / "data",
                  xdg_conf / "arbiter" / "arbiter.conf", base / "logs")


@dataclass
class Action:
    """One install step: a sentence plus the code that fulfils it."""

    describe: str
    run: Callable[[], None] | None = None
    # Steps that are safe to skip when re-running an install.
    skip_if: Callable[[], bool] | None = None

    def should_skip(self) -> bool:
        return bool(self.skip_if and self.skip_if())


@dataclass
class Plan:
    title: str
    actions: list[Action] = field(default_factory=list)

    def add(self, describe: str, run=None, skip_if=None) -> None:
        self.actions.append(Action(describe, run, skip_if))

    def render(self, stream=sys.stdout) -> None:
        print(f"\n{self.title}\n", file=stream)
        for i, a in enumerate(self.actions, 1):
            mark = "skip" if a.should_skip() else "  do"
            print(f"  {i:2}. [{mark}] {a.describe}", file=stream)
        print(file=stream)

    def execute(self, stream=sys.stdout) -> None:
        print(f"\n{self.title}\n", file=stream)
        for i, a in enumerate(self.actions, 1):
            if a.should_skip():
                print(f"  {i:2}. skipped  {a.describe}", file=stream)
                continue
            print(f"  {i:2}. {a.describe} ... ", end="", flush=True, file=stream)
            if a.run:
                a.run()
            print("ok", file=stream)
        print(file=stream)
