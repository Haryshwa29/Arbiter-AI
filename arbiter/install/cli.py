"""`python arbiter-x.y.z.pyz --install` and friends.

Lifecycle flags, all of which accept --dry-run:

    --install     first-time setup: dirs, config, databases, admin account,
                  boot service
    --upgrade     replace the installed .pyz with this one and restart
    --uninstall   remove app + service (asks separately before data)
    --status      where everything is and whether the service is running
"""

from __future__ import annotations

import argparse
import configparser
import secrets
import shutil
import subprocess
import sys
from argparse import Namespace
from pathlib import Path

from . import preflight, service
from .plan import WINDOWS, Layout, Plan, layout_for

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787
DEFAULT_MODEL = "qwen3.5:4b"

OLLAMA_HINT = {
    True: "  Windows:  winget install Ollama.Ollama",
    False: "  Linux:    see https://ollama.com/download  "
           "(download the installer, verify it, then run it)",
}


def running_archive() -> Path | None:
    """Path to the .pyz we are executing from, if any.

    When Arbiter runs from a source checkout instead (development), there is
    no archive to copy and install falls back to recording the checkout path.
    """
    arg0 = Path(sys.argv[0]).resolve()
    if arg0.suffix == ".pyz" and arg0.is_file():
        return arg0
    for entry in sys.path:
        p = Path(entry)
        if p.suffix == ".pyz" and p.is_file():
            return p.resolve()
    return None


def ask(question: str, default: bool = True, assume_yes: bool = False) -> bool:
    if assume_yes:
        return True
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        answer = input(question + suffix).strip().lower()
    except EOFError:
        return default
    if not answer:
        return default
    return answer in ("y", "yes")


def write_config(layout: Layout, host: str, port: int, backend: str,
                 model: str, events: str) -> None:
    cfg = configparser.ConfigParser()
    cfg["server"] = {"host": host, "port": str(port)}
    cfg["llm"] = {"backend": backend, "model": model}
    cfg["paths"] = {
        "data_dir": str(layout.data_dir),
        "memory_db": str(layout.memory_db),
        "audit_db": str(layout.audit_db),
        "iam_db": str(layout.iam_db),
        "events": events,
    }
    # Shadow mode on, response dry-run: the safe posture for a new install.
    # Nothing gets blocked until an operator has watched it for a while.
    cfg["policy"] = {"shadow_mode": "true", "respond": "dry-run",
                     "retention_days": "30"}
    layout.config_path.parent.mkdir(parents=True, exist_ok=True)
    layout.config_path.write_text(
        "# Arbiter configuration — edit and restart the service.\n"
        "# Written by the installer; safe to hand-edit.\n", encoding="utf-8")
    with layout.config_path.open("a", encoding="utf-8") as fh:
        cfg.write(fh)


def seed_databases(layout: Layout) -> None:
    from ..cli import cmd_seed

    cmd_seed(Namespace(db=str(layout.memory_db)))


def install_sample_events(layout: Layout) -> Path:
    """Copy the bundled sample events out of the archive into the data dir.

    The service runs with an unpredictable working directory, so every path
    written into the config must be absolute. Reading through `importlib`
    rather than the filesystem is what makes this work from inside the zipapp.
    """
    dest = layout.data_dir / "events.jsonl"
    if dest.exists():
        return dest
    try:
        import zipfile

        archive = running_archive()
        if archive:
            with zipfile.ZipFile(archive) as zf:
                data = zf.read("samples/events.jsonl")
        else:  # source checkout
            src = Path(__file__).resolve().parents[2] / "samples" / "events.jsonl"
            data = src.read_bytes()
    except (KeyError, OSError):
        # No samples available: leave the feeder pointed at a file the
        # operator will supply. Better an empty feed than a wrong path.
        dest.write_bytes(b"")
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return dest


def create_admin(layout: Layout) -> str | None:
    """Create the first admin account. Returns the password, or None if users exist."""
    from ..iam import IAM

    iam = IAM(str(layout.iam_db))
    try:
        if iam.any_users():
            return None
        password = secrets.token_urlsafe(12)
        iam.create_user("admin", password, "admin")
        return password
    finally:
        iam.close()


def build_install_plan(layout: Layout, args, archive: Path | None) -> tuple[Plan, dict]:
    """Assemble the install plan. `out` collects values to print at the end."""
    plan = Plan(f"Installing Arbiter ({layout.scope} scope) into {layout.app_dir}")
    out: dict = {}

    plan.add(
        f"create {len(layout.dirs())} directories (app, data, config, logs)",
        run=lambda: [d.mkdir(parents=True, exist_ok=True) for d in layout.dirs()],
    )

    if archive:
        plan.add(
            f"copy {archive.name} -> {layout.pyz_path}",
            run=lambda: shutil.copy2(archive, layout.pyz_path),
        )
    else:
        plan.add("(running from a source checkout — no archive to copy; skipping)")

    # Resolved before the config is written so the service gets an absolute
    # path — it starts with an unpredictable working directory.
    events_path = str(Path(args.events).expanduser().resolve()) if args.events \
        else str(layout.data_dir / "events.jsonl")
    if not args.events or not Path(args.events).exists():
        plan.add(
            f"install the bundled sample events to {layout.data_dir / 'events.jsonl'}",
            run=lambda: install_sample_events(layout),
        )
        events_path = str(layout.data_dir / "events.jsonl")
    out["events"] = events_path

    plan.add(
        f"write configuration to {layout.config_path}",
        run=lambda: write_config(layout, args.host, args.port, args.backend,
                                 args.model, events_path),
        skip_if=lambda: layout.config_path.exists() and not args.force,
    )

    plan.add(
        f"initialise and seed the memory database at {layout.memory_db}",
        run=lambda: seed_databases(layout),
        skip_if=lambda: layout.memory_db.exists(),
    )

    def _admin():
        out["admin_password"] = create_admin(layout)

    plan.add(
        "create the initial admin account (one-time password printed below)",
        run=_admin,
    )

    if args.backend == "ollama":
        plan.add(
            f"pull the local model {args.model!r} via Ollama "
            "(the only network call this installer makes)",
            run=lambda: subprocess.run(["ollama", "pull", args.model], check=False),
            skip_if=lambda: not preflight.ollama_present(),
        )

    if args.service:
        def _svc():
            out["service"] = service.install_service(
                layout, sys.executable, args.host, args.port, out["events"])

        plan.add("register Arbiter to start on boot", run=_svc)

    return plan, out


def cmd_install(args) -> int:
    layout = layout_for(args.scope, args.prefix)
    archive = running_archive()

    checks = preflight.run_checks(layout.data_dir, args.host, args.port)
    if not preflight.report(checks) and not args.dry_run:
        print("Preflight failed — fix the items marked FAIL and re-run.",
              file=sys.stderr)
        return 1

    if args.backend == "ollama" and not preflight.ollama_present():
        print("Ollama is not installed. Arbiter will run on the mock backend\n"
              "(deterministic heuristics — fine for a demo, not for real triage).\n"
              "To install it later:")
        print(OLLAMA_HINT[WINDOWS])
        print()
        if not args.dry_run and not ask("Continue with the mock backend?",
                                        assume_yes=args.yes):
            return 1
        args.backend = "mock"

    plan, out = build_install_plan(layout, args, archive)

    if args.dry_run:
        plan.render()
        print("Dry run — nothing was changed.")
        return 0

    plan.execute()

    print(f"Arbiter is installed.\n")
    print(f"  dashboard   http://{args.host}:{args.port}")
    print(f"  data        {layout.data_dir}")
    print(f"  config      {layout.config_path}")
    if out.get("service"):
        print(f"  service     {out['service']}")
    if out.get("admin_password"):
        print(f"\n  Sign in as    admin")
        print(f"  One-time pw   {out['admin_password']}")
        print("  Change this password after your first sign-in.")
    else:
        print("\n  An account already existed — your previous credentials still work.")
    return 0


def cmd_upgrade(args) -> int:
    layout = layout_for(args.scope, args.prefix)
    archive = running_archive()
    if archive is None:
        print("--upgrade must be run from a release .pyz", file=sys.stderr)
        return 1
    if not layout.app_dir.exists():
        print(f"No installation found at {layout.app_dir} — run --install first.",
              file=sys.stderr)
        return 1

    plan = Plan(f"Upgrading Arbiter at {layout.app_dir}")
    backup = layout.pyz_path.with_suffix(".pyz.previous")
    plan.add(f"back up current build to {backup.name}",
             run=lambda: shutil.copy2(layout.pyz_path, backup),
             skip_if=lambda: not layout.pyz_path.exists())
    plan.add(f"install {archive.name}",
             run=lambda: shutil.copy2(archive, layout.pyz_path))

    outcome: dict = {}
    plan.add("restart the service",
             run=lambda: outcome.__setitem__("restart",
                                             service.restart_service(layout)))
    # Databases are untouched: the memory DB is the analyst's learning and
    # must survive upgrades (invariant #4).
    plan.add("(databases left untouched — learned history survives upgrades)")

    if args.dry_run:
        plan.render()
        print("Dry run — nothing was changed.")
        return 0
    plan.execute()
    print(f"Upgraded to {__import__('arbiter').__version__}. "
          f"Service: {outcome.get('restart', 'unchanged')}.")
    print(f"Previous build kept as {backup.name} in case you need to roll back.")
    return 0


def cmd_uninstall(args) -> int:
    layout = layout_for(args.scope, args.prefix)
    plan = Plan(f"Removing Arbiter from {layout.app_dir}")
    plan.add("stop and deregister the boot service",
             run=lambda: service.remove_service(layout))
    plan.add(f"delete the application directory {layout.app_dir}",
             run=lambda: shutil.rmtree(layout.app_dir, ignore_errors=True))

    if args.dry_run:
        plan.render()
        print(f"Data at {layout.data_dir} would be kept unless you confirm removal.")
        print("Dry run — nothing was changed.")
        return 0

    plan.execute()

    # Asked separately and defaulting to "no": the memory DB holds everything
    # the analyst learned about this environment. Deleting it is not part of
    # "uninstall the program".
    print(f"Arbiter's data is still at {layout.data_dir}")
    print("  (memory database, audit history, accounts)")
    if args.purge or ask("Delete this data too?", default=False, assume_yes=False):
        shutil.rmtree(layout.data_dir, ignore_errors=True)
        layout.config_path.unlink(missing_ok=True)
        print("Data deleted.")
    else:
        print("Data kept. Re-installing later will pick it up again.")
    return 0


def cmd_status(args) -> int:
    layout = layout_for(args.scope, args.prefix)
    installed = layout.pyz_path.exists()
    print(f"\nArbiter status ({layout.scope} scope)\n")
    print(f"  installed   {'yes' if installed else 'no'}  {layout.pyz_path}")
    print(f"  config      {layout.config_path} "
          f"({'present' if layout.config_path.exists() else 'missing'})")
    for label, path in (("memory db", layout.memory_db),
                        ("audit db", layout.audit_db),
                        ("iam db", layout.iam_db)):
        size = f"{path.stat().st_size / 1024:.0f} KB" if path.exists() else "absent"
        print(f"  {label:11} {path} ({size})")
    print(f"  service     {service.service_status(layout)}")
    print()
    return 0 if installed else 1


def build_parser() -> argparse.ArgumentParser:
    from .. import __version__

    p = argparse.ArgumentParser(
        prog="arbiter.pyz",
        description="Install, upgrade or remove Arbiter "
                    f"(version {__version__}).",
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--install", action="store_true")
    mode.add_argument("--upgrade", action="store_true")
    mode.add_argument("--uninstall", action="store_true")
    mode.add_argument("--status", action="store_true")

    p.add_argument("--dry-run", action="store_true",
                   help="print every step without changing anything")
    p.add_argument("--scope", choices=["system", "user"], default=None,
                   help="default: system when run as root/admin, else user")
    p.add_argument("--prefix", default=None,
                   help="install everything under this directory instead of "
                        "the standard system paths (useful for testing)")
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--backend", choices=["mock", "ollama"], default="ollama")
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--events", default=None,
                   help="event source the dashboard feeder reads; defaults to "
                        "a copy of the bundled samples in the data directory")
    p.add_argument("--no-service", dest="service", action="store_false",
                   help="do not register a boot service")
    p.add_argument("--force", action="store_true",
                   help="overwrite existing configuration")
    p.add_argument("--purge", action="store_true",
                   help="with --uninstall, also delete data without asking")
    p.add_argument("--yes", "-y", action="store_true",
                   help="assume yes for prompts (non-interactive install)")
    p.add_argument("--version", action="version", version=f"arbiter {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.install:
        return cmd_install(args)
    if args.upgrade:
        return cmd_upgrade(args)
    if args.uninstall:
        return cmd_uninstall(args)
    return cmd_status(args)


if __name__ == "__main__":
    raise SystemExit(main())
