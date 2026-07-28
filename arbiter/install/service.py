"""Register Arbiter to start on boot.

Linux  -> systemd unit (system unit as root, `--user` unit otherwise)
Windows -> Task Scheduler task (ONSTART for system, ONLOGON for user)

Task Scheduler is chosen over a real Windows service deliberately: a true
service needs a wrapper (NSSM/pywin32), and the stdlib-only rule applies to
install-time dependencies too. A scheduled task that launches at boot and
restarts on failure is enough for the dashboard, and it is inspectable with
`schtasks /Query /TN Arbiter`.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .plan import WINDOWS, Layout

SERVICE_NAME = "arbiter"
TASK_NAME = "Arbiter"

UNIT_TEMPLATE = """\
[Unit]
Description=Arbiter — self-hosted AI security analyst
Documentation=https://github.com/Haryshwa29/arbiter
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_start}
WorkingDirectory={data_dir}
Restart=on-failure
RestartSec=5
# Least privilege: the dashboard reads its own SQLite files and nothing else.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={data_dir} {log_dir}

[Install]
WantedBy={wanted_by}
"""


def serve_argv(layout: Layout, python: str, host: str, port: int,
               events: str) -> list[str]:
    """The exact command the service runs. Shared by every platform.

    Note the argument order: `--db` is a *global* option on the arbiter CLI
    and must appear before the `serve` subcommand, not after it.
    """
    return [
        python, str(layout.pyz_path),
        "--db", str(layout.memory_db),
        "serve",
        "--host", host, "--port", str(port),
        "--store-db", str(layout.audit_db),
        "--iam-db", str(layout.iam_db),
        "--events", events,
    ]


def unit_text(layout: Layout, python: str, host: str, port: int,
              events: str) -> str:
    # Derived from serve_argv so the unit and the Windows task can never
    # disagree about how Arbiter is launched.
    exec_start = " ".join(serve_argv(layout, python, host, port, events))
    return UNIT_TEMPLATE.format(
        exec_start=exec_start,
        data_dir=layout.data_dir, log_dir=layout.log_dir,
        wanted_by="multi-user.target" if layout.scope == "system" else "default.target",
    )


def unit_path(layout: Layout) -> Path:
    if layout.scope == "system":
        return Path("/etc/systemd/system") / f"{SERVICE_NAME}.service"
    return Path.home() / ".config" / "systemd" / "user" / f"{SERVICE_NAME}.service"


def systemd_available() -> bool:
    return shutil.which("systemctl") is not None and Path("/run/systemd/system").exists()


def _systemctl(layout: Layout, *args: str) -> None:
    cmd = ["systemctl"]
    if layout.scope != "system":
        cmd.append("--user")
    cmd.extend(args)
    subprocess.run(cmd, check=True)


def install_service(layout: Layout, python: str, host: str, port: int,
                    events: str) -> str:
    """Register the service. Returns a sentence describing what happened."""
    if WINDOWS:
        argv = serve_argv(layout, python, host, port, events)
        quoted = " ".join(f'\\"{a}\\"' if " " in str(a) else str(a) for a in argv)
        cmd = ["schtasks", "/Create", "/F", "/TN", TASK_NAME,
               "/TR", quoted,
               "/SC", "ONSTART" if layout.scope == "system" else "ONLOGON"]
        if layout.scope == "system":
            cmd += ["/RU", "SYSTEM", "/RL", "HIGHEST"]
        subprocess.run(cmd, check=True, capture_output=True)
        return f"scheduled task {TASK_NAME!r} created"

    if not systemd_available():
        return ("systemd not available — start Arbiter manually with:\n      "
                + " ".join(serve_argv(layout, python, host, port, events)))

    path = unit_path(layout)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(unit_text(layout, python, host, port, events), encoding="utf-8")
    _systemctl(layout, "daemon-reload")
    _systemctl(layout, "enable", "--now", f"{SERVICE_NAME}.service")
    return f"systemd unit written to {path} and enabled"


def restart_service(layout: Layout) -> str:
    """Best-effort restart.

    Never raises: an upgrade that has already swapped the binary must not be
    reported as failed just because there is no service registered (a
    `--no-service` install, or a machine without systemd). The caller prints
    what happened so the operator can start it themselves.
    """
    if WINDOWS:
        subprocess.run(["schtasks", "/End", "/TN", TASK_NAME], capture_output=True)
        r = subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME],
                           capture_output=True)
        return ("restarted" if r.returncode == 0
                else "no scheduled task registered — start Arbiter yourself")
    if not systemd_available():
        return "systemd unavailable — start Arbiter yourself"
    if not unit_path(layout).exists():
        return "no service registered — start Arbiter yourself"
    try:
        _systemctl(layout, "restart", f"{SERVICE_NAME}.service")
        return "restarted"
    except (subprocess.CalledProcessError, OSError) as e:
        return f"could not restart automatically ({e}) — start Arbiter yourself"


def remove_service(layout: Layout) -> None:
    if WINDOWS:
        subprocess.run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME],
                       capture_output=True)
        return
    if not systemd_available():
        return
    subprocess.run(
        ["systemctl"] + ([] if layout.scope == "system" else ["--user"])
        + ["disable", "--now", f"{SERVICE_NAME}.service"],
        capture_output=True,
    )
    unit_path(layout).unlink(missing_ok=True)
    subprocess.run(
        ["systemctl"] + ([] if layout.scope == "system" else ["--user"])
        + ["daemon-reload"],
        capture_output=True,
    )


def service_status(layout: Layout) -> str:
    if WINDOWS:
        r = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME],
                           capture_output=True, text=True)
        return "registered" if r.returncode == 0 else "not registered"
    if not systemd_available():
        return "systemd unavailable"
    r = subprocess.run(
        ["systemctl"] + ([] if layout.scope == "system" else ["--user"])
        + ["is-active", f"{SERVICE_NAME}.service"],
        capture_output=True, text=True,
    )
    return r.stdout.strip() or "unknown"
