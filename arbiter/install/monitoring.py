"""Explicit provisioning entrypoint; packaged script is inspectable and local."""
import importlib.resources
import os
from pathlib import Path
import subprocess
import tempfile


def setup_monitoring(args):
    if os.name != "nt":
        raise ValueError("managed tool provisioning currently supports Windows x64")
    # Resources also work from inside the release zipapp.
    content = importlib.resources.files("arbiter.install").joinpath("setup-monitoring.ps1").read_bytes()
    with tempfile.TemporaryDirectory(prefix="arbiter-monitoring-") as directory:
        path = Path(directory) / "setup-monitoring.ps1"
        path.write_bytes(content)
        flags = ["-InventoryOnly"] if args.inventory_only else []
        result = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                                 "-File", str(path), *flags])
        if result.returncode:
            raise SystemExit(result.returncode)
