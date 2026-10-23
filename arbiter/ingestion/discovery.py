"""Local read-only discovery. No download, scanning or installation at runtime."""
import os
import platform
from pathlib import Path

from .collectors.windows import WindowsCollector, SYSMON_CHANNEL, channel_installed
from .collectors.defender import CHANNEL


def discover_local():
    if os.name != "nt":
        return {"attachments": {"interval": 15}} if platform.system() == "Linux" else {}
    found = {"windows_security": {"interval": 300}, "attachments": {"interval": 15}}
    probe = WindowsCollector({"adapter": "windows"})
    channels = []
    for name in ("System", "Application", "Security", SYSMON_CHANNEL, CHANNEL):
        try:
            probe._query(name, newest=True)
        except (OSError, ValueError):
            if name == SYSMON_CHANNEL and channel_installed(name):
                found["sysmon"] = {"read_existing": False}
            continue
        if name == SYSMON_CHANNEL:
            found["sysmon"] = {"read_existing": False}
        elif name == CHANNEL:
            found["defender"] = {"read_existing": False}
        else:
            channels.append(name)
    if channels:
        found["windows"] = {"channels": channels, "read_existing": False}
    candidates = []
    for variable, suffix in (("ProgramFiles", "osquery/osqueryi.exe"),
                             ("ProgramFiles", "osquery/osqueryi/osqueryi.exe"),
                             ("ProgramFiles", "Arbiter/tools/osquery/osqueryi.exe"),
                             ("LOCALAPPDATA", "Arbiter/tools/osquery/osqueryi.exe")):
        root = os.environ.get(variable)
        if root:
            candidates.append(Path(root) / suffix)
    # Elevated/system runtimes never execute tools from user-writable folders.
    from .permissions import is_elevated
    if is_elevated():
        local_root = os.environ.get("LOCALAPPDATA")
        if local_root:
            candidates = [p for p in candidates if not p.is_relative_to(Path(local_root))]
    for path in candidates:
        if path.is_file():
            found["osquery"] = {"path": str(path.resolve()), "interval": 300}
            break
    return found
