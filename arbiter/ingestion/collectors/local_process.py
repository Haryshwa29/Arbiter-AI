"""Read-only process/network snapshots for an already-running compromise."""
import base64
import ipaddress
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import socket
import subprocess
import time

from ..base import Collector
from ..schema import SecurityEvent, safe_json


WINDOWS_SNAPSHOT = r"""
$ErrorActionPreference = 'Stop'
$p = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.CreationDate } | ForEach-Object {
 @{pid=[string]$_.ProcessId;created=[string]$_.CreationDate.ToUniversalTime().Ticks;
 cpu=([double]$_.KernelModeTime+[double]$_.UserModeTime)/10000000;
 path=[string]$_.ExecutablePath;command=[string]$_.CommandLine}
})
$c = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -in @('Established','SynSent') } | ForEach-Object {
 @{pid=[string]$_.OwningProcess;remote=[string]$_.RemoteAddress;port=[int]$_.RemotePort}
})
@{processes=$p;connections=$c} | ConvertTo-Json -Depth 4 -Compress
"""


def windows_snapshot():
    encoded = base64.b64encode(WINDOWS_SNAPSHOT.encode("utf-16le")).decode("ascii")
    executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run([str(executable), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                            capture_output=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode or len(result.stdout) > 8 * 1024 * 1024:
        raise OSError("local process/network snapshot unavailable")
    return safe_json(result.stdout.decode("utf-8-sig"))


def linux_snapshot(root=Path("/proc")):
    connections = {}
    for name, ipv6 in (("tcp", False), ("tcp6", True)):
        try:
            lines = (root / "net" / name).read_text().splitlines()[1:]
        except FileNotFoundError:
            continue
        for line in lines:
            fields = line.split()
            if fields[3] not in {"01", "02"}: continue  # established or SYN sent
            host, port = fields[2].split(":")
            packed = bytes.fromhex(host)
            packed = b"".join(packed[i:i+4][::-1] for i in range(0, len(packed), 4))
            remote = socket.inet_ntop(socket.AF_INET6 if ipv6 else socket.AF_INET, packed)
            connections.setdefault(fields[9], []).append({"remote": remote, "port": int(port, 16)})
    processes, peers = [], []
    ticks = os.sysconf("SC_CLK_TCK")
    for directory in root.iterdir():
        if not directory.name.isdigit(): continue
        try:
            fields = (directory / "stat").read_text().rsplit(")", 1)[1].split()
            path = os.readlink(directory / "exe").removesuffix(" (deleted)")
            command = (directory / "cmdline").read_bytes()[:32768].replace(b"\0", b" ").decode("utf-8", errors="replace")
            processes.append({"pid": directory.name, "created": fields[19], "path": path,
                              "cpu": (int(fields[11]) + int(fields[12])) / ticks, "command": command})
            for descriptor in (directory / "fd").iterdir():
                try:
                    link = os.readlink(descriptor)
                except OSError:
                    continue
                if link.startswith("socket:["):
                    for connection in connections.get(link[8:-1], []):
                        peers.append({"pid": directory.name, **connection})
        except (OSError, ValueError, IndexError):
            continue  # exited/inaccessible processes are not fabricated
    return {"processes": processes, "connections": peers}


def temporary_executable(path):
    """A narrow location signal, never a verdict by itself."""
    windows = PureWindowsPath(path)
    if windows.drive:
        parts = tuple(part.casefold() for part in windows.parts[:-1])
        return ("temp" in parts or "tmp" in parts) and not str(path).startswith("\\\\")
    parts = PurePosixPath(path).parts
    return parts[:2] == ("/", "tmp") or parts[:3] in {("/", "var", "tmp"), ("/", "dev", "shm")}


class LocalProcessCollector(Collector):
    interval = 5.0

    def __init__(self, config, checkpoint=None):
        super().__init__(config, checkpoint)
        self.previous = {}
        self.high = {}
        self.sampled = None
        self.observed_processes = 0

    def snapshot(self):
        if platform.system() == "Windows": return windows_snapshot()
        if platform.system() == "Linux": return linux_snapshot()
        raise OSError("unsupported local process snapshot")

    def normalize(self, event):
        return event

    def health(self):
        return {**super().health(), "observed_processes": self.observed_processes,
                "coverage": "Readable processes only; needs two CPU intervals and a temporary-path executable with a TCP peer"}

    def collect(self):
        data = self.snapshot()
        sampled = time.monotonic()
        elapsed = sampled - self.sampled if self.sampled is not None else 0
        processes = data["processes"]
        self.observed_processes = len(processes)
        previous, high = {}, {}
        events = []
        for process in processes:
            key = (process["pid"], process["created"], process["path"])
            cpu = float(process["cpu"])
            previous[key] = cpu
            if key not in self.previous or elapsed <= 0: continue
            usage = 100 * (cpu - self.previous[key]) / elapsed
            if usage < 70 or not temporary_executable(process["path"]): continue
            high[key] = self.high.get(key, 0) + 1
            if high[key] < 2: continue
            remotes = {(c["remote"], c["port"]) for c in data["connections"] if c["pid"] == process["pid"]}
            for remote, port in sorted(remotes):
                address = ipaddress.ip_address(remote)
                if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local: continue
                events.append(SecurityEvent(source_type="local_process", hostname=socket.gethostname(),
                    event_type="process_network_risk", event_category="process", severity=8,
                    process_id=process["pid"], process_name=process["path"],
                    command_line=process.get("command", "")[:16000], dst_ip=remote, dst_port=port,
                    message=f"Temporary-path executable consumed {usage:.0f}% of one CPU core across repeated samples and has TCP activity to {remote}:{port}; operator review required",
                    metadata={"normalized_by": "local_process", "cpu_percent_one_core": usage,
                              "consecutive_high_samples": high[key], "process_created": process["created"]}))
        # Update sampling state only after all yielded events are enqueued.
        for event in events: yield event
        self.previous, self.high, self.sampled = previous, high, sampled
