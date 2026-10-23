"""Passive attachment and local network-edge observations; no probes or actuators."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import re
import socket
import subprocess

from ..base import Collector
from ..schema import SecurityEvent, safe_json

LIMIT = 1024
CATEGORIES = ("devices", "interfaces", "neighbors", "executions", "connections")
COVERAGE = ("Passive local observations, not a vulnerability scan. USB/Bluetooth enumeration, "
            "active adapters, cached IPv4 neighbors and readable removable-drive executions. "
            "TCP edges are observed only for cached neighbors. No phone internals, USB file scan, "
            "Bluetooth traffic inspection, full network visibility or automatic blocking. "
            "Attachments shorter than the polling interval may be missed.")

WINDOWS_SNAPSHOT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$result = @{}; $errors = @{}
try {
 $result.devices = @(Get-PnpDevice -PresentOnly -ErrorAction Stop | Where-Object {
  $_.InstanceId -match '^(USB\\|BTHENUM\\|BTHLEDEVICE\\)'
 } | ForEach-Object { @{id=[string]$_.InstanceId;name=[string]$_.FriendlyName;class=[string]$_.Class;status=[string]$_.Status} })
} catch { $errors.devices = 'Device enumeration unavailable' }
try {
 $result.interfaces = @(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up' | ForEach-Object {
  @{id=[string]$_.ifIndex;name=[string]$_.Name;description=[string]$_.InterfaceDescription;mac=[string]$_.MacAddress}
 })
} catch { $errors.interfaces = 'Adapter enumeration unavailable' }
try {
 $result.neighbors = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
  $_.State -in @('Reachable','Stale','Delay','Probe','Permanent')
 } | ForEach-Object { @{ip=[string]$_.IPAddress;mac=[string]$_.LinkLayerAddress;interface=[string]$_.ifIndex} })
} catch { $errors.neighbors = 'Neighbor cache unavailable' }
try {
 $usbNumbers = @(Get-Disk -ErrorAction Stop | Where-Object BusType -eq 'USB' | Select-Object -ExpandProperty Number)
 $mounts = @(Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Where-Object {
  $_.InterfaceType -eq 'USB' -or $_.Index -in $usbNumbers
 } | ForEach-Object {
  Get-CimAssociatedInstance -InputObject $_ -Association Win32_DiskDriveToDiskPartition -ErrorAction Stop | ForEach-Object {
   Get-CimAssociatedInstance -InputObject $_ -Association Win32_LogicalDiskToPartition -ErrorAction Stop | ForEach-Object { [string]$_.DeviceID + '\' }
  }
 })
 $result.executions = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object ExecutablePath | ForEach-Object {
  $process = $_
  foreach ($mount in $mounts) {
   if ($process.ExecutablePath.StartsWith($mount,[System.StringComparison]::OrdinalIgnoreCase)) {
    @{id=([string]$process.ProcessId + ':' + [string]$process.CreationDate);pid=[string]$process.ProcessId;path=[string]$process.ExecutablePath;mount=$mount}
    break
   }
  }
 })
} catch { $errors.executions = 'USB disk/process enumeration unavailable' }
try {
 $result.connections = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object State -eq 'Established' | ForEach-Object {
  @{remote=[string]$_.RemoteAddress;port=[int]$_.RemotePort;local_port=[int]$_.LocalPort;pid=[string]$_.OwningProcess}
 })
} catch { $errors.connections = 'TCP snapshot unavailable' }
$result.errors = $errors
$result | ConvertTo-Json -Depth 6 -Compress
"""


def windows_command():
    executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    return [str(executable), "-NoProfile", "-NonInteractive", "-Command", WINDOWS_SNAPSHOT]


def windows_snapshot():
    result = subprocess.run(windows_command(),
        capture_output=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode or len(result.stdout) > 8 * 1024 * 1024:
        raise OSError("attachment snapshot unavailable")
    return safe_json(result.stdout.decode("utf-8-sig"))


def beneath(path, mount):
    """Component boundary, not a substring (E:\\ is not E-other)."""
    kind = PureWindowsPath if PureWindowsPath(mount).drive else PurePosixPath
    try:
        kind(path).relative_to(kind(mount))
        return True
    except ValueError:
        return False


def linux_snapshot(sys_root=Path("/sys"), proc_root=Path("/proc")):
    result = {"errors": {}}
    def read(path):
        return path.read_text().strip()[:512]
    try:
        devices = []
        for device in (sys_root / "bus/usb/devices").iterdir():
            if not (device / "idVendor").is_file():
                continue
            devices.append({"id": device.name, "name": read(device / "product") if (device / "product").exists() else "USB device",
                "vendor": read(device / "idVendor"), "product": read(device / "idProduct"),
                "serial": read(device / "serial") if (device / "serial").exists() else "",
                "class": read(device / "bDeviceClass")})
        result["devices"] = devices
    except OSError:
        result["errors"]["devices"] = "USB sysfs unavailable (Bluetooth peers are not enumerated on Linux)"
    try:
        result["interfaces"] = [{"id": p.name, "name": p.name, "mac": read(p / "address"),
            "transport": "wireless" if (p / "wireless").exists() else "usb" if "/usb" in str(p.resolve()) else "wired or virtual"}
            for p in (sys_root / "class/net").iterdir() if p.name != "lo" and read(p / "operstate") == "up"]
    except OSError:
        result["errors"]["interfaces"] = "Network sysfs unavailable"
    try:
        result["neighbors"] = [{"ip": f[0], "mac": f[3], "interface": f[5]}
            for line in (proc_root / "net/arp").read_text().splitlines()[1:]
            if len(f := line.split()) >= 6 and int(f[2], 16) & 2]
    except (OSError, ValueError):
        result["errors"]["neighbors"] = "IPv4 neighbor cache unavailable"
    try:
        mounts = []
        for line in (proc_root / "self/mountinfo").read_text().splitlines():
            f = line.split()
            block = sys_root / "dev/block" / f[2]
            if block.exists() and ("/usb" in str(block.resolve()) or
                    ((block / "removable").exists() and read(block / "removable") == "1")):
                mounts.append(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), f[4]))
        executions = []
        unreadable = 0
        for directory in proc_root.iterdir() if mounts else []:
            if not directory.name.isdigit():
                continue
            try:
                path = os.readlink(directory / "exe").removesuffix(" (deleted)")
                mount = next((m for m in mounts if beneath(path, m)), None)
                if mount:
                    created = (directory / "stat").read_text().rsplit(")", 1)[1].split()[19]
                    executions.append({"id": f"{directory.name}:{created}", "pid": directory.name, "path": path, "mount": mount})
            except PermissionError:
                unreadable += 1
            except (FileNotFoundError, ProcessLookupError):
                continue
        result["executions"] = executions
        if unreadable:
            result["warnings"] = [f"{unreadable} process paths inaccessible; removable execution coverage is partial"]
    except (OSError, ValueError, IndexError):
        result["errors"]["executions"] = "Mount/process enumeration unavailable"
    try:
        connections = []
        for line in (proc_root / "net/tcp").read_text().splitlines()[1:]:
            f = line.split()
            if f[3] != "01":
                continue
            address, port = f[2].split(":")
            connections.append({"remote": socket.inet_ntoa(bytes.fromhex(address)[::-1]),
                "port": int(port, 16), "local_port": int(f[1].split(":")[1], 16)})
        result["connections"] = connections
    except (OSError, ValueError, IndexError):
        result["errors"]["connections"] = "IPv4 TCP snapshot unavailable"
    return result


def clean_row(row):
    if not isinstance(row, dict):
        raise ValueError("invalid attachment row")
    return {str(k)[:64]: v if isinstance(v, int) else str(v or "")[:1024]
            for k, v in row.items() if k in {"id", "name", "class", "status", "vendor", "product",
                "description", "serial", "mac", "transport", "ip", "interface", "pid", "path", "mount", "remote", "port", "local_port"}}


def fingerprint(row):
    return hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()


class AttachmentCollector(Collector):
    def __init__(self, config, checkpoint=None):
        super().__init__(config, checkpoint)
        self.interval = config.get("interval", 15)
        self.counts = {}
        self.partial = []

    def snapshot(self):
        if platform.system() == "Windows":
            return windows_snapshot()
        if platform.system() == "Linux":
            return linux_snapshot()
        raise OSError("attachment monitoring supports Windows and Linux")

    def normalize(self, event):
        return event

    def health(self):
        return {**super().health(), "coverage": COVERAGE + (" Linux: no Bluetooth peer enumeration or IPv6 edge coverage." if platform.system() == "Linux" else ""),
            "observed": dict(self.counts), "limitations": list(self.partial)}

    def collect(self):
        data = self.snapshot()
        if not isinstance(data, dict):
            raise ValueError("invalid snapshot")
        self.partial = list(data.get("errors", {}).values()) + list(data.get("warnings", []))
        maps = {}
        for category in CATEGORIES:
            if category == "connections" and "neighbors" not in maps:
                continue
            if category not in data or category in data.get("errors", {}):
                continue  # an unavailable category is never a mass disconnection
            rows = data[category]
            if not isinstance(rows, list) or len(rows) > LIMIT:
                self.partial.append(f"{category} snapshot exceeds coverage limit or is invalid")
                continue
            current = {}
            for value in rows:
                row = clean_row(value)
                if category == "neighbors":
                    try:
                        address = ipaddress.ip_address(row.get("ip", ""))
                    except ValueError:
                        continue
                    mac = str(row.get("mac", "")).replace("-", ":").lower()
                    if address.is_multicast or address.is_loopback or address.is_unspecified or mac in {"", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
                        continue
                    row["mac"] = mac
                    key = f"{row.get('interface', '')}:{address}"
                elif category == "connections":
                    # Only observed local-neighbor traffic, not arbitrary Internet peers.
                    if row.get("remote") not in {r["ip"] for r in maps.get("neighbors", {}).values()}:
                        continue
                    key = f"{row.get('remote')}:{row.get('port')}:{row.get('local_port')}:{row.get('pid', '')}"
                else:
                    key = row.get("id", "")
                    if not key:
                        raise ValueError("attachment identifier missing")
                current[str(key)] = row
            maps[category] = current
        self.counts = {k: len(v) for k, v in maps.items()}
        if self.partial:
            self.error = "Partial coverage; see source limitations"
            self.status = "Error"
        for category, current in maps.items():
            previous = self.checkpoint.setdefault(category, {})
            initial = not self.checkpoint.get(category + "_initialized", False)
            changes = [(key, row, "present" if initial else "added" if key not in previous else "changed")
                for key, row in current.items() if previous.get(key) != row]
            if category in {"devices", "interfaces", "neighbors"}:
                changes += [(key, row, "removed") for key, row in previous.items() if key not in current]
            for key, row, action in changes:
                sequence = self.checkpoint.get("sequence", 0)
                event = self.event(category, key, row, action, sequence)
                yield event
                # Advancing only after enqueue preserves retry on queue backpressure.
                if action == "removed":
                    previous.pop(key, None)
                else:
                    previous[key] = row
                self.checkpoint["sequence"] = sequence + 1
            self.checkpoint[category] = current
            self.checkpoint[category + "_initialized"] = True

    def event(self, category, key, row, action, sequence):
        severity = 1 if action in {"present", "removed"} else 4
        kind = f"attachment_{category}_{action}"
        finding = False
        recommendation = "Review whether this device or connection is expected. Presence alone is not evidence of compromise."
        if category == "executions":
            kind, severity, finding = "removable_process_exec", 8, True
            recommendation = "A readable executable is running directly from removable storage. Verify its origin and scan the drive with endpoint antivirus; this observation does not prove malware."
        elif category == "connections":
            kind = "local_peer_connection"
            severity = 3
            ports = {row.get("port"), row.get("local_port")}
            if ports & {23, 5555}:
                severity, finding = 7, True
                recommendation = "TCP traffic uses a port commonly associated with Telnet or Android debugging. Verify the actual service and whether access is intended; port numbers alone do not establish a vulnerability."
            elif ports & {135, 139, 445, 3389, 5900}:
                severity = 5
                recommendation = "Observed a port commonly used for remote access or file sharing. Check that this peer and access are expected. This is not proof of a vulnerable service."
        evidence = {"category": category, "change": action, "observation": row,
                    "initial_inventory": action == "present", "review_required": finding,
                    "recommendation": recommendation, "coverage": "passive local observation"}
        return SecurityEvent(source_type="attachments", hostname=socket.gethostname(),
            event_type=kind, event_category="process" if category == "executions" else "network" if category in {"neighbors", "connections", "interfaces"} else "device",
            severity=severity, action=action, device_id=str(row.get("id", "")),
            process_id=str(row.get("pid", "")), file_path=str(row.get("path", "")),
            process_name=str(row.get("path", "")),
            message=f"{category} {action}: {json.dumps(row, sort_keys=True)}. {recommendation}",
            event_id=hashlib.sha256(f"attachments:{socket.gethostname()}:{category}:{key}:{fingerprint(row)}:{action}:{sequence}".encode()).hexdigest(),
            raw_event=row, metadata={"normalized_by": "attachments", "attachment": evidence,
                "legacy_fields": {"attachment": evidence}})
