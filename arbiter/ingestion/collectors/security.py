"""Observe local antivirus/firewall posture. Never change settings or run scans."""
import os
import socket
import subprocess

from ..base import Collector
from ..schema import SecurityEvent, safe_json

SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$env:PSModulePath = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules') + ';' + $env:PSModulePath
$defender = Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled
$firewall = @(Get-NetFirewallProfile | Select-Object Name,Enabled)
@{defender=$defender;firewall=$firewall} | ConvertTo-Json -Depth 4 -Compress
"""


def security(data, source="windows_security"):
    defender, firewall = data.get("defender"), data.get("firewall")
    if not isinstance(defender, dict) or not isinstance(firewall, list):
        raise ValueError("invalid local security posture")
    gaps, unknown = [], []
    for name in ("AntivirusEnabled", "RealTimeProtectionEnabled", "BehaviorMonitorEnabled", "IoavProtectionEnabled"):
        value = defender.get(name)
        if value is False: gaps.append(name + " disabled")
        elif value is not True: unknown.append(name)
    if not firewall: unknown.append("firewall profiles")
    for profile in firewall:
        if not isinstance(profile, dict): raise ValueError("invalid firewall profile")
        name, value = str(profile.get("Name", "unknown")), profile.get("Enabled")
        # Windows reports Enabled as an enum (0/1/2), not necessarily JSON bool.
        if value is False or (type(value) is int and value == 0): gaps.append(name + " firewall disabled")
        elif value is not True and not (type(value) is int and value == 1): unknown.append(name + " firewall")
    message = ("Protection gaps: " + "; ".join(gaps)) if gaps else (
        "Protection state unknown: " + "; ".join(unknown)) if unknown else "Defender and all observed firewall profiles enabled"
    return SecurityEvent(source_type=source, source_vendor="Microsoft", source_product="Windows Security",
        hostname=str(data.get("hostname") or socket.gethostname()), event_type="security_posture", event_category="security",
        severity=8 if gaps else 3 if unknown else 0, message=message, raw_event=data,
        metadata={"normalized_by": source, "protection_gaps": gaps, "unknown_controls": unknown,
                  "protection_status": {"defender": defender, "firewall": firewall}})


class SecurityCollector(Collector):
    def __init__(self, config, checkpoint=None):
        super().__init__(config, checkpoint)
        self.interval = float(config.get("interval", 300))

    def collect(self):
        if os.name != "nt": raise OSError("Windows only")
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", SCRIPT],
            capture_output=True, timeout=25, creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode or len(result.stdout) > 65536: raise OSError("security posture unavailable")
        data = safe_json(result.stdout.decode("utf-8-sig"))
        if not isinstance(data, dict): raise ValueError("invalid posture response")
        yield data

    def normalize(self, raw):
        return security(raw)
