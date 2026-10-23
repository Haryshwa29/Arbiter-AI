"""Read-only local containment readiness; never changes host configuration."""

import json
import os
import platform
import shutil


def inspect_host():
    """Report prerequisites separately from implemented enforcement capability.

    Root is only a prerequisite on Linux: containers may still lack NET_ADMIN.
    Finding an executable is not proof that a firewall or collector is usable.
    No probes execute commands, open databases, or contact the network.
    """
    system = platform.system()
    if system == "Windows":
        from .ingestion.permissions import is_elevated

        privileged = is_elevated()
        tools = {name: shutil.which(name) is not None
                 for name in ("powershell.exe", "wevtutil.exe")}
        implemented = tools["powershell.exe"]
        blockers = []
        if not privileged:
            blockers.append("Windows administrator permission is required for firewall changes.")
        if not implemented:
            blockers.append("Windows PowerShell is unavailable.")
        blockers.append("Run agent with explicit containment scope; telemetry access and native enforcement still need validation.")
        notes = [
            "The dashboard supports approved five-minute IP blocks for qualifying local Windows/Sysmon events.",
            "The terminal agent accepts explicitly scoped private lab IPs and protected management/service networks.",
        ]
    elif system == "Linux":
        privileged = hasattr(os, "geteuid") and os.geteuid() == 0
        tools = {name: shutil.which(name) is not None
                 for name in ("nft", "journalctl", "osqueryi")}
        implemented = tools["nft"]
        blockers = ["Run agent with explicit containment scope; telemetry access and native enforcement still need validation."]
        if not privileged:
            blockers.append("Firewall changes require separately granted network administration privileges.")
        if not tools["nft"]:
            blockers.append("nftables executable is unavailable; the planned Linux adapter requires it.")
        notes = [
            "Root status does not prove NET_ADMIN capability or access to the target network namespace.",
            "Telemetry access and firewall behavior require separate live validation.",
        ]
    else:
        privileged, implemented, tools = None, False, {}
        blockers = ["Containment is planned for Windows and Linux; this operating system is unsupported."]
        notes = []
    return {
        "os": system,
        "architecture": platform.machine(),
        "privileged": privileged,
        "tools_found": tools,
        "local_firewall_adapter_available": implemented,
        "cli_available": system in {"Windows", "Linux"},
        "cli_containment_ready": False,
        "live_containment_verified": False,
        "blockers": blockers,
        "notes": notes,
    }


def cmd_readiness(args):
    report = inspect_host()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Arbiter readiness: {report['os']} / {report['architecture']}")
        print("Read-only assessment. Live containment has not been verified.")
        print(f"Administrator/root: {report['privileged']}")
        for name, found in report["tools_found"].items():
            print(f"  {name}: {'found' if found else 'not found'}")
        for message in report["blockers"]:
            print(f"Blocker: {message}")
        for message in report["notes"]:
            print(f"Note: {message}")
    # A successful inspection is distinct from readiness for enforcement.
    if args.require_ready and not report["cli_containment_ready"]:
        raise SystemExit(1)
