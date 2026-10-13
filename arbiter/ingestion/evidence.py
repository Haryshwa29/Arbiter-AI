"""Bounded, source-specific evidence. No commands, model calls or actuators."""
from pathlib import PureWindowsPath
import hashlib
import json
import re
import os
import sys
import subprocess
import socket
import shlex


def artifact(value):
    value = str(value or "").strip().strip('"')
    if value.lower().startswith("file:_"):
        value = value[6:]
    # Defender multi-resource/container descriptions cannot identify one process.
    if not value or ";" in value or value.lower().startswith("containerfile:"):
        return ""
    if "\\" in value or (len(value) > 1 and value[1] == ":"):
        return str(PureWindowsPath(value)).casefold()
    return value


def tool_finding(event):
    """Derive findings only from adapter-owned fields, not uploaded markers."""
    if event.metadata.get("normalized_by") != event.source_type:
        return None
    high = False
    if event.source_type == "defender":
        high = event.metadata.get("windows_event_id") in {1116, 1118, 1119, 1121, 5001, 5010, 5012}
    elif event.source_type == "wazuh":
        level = event.metadata.get("wazuh_level", 0)
        high = isinstance(level, int) and not isinstance(level, bool) and level >= 12
    elif event.source_type == "suricata":
        raw = event.raw_event if isinstance(event.raw_event, dict) else {}
        alert = raw.get("alert", {})
        priority = alert.get("severity") if isinstance(alert, dict) else None
        high = event.event_type == "network_alert" and type(priority) is not bool and priority in (1, "1")
    elif event.source_type == "guardduty":
        raw = event.raw_event if isinstance(event.raw_event, dict) else {}
        value = raw.get("Severity", 0)
        try: high = type(value) is not bool and 7 <= float(value) <= 10
        except (TypeError, ValueError): high = False
    elif event.source_type == "windows_security":
        high = bool(event.metadata.get("protection_gaps"))
    elif event.source_type == "osquery":
        high = bool(event.metadata.get("security_findings"))
    else:
        return None
    return {"source": event.source_type, "high_priority": high,
            "type": event.event_type, "rule_id": event.rule_id,
            "name": event.rule_name, "source_severity": event.severity,
            "reported_action": event.action}


def process_context(event, legacy, engine, connector):
    """Exact native process context; legacy signatures and feedback stay intact."""
    if connector != "sysmon" or event.source_type != "sysmon" or event.event_type != "process_exec":
        return None
    if getattr(engine.llm, "name", "") != "ollama" or event.metadata.get("correlation") or event.severity > 2:
        return None
    from ..prefilter import routine_telemetry
    if routine_telemetry(legacy): return None
    digest = re.search(r"(?:^|,)SHA256=([0-9a-fA-F]{64})(?:,|$)", event.file_hash)
    if not digest or not event.process_name or not event.username or not event.parent_process:
        return None
    from ..facts import render_all
    facts = render_all(engine.memory.facts_for(event.hostname, event.source_type), legacy)
    previous_posture = legacy.fields.get("asset_context", {}).get("protection_status", {})
    if not isinstance(previous_posture, dict) or previous_posture.get("gaps"): return None
    posture = dict(previous_posture)
    posture.pop("observed_at", None)
    context = [event.source_type, event.hostname, event.event_type, artifact(event.process_name),
        digest[1].lower(), event.command_line, event.username, event.user_id, artifact(event.parent_process),
        event.metadata.get("legacy_fields", {}).get("ParentCommandLine", ""), facts,
        engine.memory.asset_criticality(event.hostname), posture, getattr(engine.llm, "model", "")]
    key = hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest()
    return legacy.signature + ":ctx:" + key


def own_log_query(event, connector):
    """Attest only Arbiter-owned, exact fixed wevtutil read commands."""
    if connector != "sysmon" or event.source_type != "sysmon" or event.event_type != "process_exec":
        return False
    if event.hostname.casefold().split('.')[0] != socket.gethostname().casefold().split('.')[0]: return False
    if event.metadata.get("normalized_by") != "sysmon": return False
    fields = event.metadata.get("legacy_fields", {})
    if not isinstance(fields, dict) or artifact(event.parent_process) != artifact(sys.executable): return False
    same_parent = str(fields.get("ParentProcessId", "")) == str(os.getpid())
    try:
        parent_args = [part.strip('"').casefold() for part in shlex.split(str(fields.get("ParentCommandLine", "")), posix=False)]
        same_launch = parent_args == [str(part).casefold() for part in getattr(sys, "orig_argv", [])]
    except ValueError:
        same_launch = False
    if not (same_parent or same_launch): return False
    executable = os.environ.get("SystemRoot", r"C:\Windows").rstrip("\\/") + r"\System32\wevtutil.exe"
    if artifact(event.process_name) != artifact(executable): return False
    cursor = re.search(r"EventRecordID > ([0-9]+)", event.command_line)
    for channel in ("Security", "System", "Application", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Windows Defender/Operational"):
        for newest in (True, False):
            args = [executable, "qe", channel, "/f:xml", "/uni:true", "/rd:true" if newest else "/rd:false", "/c:1" if newest else "/c:200"]
            if event.command_line == subprocess.list2cmdline(args): return True
            if cursor and not newest:
                args.append(f"/q:*[System[(EventRecordID > {int(cursor[1])})]]")
                if event.command_line == subprocess.list2cmdline(args): return True
    return False
