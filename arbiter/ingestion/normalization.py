"""Adapters populate optional fields; preserve source payload for forensics."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ..schema import Event
from .schema import SecurityEvent, safe_json


def identity(source: str, value: Any) -> str:
    return hashlib.sha256((source + ":" + str(value)).encode()).hexdigest()


def normalize(data: Any, source: str = "auto") -> SecurityEvent:
    if isinstance(data, Event):
        data = json.loads(data.to_json())
    if not isinstance(data, dict):
        raise ValueError("event must be an object")
    original = data
    if isinstance(data.get("event"), dict):
        data = data["event"]
    if source == "auto":
        if "source" in data and "host" in data:
            source = "legacy"
        elif "schema_version" in data:
            source = "normalized"
        elif "eventSource" in data or "CloudTrailEvent" in data:
            source = "cloudtrail"
        elif "Severity" in data and "Resource" in data:
            source = "guardduty"
        elif "event_type" in data and "src_ip" in data:
            source = "suricata"
        elif "System" in data:
            source = "sysmon" if "Sysmon" in str(data["System"]) else "windows"
        else:
            raise ValueError("unrecognized event format; choose a source adapter")
    if source == "normalized":
        data = dict(data)
        data["raw_event"] = data.get("raw_event") or original
        metadata = dict(data.get("metadata", {}))
        metadata["normalized_by"] = "legacy"  # untrusted uploads cannot claim provenance
        data["metadata"] = metadata
        return SecurityEvent(**data)
    if source == "legacy":
        import math
        severity = float(data.get("severity", 5))
        if not math.isfinite(severity) or not 0 <= severity <= 10:
            raise ValueError("invalid severity")
        ev = Event(**data)
        f = ev.fields
        if not isinstance(f, dict):
            raise ValueError("fields must be an object")
        return SecurityEvent(source_type=ev.source, hostname=ev.host, event_type=ev.event_type,
            message=ev.message, severity=ev.severity, timestamp=ev.timestamp, event_id=ev.id,
            raw_event=original, username=str(f.get("user", f.get("username", ""))),
            src_ip=str(f.get("src_ip", "")), metadata={"normalized_by": "legacy", "legacy_fields": f})
    adapters = {"windows": windows, "sysmon": windows, "suricata": suricata,
                "cloudtrail": cloudtrail, "guardduty": guardduty, "osquery": osquery}
    if source not in adapters:
        raise ValueError("unsupported source adapter")
    return adapters[source](data, source)


WINDOWS_TYPES = {4624: ("auth_success", "authentication", 1),
    4625: ("auth_failure", "authentication", 2), 4634: ("logout", "authentication", 0),
    4648: ("explicit_credentials", "authentication", 3), 4672: ("privileges_assigned", "identity", 3),
    4688: ("process_exec", "process", 1), 4697: ("service_install", "persistence", 4),
    4720: ("user_created", "identity", 3), 4726: ("user_deleted", "identity", 3),
    4732: ("group_change", "identity", 4), 1102: ("audit_log_cleared", "audit", 5)}
SYSMON_TYPES = {1: ("process_exec", "process", 1), 3: ("network_connection", "network", 1),
    6: ("driver_load", "process", 3), 7: ("image_load", "process", 1),
    10: ("process_access", "process", 3), 11: ("file_create", "file", 1),
    12: ("registry_change", "registry", 2), 13: ("registry_change", "registry", 2),
    14: ("registry_change", "registry", 2), 22: ("dns_query", "network", 0)}


def windows(data: dict, source="windows") -> SecurityEvent:
    system, f = data.get("System", {}), data.get("EventData", {})
    if not isinstance(system, dict) or not isinstance(f, dict):
        raise ValueError("invalid Windows event")
    eid = int(system.get("EventID", 0))
    kind, category, severity = (SYSMON_TYPES if source == "sysmon" else WINDOWS_TYPES).get(
        eid, ("system_log", "system", 1))
    if kind == "system_log":
        severity = {1: 8, 2: 5, 3: 3, 4: 1, 0: 1}.get(int(system.get("Level", 4)), 3)
    host = str(system.get("Computer", "unknown"))
    channel = str(system.get("Channel", source))
    process = str(f.get("Image", f.get("NewProcessName", f.get("SourceImage", ""))))
    cmd = str(f.get("CommandLine", ""))
    user = str(f.get("TargetUserName", f.get("User", f.get("SubjectUserName", ""))))
    user_id = str(f.get("TargetUserSid", ""))
    if eid == 4732 and source == "windows":
        user = str(f.get("MemberName", "")) or user
        user_id = str(f.get("MemberSid", "")) or user_id
    details = f"{kind}: " + " ".join(f"{k}={v}" for k, v in f.items())
    # Rendered/localized prose must not hide structured command/process fields
    # from the existing text-based guardrails.
    message = (str(data.get("Message", "")) + " | " + details) if data.get("Message") else details
    # A normal access to a process named lsass is still evaluated by existing rails;
    # no ID alone produces a maliciousness decision.
    return SecurityEvent(source_type=source, source_vendor="Microsoft",
        source_product="Sysmon" if source == "sysmon" else "Windows Event Log",
        hostname=host, event_type=kind, event_category=category, severity=severity,
        message=message, timestamp=str(system.get("TimeCreated", "")),
        event_id=identity(source, (host, channel, system.get("EventRecordID"), system.get("TimeCreated"))),
        username=user, user_id=user_id,
        src_ip=str(f.get("IpAddress", f.get("SourceIp", ""))), src_port=f.get("SourcePort"),
        dst_ip=str(f.get("DestinationIp", "")), dst_port=f.get("DestinationPort"),
        protocol=str(f.get("Protocol", "")), process_name=process,
        process_id=str(f.get("ProcessId", f.get("NewProcessId", ""))),
        parent_process=str(f.get("ParentImage", f.get("ParentProcessName", ""))),
        command_line=cmd, file_path=str(f.get("TargetFilename", f.get("ImageLoaded", ""))),
        file_hash=str(f.get("Hashes", "")), raw_event=data,
        metadata={"normalized_by": source, "windows_event_id": eid, "channel": channel,
                  "legacy_fields": f, "process_guid": f.get("ProcessGuid", "")})


def suricata(data: dict, source="suricata") -> SecurityEvent:
    kind = data.get("event_type")
    if kind not in {"alert", "dns", "http", "tls", "flow", "fileinfo"}:
        raise ValueError("unsupported EVE event type")
    alert = data.get("alert", {})
    severity = {1: 8, 2: 5, 3: 3}.get(int(alert.get("severity", 3)), 3) if kind == "alert" else 0
    specific = data.get(kind, {})
    return SecurityEvent(source_type=source, source_vendor="OISF", source_product="Suricata",
        hostname=str(data.get("host", data.get("sensor_name", "suricata-sensor"))),
        event_type="network_alert" if kind == "alert" else kind,
        event_category="network", severity=severity, timestamp=str(data.get("timestamp", "")),
        event_id=identity(source, json.dumps(data, sort_keys=True)),
        message=str(alert.get("signature", "")) or f"Suricata {kind}: {json.dumps(specific)}",
        src_ip=str(data.get("src_ip", "")), dst_ip=str(data.get("dest_ip", "")),
        src_port=data.get("src_port"), dst_port=data.get("dest_port"), protocol=str(data.get("proto", "")),
        rule_id=str(alert.get("signature_id", "")), rule_name=str(alert.get("signature", "")),
        action=str(alert.get("action", "")), raw_event=data,
        metadata={"normalized_by": source, "flow_id": data.get("flow_id"), "details": specific})


def cloudtrail(data: dict, source="cloudtrail") -> SecurityEvent:
    original = data
    if "CloudTrailEvent" in data:
        data = safe_json(data["CloudTrailEvent"])
    if not isinstance(data, dict) or not data.get("eventName"):
        raise ValueError("invalid CloudTrail event")
    user = data.get("userIdentity", {})
    name = data["eventName"]
    kind = ("auth_failure" if (data.get("responseElements") or {}).get("ConsoleLogin") == "Failure"
            else "auth_success") if name == "ConsoleLogin" else (
        "security_group_change" if name == "AuthorizeSecurityGroupIngress" else
        "iam_change" if str(data.get("eventSource", "")).startswith("iam.") else "cloud_activity")
    params = data.get("requestParameters") or {}
    passive = data.get("readOnly") is True and not data.get("errorCode") and name.startswith(("Describe", "List"))
    if passive:
        kind = "cloud_read"
    account = str(data.get("recipientAccountId", user.get("accountId", "")))
    return SecurityEvent(source_type=source, source_vendor="Amazon", source_product="CloudTrail",
        hostname=str(user.get("arn", account or "aws-account")), event_type=kind,
        event_category="authentication" if name == "ConsoleLogin" else "cloud",
        action=name, severity=0 if passive else 2 if name in {"ConsoleLogin", "AssumeRole"} else 4,
        timestamp=str(data.get("eventTime", "")),
        event_id=identity(source, data.get("eventID") or json.dumps(data, sort_keys=True)),
        username=str(user.get("userName", user.get("principalId", ""))), user_id=str(user.get("arn", "")),
        src_ip=str(data.get("sourceIPAddress", "")) if _is_ip(data.get("sourceIPAddress")) else "",
        cloud_provider="aws", cloud_account=account, region=str(data.get("awsRegion", "")),
        resource_id=str((data.get("resources") or [{}])[0].get("ARN", "")),
        message=f"{name}: {json.dumps(params)} {data.get('errorCode', '')}", raw_event=data,
        metadata={"normalized_by": source, "event_source": data.get("eventSource"),
                  "lookup_event_id": original.get("EventId", ""),
                  "request_parameters": params, "identity": user,
                  "legacy_fields": {"user": user.get("userName", ""), "action": name}})


def _is_ip(value):
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def guardduty(data: dict, source="guardduty") -> SecurityEvent:
    if not data.get("Id") or "Severity" not in data:
        raise ValueError("invalid GuardDuty finding")
    resource = data.get("Resource", {})
    instance = resource.get("InstanceDetails", {})
    account = str(data.get("AccountId", ""))
    return SecurityEvent(source_type=source, source_vendor="Amazon", source_product="GuardDuty",
        hostname=str(instance.get("InstanceId", account or "aws-account")),
        event_type="cloud_finding", event_category="cloud", severity=float(data["Severity"]),
        event_id=identity(source, (data["Id"], data.get("UpdatedAt", ""))),
        timestamp=str(data.get("UpdatedAt", data.get("CreatedAt", ""))),
        message=str(data.get("Title", data.get("Type", "GuardDuty finding"))) + ": " + str(data.get("Description", "")),
        cloud_provider="aws", cloud_account=account, region=str(data.get("Region", "")),
        resource_id=str(instance.get("InstanceId", "")), rule_id=str(data.get("Type", "")),
        raw_event=data, metadata={"normalized_by": source, "resource": resource, "service": data.get("Service", {})})


def osquery(data: dict, source="osquery") -> SecurityEvent:
    if not isinstance(data.get("rows"), list) or not data.get("table"):
        raise ValueError("invalid osquery snapshot")
    return SecurityEvent(source_type=source, hostname=str(data.get("hostname", "unknown")),
        source_product="osquery", event_type="asset_snapshot", event_category="inventory",
        message=f"osquery {data['table']}: {len(data['rows'])} rows", severity=0,
        raw_event=data, metadata={"normalized_by": source, "table": data["table"], "rows": data["rows"]})
