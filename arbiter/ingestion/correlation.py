"""Bounded correlation rules. Findings are context, not autonomous response."""
from __future__ import annotations

from .schema import SecurityEvent


def correlate(event: SecurityEvent, previous: list[SecurityEvent]) -> list[dict]:
    matches = []
    def identity_match(previous):
        if previous.user_id and event.user_id and "S-1-0-0" not in {previous.user_id, event.user_id}:
            return previous.user_id == event.user_id
        return bool(previous.username and previous.username == event.username)

    same_identity = [p for p in previous if p.hostname == event.hostname and
                     identity_match(p) and
                     (not event.src_ip or p.src_ip == event.src_ip)]
    failures = [p for p in same_identity if p.event_type == "auth_failure"]
    if event.event_type in {"auth_failure", "auth_success"} and len(failures) >= (4 if event.event_type == "auth_failure" else 5):
        matches.append({"rule": "repeated_login_failures" if event.event_type == "auth_failure" else "failed_then_successful_login",
                        "events": [p.event_id for p in failures[:20]], "severity": 7,
                        "reason": "Repeated failures for the same host, account and source within five minutes"})
    created = [p for p in same_identity if p.event_type == "user_created"]
    if event.event_type == "group_change" and created:
        matches.append({"rule": "new_user_group_change", "events": [p.event_id for p in created],
                        "severity": 6, "reason": "New account followed by group membership change; review privilege context"})
    processes = [p for p in previous if p.hostname == event.hostname and p.event_type == "process_exec"
                 and p.process_id and p.process_id == event.process_id and
                 (not p.metadata.get("process_guid") or p.metadata.get("process_guid") == event.metadata.get("process_guid"))]
    if event.event_type == "network_connection":
        from ..guardrails import guardrail_check
        hot = [p for p in processes if guardrail_check(p.to_event())]
        if hot:
            matches.append({"rule": "suspicious_process_network", "events": [p.event_id for p in hot],
                            "severity": 8, "reason": "Outbound connection by a process with an existing guardrail signal"})
    if event.event_type in {"network_connection", "process_exec"}:
        from .evidence import artifact
        path = artifact(event.process_name)
        malware = [p for p in previous if p.hostname == event.hostname and p.source_type == "defender"
                   and p.event_type == "malware_detection" and path
                   and path == artifact(p.file_path)]
        if malware:
            matches.append({"rule": "malware_process_network" if event.event_type == "network_connection" else "malware_process_execution", "events": [p.event_id for p in malware[:20]],
                            "severity": 9, "verified_tool_source": any(p.metadata.get("_collector_origin") == "defender" for p in malware),
                            "reason": "Activity by the exact executable associated with a recent Defender malware detection on this host"})
    if event.source_type == "defender" and event.event_type == "malware_detection":
        from .evidence import artifact
        paths = {artifact(event.file_path)} - {""}
        activity = [p for p in previous if p.hostname == event.hostname and p.source_type == "sysmon"
                    and p.event_type in {"process_exec", "network_connection"}
                    and artifact(p.process_name) in paths]
        if activity:
            matches.append({"rule": "malware_related_process_activity", "events": [p.event_id for p in activity[:20]],
                            "severity": 9, "reason": "Defender malware detection matches recent Sysmon executable activity; no remediation assumed"})
    if event.event_type == "iam_change":
        logins = [p for p in same_identity if p.event_type == "auth_success"]
        if logins:
            matches.append({"rule": "cloud_login_iam_change", "events": [p.event_id for p in logins],
                            "severity": 5, "reason": "Cloud login followed by IAM changes; no geographic baseline assumed"})
    findings = [p for p in previous if p.event_type in {"cloud_finding", "network_alert"} and
                (p.hostname == event.hostname or bool(event.src_ip and event.src_ip in {p.src_ip, p.dst_ip}) or
                 bool(event.cloud_account and event.cloud_account == p.cloud_account))]
    if findings and event.source_type not in {"guardduty", "suricata"}:
        matches.append({"rule": "tool_finding_related_activity", "events": [p.event_id for p in findings[:20]],
                        "severity": max(p.severity for p in findings), "reason": "Recent tool finding shares asset, account or IP"})
    if event.event_type in {"cloud_finding", "network_alert"}:
        activity = [p for p in previous if p.source_type != event.source_type and (
            p.hostname == event.hostname or bool(event.cloud_account and event.cloud_account == p.cloud_account) or
            bool(event.src_ip and event.src_ip in {p.src_ip, p.dst_ip}))]
        if activity:
            matches.append({"rule": "activity_related_tool_finding", "events": [p.event_id for p in activity[:20]],
                            "severity": event.severity, "reason": "Tool finding shares account, asset or IP with recent activity"})
    return matches
