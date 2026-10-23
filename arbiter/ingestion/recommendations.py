"""Read-only advice. Model prose never selects an executable operation."""
from ..llm import validated_steps


def event_values(event):
    metadata = event.get("metadata") or {}
    fields = metadata.get("legacy_fields") or {}
    raw = event.get("raw_event")
    raw = raw if isinstance(raw, dict) else {}
    def value(*keys):
        for source in (event, fields, raw):
            for key in keys:
                item = source.get(key)
                if isinstance(item, (str, int)) and not isinstance(item, bool) and str(item).strip():
                    return str(item)[:32768]
        return "Not recorded"
    return value


def guidance(event, analysis):
    if not analysis or analysis.get("decision") != "escalate": return None
    steps = validated_steps(analysis.get("recommended_steps"))
    if steps and analysis.get("backend") in {"ollama", "ollama-cloud"}:
        return {"source": "model", "steps": steps,
                "caution": "AI-suggested investigation steps; verify them against the original evidence. Advice does not authorize execution."}
    kind = str(event.get("event_type", "")).lower()
    if any(s in kind for s in ("syn_flood", "http_request_flood", "http_flood", "request_flood", "slowloris", "connection_exhaustion", "conn_exhaustion")):
        value = event_values(event)
        port = value("dst_port", "port")
        target = "the reported service" if port == "Not recorded" else f"the service on port {port}"
        steps = [f"Check {target} on {event.get('hostname') or 'the affected host'} for failed requests, increased latency and connection exhaustion at the event time.",
                 "Compare connection states, request rates and source addresses in server and network logs with this host's normal traffic. Check for an approved load test or traffic surge.",
                 "Verify whether the reported mitigation is active and service health recovered. Identify supported source addresses before considering a scoped traffic block; do not block an entire service based on this alert alone."]
    elif "package" in kind or "update" in kind:
        steps = ["Check the approved change or maintenance record and identify who initiated the update.",
                 "Verify the package source and installed version against your approved release.",
                 "Check service health and relevant logs. A package update alone does not establish malicious activity; do not roll back without further evidence."]
    elif any(s in kind for s in ("auth", "login", "logon")):
        value = event_values(event)
        user = value("username", "User", "user")
        account = "the recorded account" if user == "Not recorded" else f"account {user}"
        steps = [f"Verify the logon result, logon type, source address and time for {account} in the original authentication logs.",
                 f"Confirm with the account owner whether {account} was expected to access this host from that source at that time. A missing baseline alone does not establish credential theft.",
                 "Review nearby failed and successful logins and any subsequent process or privilege changes. Record which evidence supports misuse and which facts are still unknown before choosing a response."]
    elif any(s in kind for s in ("disk", "storage")):
        steps = ["Check the affected disk's health report and the exact error counters or failure indicators in the original event. Identify the disk and affected volumes before taking action.",
                 "Review storage and application logs for read/write errors and confirm that recent backups are usable.",
                 "Ask the device owner to assess replacement or recovery through the approved maintenance process. A disk-health warning alone does not establish a cyberattack."]
    elif any(s in kind for s in ("mass_file_rename", "ransomware", "file_integrity")):
        steps = ["Verify the affected file paths, change count, timestamps and initiating process against file-audit or integrity records.",
                 "Compare the changes with approved deployments, package updates or user activity. Check endpoint-protection findings for the same process and files.",
                 "If changes are unexplained, preserve the relevant records and check backup availability before coordinating a scoped response. Do not delete or restore files based on this alert alone."]
    else:
        steps = ["Verify the affected device, actor and time against the original event and related records.",
                 "Check whether the activity matches an approved change or expected task; record any evidence gaps.",
                 "If unexplained, investigate with the device owner or security team. Approve only a supported, scoped response after reviewing its impact."]
    return {"source": "policy", "steps": steps,
            "caution": "Policy-guided manual investigation. No AI recommendation was recorded for this event; no arbitrary commands will be executed."}


def alert_brief(event, analysis):
    """Explain recorded evidence without conferring trust or response authority."""
    if not analysis or analysis.get("decision") != "escalate":
        return None
    value = event_values(event)
    kind = str(event.get("event_type", "")).lower()
    origin = {"Affected device": value("hostname", "host"),
              "Source address": value("src_ip", "IpAddress", "source_ip"),
              "Destination address": value("dst_ip", "destination_ip"),
              "Destination port": value("dst_port", "port"),
              "Half-open connections": value("half_open"),
              "Logon type": value("logon_type", "LogonType"),
              "Detection rule": value("rule_name", "rule_id"),
              "File path": value("file_path", "path", "TargetFilename"),
              "File hash": value("file_hash", "Hashes"),
              "Executable": value("process_name", "Image", "process"),
              "Parent executable": value("parent_process", "ParentImage"),
              "Account": value("username", "User", "user"),
              "Command": value("command_line", "CommandLine"),
              "Parent command": value("ParentCommandLine")}
    origin = {key: item for key, item in origin.items() if item != "Not recorded"}
    observed = value("message")
    if observed == "Not recorded":
        observed = "No event description was recorded. Inspect the original payload; the reason for the underlying activity is unknown."
    basis = analysis.get("rationale") or "No decision rationale was recorded."
    why = basis
    gaps = "The record alone does not establish the cause or whether the activity was authorized. Verify the original event and related records."
    if any(s in kind for s in ("syn_flood", "http_request_flood", "http_flood", "request_flood", "slowloris", "connection_exhaustion", "conn_exhaustion")):
        why = "The source reports a traffic or connection-exhaustion condition that may prevent legitimate clients from reaching the service. This is the reported network symptom; the priority score is not the diagnosis."
        gaps = "The event does not establish who caused the traffic, whether it was an attack or a legitimate load surge, or whether users experienced an outage. Reported mitigation does not prove recovery. Check traffic baselines and service health."
    elif any(s in kind for s in ("auth", "login", "logon")):
        if analysis.get("tier") == "llm":
            why = "The AI requested review of this authentication event: " + basis
        gaps = "A successful or unfamiliar login, missing baseline, or unrelated environment fact does not prove stolen credentials or lateral movement. Verify the result, source, logon type and authorization; these details may be absent from this record."
    elif analysis.get("tier") == "prefilter":
        why = "The event was escalated by the priority policy using source severity, asset importance and available history. This prioritizes review; it does not independently identify an attack or explain its cause."
    elif analysis.get("backend") == "policy-fallback":
        why = "The AI could not complete an assessment. Safety policy escalated the event for review; this does not establish malicious activity."
    next_steps = guidance(event, analysis)
    if "NON_SUPPRESSIBLE_LOLBIN" in basis:
        from ..guardrails import _LOLBINS, _LOLBIN_CTX
        message = str(event.get("message", "")).lower()
        binaries = [token for token in _LOLBINS if token in message]
        markers = [token for token in _LOLBIN_CTX if token in message]
        if binaries and markers:
            why = ("The recorded event text matched the system-tool rule: "
                   + ", ".join(binaries) + "; command markers: " + ", ".join(markers)
                   + ". Matches can come from the parent command. These text matches do not establish a download or malicious execution.")
        gaps += " A system path or Microsoft file description does not verify the file signature."
        next_steps = {"source": "policy", "steps": [
            "Review the executable and parent command above. Identify the application that launched the parent process using its Sysmon process GUID and creation-time records.",
            "Check whether that application and script belong to an approved monitoring or administration task. Verify the executable signature and compare the script with its installed source.",
            "If the activity is expected, acknowledge this alert as reviewed. If unexplained, inspect related process and network events and scan the identified file with endpoint protection before considering a scoped response."
        ], "caution": "Acknowledgement records review only; it does not mark the activity benign or stop a process. Signature-wide false-alarm feedback can affect other events."}
        from .collectors.attachments import WINDOWS_SNAPSHOT
        command = origin.get("Parent command", "").replace("\r\n", "\n")
        if WINDOWS_SNAPSHOT.strip() in command:
            gaps = ("The parent command contains Arbiter's device/network inventory script. This suggests collector activity, but matching script text alone does not verify who launched it. " + gaps)
    return {"observed": observed, "why": why, "decision_basis": basis,
            "origin": origin, "uncertainty": gaps, "guidance": next_steps}
