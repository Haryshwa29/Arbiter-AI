"""Read-only advice. Model prose never selects an executable operation."""
from ..llm import validated_steps


def guidance(event, analysis):
    if not analysis or analysis.get("decision") != "escalate": return None
    steps = validated_steps(analysis.get("recommended_steps"))
    if steps and analysis.get("backend") in {"ollama", "ollama-cloud"}:
        return {"source": "model", "steps": steps,
                "caution": "AI-suggested investigation steps; verify them against the original evidence. Advice does not authorize execution."}
    kind = str(event.get("event_type", "")).lower()
    if "package" in kind or "update" in kind:
        steps = ["Check the approved change or maintenance record and identify who initiated the update.",
                 "Verify the package source and installed version against your approved release.",
                 "Check service health and relevant logs. A package update alone does not establish malicious activity; do not roll back without further evidence."]
    elif any(s in kind for s in ("auth", "login", "logon")):
        steps = ["Verify the affected account, source address and timestamps in the original authentication logs.",
                 "Check for successful logins after the failures and confirm whether the activity was authorized.",
                 "Review related events before approving any supported temporary peer block; consider legitimate users and management access."]
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
    metadata = event.get("metadata") or {}
    fields = metadata.get("legacy_fields") or {}
    raw = event.get("raw_event")
    raw = raw if isinstance(raw, dict) else {}
    def value(*keys):
        for source in (event, fields, raw):
            for key in keys:
                item = source.get(key)
                if isinstance(item, (str, int)) and str(item).strip():
                    return str(item)[:32768]
        return "Not recorded"
    origin = {"Executable": value("process_name", "Image", "process"),
              "Parent executable": value("parent_process", "ParentImage"),
              "Account": value("username", "User", "user"),
              "Command": value("command_line", "CommandLine"),
              "Parent command": value("ParentCommandLine")}
    why = analysis.get("rationale") or "Escalated for manual review; no specific trigger explanation was recorded."
    gaps = "This alert is a reason to investigate, not proof of compromise. The initiating application and authorization may require parent-process records."
    next_steps = guidance(event, analysis)
    if "NON_SUPPRESSIBLE_LOLBIN" in why:
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
        command = origin["Parent command"].replace("\r\n", "\n")
        if WINDOWS_SNAPSHOT.strip() in command:
            gaps = ("The parent command contains Arbiter's device/network inventory script. This suggests collector activity, but matching script text alone does not verify who launched it. " + gaps)
    return {"why": why, "origin": origin, "uncertainty": gaps, "guidance": next_steps}
