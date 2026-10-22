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
