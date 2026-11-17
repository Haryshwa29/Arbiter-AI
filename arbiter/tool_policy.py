"""Shared provenance checks for deterministic source-observation policies."""
from .schema import Event


def verified_finding(event: Event, source: str) -> dict | None:
    finding = event.fields.get("_tool_finding")
    provenance = event.fields.get("_telemetry")
    if (isinstance(finding, dict) and isinstance(provenance, dict)
            and event.source == source == finding.get("source") == provenance.get("source")
            and finding.get("type") == event.event_type):
        return finding
    return None


def source_observations(event: Event, source: str) -> dict:
    finding = verified_finding(event, source)
    observations = finding.get("observations", {}) if finding else {}
    return observations if isinstance(observations, dict) else {}


def routine_source_reason(event: Event) -> str:
    """Narrow observation policies, never blanket authentication/IDS silence."""
    finding = verified_finding(event, "wazuh")
    if (not finding or finding.get("high_priority") is True
            or event.severity > 2 or event.fields.get("correlation")):
        return ""
    observations = source_observations(event, "wazuh")
    if observations.get("local_tls_mail_login") is True and event.event_type == "auth_success":
        return ("Routine Dovecot authentication observation: a non-privileged account, "
                "explicit TLS and the same private local/remote address were recorded; "
                "no correlated detection. Retained for correlation; not proof the account is safe.")
    if observations.get("signature_database_update") is True:
        return ("Routine FreshClam signature-database update observation: the source decoder, "
                "update rule and recorded update-start message agree; no correlated detection. "
                "An update start does not prove completion or absence of malware.")
    return ""
