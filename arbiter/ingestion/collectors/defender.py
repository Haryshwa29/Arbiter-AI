"""Read Defender findings without changing antivirus settings or running scans."""
from .windows import WindowsCollector
from ..normalization import identity
from ..schema import SecurityEvent

CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
TYPES = {1116: ("malware_detection", 8), 1117: ("antivirus_action", 5),
         1118: ("antivirus_action_failed", 8), 1119: ("antivirus_action_failed", 8),
         1121: ("attack_surface_reduction_block", 7), 1122: ("attack_surface_reduction_audit", 5),
         5001: ("antivirus_disabled", 8), 5007: ("antivirus_configuration_change", 4),
         5010: ("antivirus_scanning_disabled", 8), 5012: ("antivirus_scanning_disabled", 8)}


class DefenderCollector(WindowsCollector):
    def __init__(self, config, checkpoint=None):
        super().__init__(config, checkpoint)
        self.channels = [CHANNEL]

    def collect(self):
        for raw in super().collect():
            if int(raw["System"]["EventID"]) in TYPES:
                yield raw

    def normalize(self, raw):
        return defender(raw)


def defender(raw, source="defender"):
    system, fields = raw.get("System", {}), raw.get("EventData", {})
    if not isinstance(system, dict) or not isinstance(fields, dict):
        raise ValueError("invalid Defender event")
    eid = int(system.get("EventID", 0))
    if eid not in TYPES:
        raise ValueError("unsupported Defender event")
    kind, severity = TYPES[eid]
    host = str(system.get("Computer", "unknown"))
    return SecurityEvent(source_type=source, source_vendor="Microsoft", source_product="Microsoft Defender",
        hostname=host, event_type=kind, event_category="security", severity=severity,
        event_id=identity(source, (host, CHANNEL, system.get("EventRecordID"), system.get("TimeCreated"))),
        timestamp=str(system.get("TimeCreated", "")),
        message=f"{kind}: {raw.get('Message', '')} | " + " ".join(f"{k}={v}" for k, v in fields.items()),
        process_name=str(fields.get("Process Name", "")), file_path=str(fields.get("Path", "")),
        username=str(fields.get("Detection User", "")), rule_name=str(fields.get("Threat Name", "")),
        rule_id=str(fields.get("Threat ID", "")), action=str(fields.get("Action Name", "")), raw_event=raw,
        metadata={"normalized_by": source, "windows_event_id": eid, "legacy_fields": fields})
