"""Versioned telemetry contract; Event remains the stable brain boundary."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
import ipaddress
import json
import math
from typing import Any
import uuid

from ..schema import Event

MAX_EVENT_BYTES = 256 * 1024


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def timestamp(value: Any) -> str:
    if value in (None, "", "-"):
        return now()
    if isinstance(value, (float, int)):
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt.replace(tzinfo=dt.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat()


def safe_json(value: str | bytes) -> Any:
    def invalid(_):
        raise ValueError("non-finite JSON number")
    try:
        return json.loads(value, parse_constant=invalid)
    except (RecursionError, UnicodeError) as exc:
        raise ValueError("invalid JSON structure") from exc


@dataclass
class SecurityEvent:
    source_type: str
    hostname: str
    event_type: str
    message: str
    schema_version: str = "1.0"
    event_id: str = ""
    timestamp: str = ""
    received_at: str = ""
    source_vendor: str = ""
    source_product: str = ""
    device_id: str = ""
    username: str = ""
    user_id: str = ""
    src_ip: str = ""
    src_port: int | None = None
    dst_ip: str = ""
    dst_port: int | None = None
    protocol: str = ""
    process_name: str = ""
    process_id: str = ""
    parent_process: str = ""
    command_line: str = ""
    file_path: str = ""
    file_hash: str = ""
    event_category: str = "other"
    action: str = ""
    severity: float = 0
    raw_event: Any = None
    cloud_provider: str = ""
    cloud_account: str = ""
    region: str = ""
    resource_id: str = ""
    rule_name: str = ""
    rule_id: str = ""
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.schema_version != "1.0":
            raise ValueError("unsupported schema version")
        if not isinstance(self.metadata, dict) or not isinstance(self.tags, list):
            raise ValueError("metadata must be an object and tags an array")
        if len(self.tags) > 100 or any(not isinstance(t, str) for t in self.tags):
            raise ValueError("invalid tags")
        for f in fields(self):
            if f.name not in {"severity", "src_port", "dst_port", "raw_event", "tags", "metadata"}:
                value = getattr(self, f.name)
                if not isinstance(value, str) or len(value) > 32768:
                    raise ValueError(f"invalid {f.name}")
        if not self.source_type or not self.hostname or not self.event_type:
            raise ValueError("source, host and event type required")
        self.event_id = self.event_id or uuid.uuid4().hex
        self.timestamp = timestamp(self.timestamp)
        self.received_at = timestamp(self.received_at)
        self.severity = float(self.severity)
        if not math.isfinite(self.severity) or not 0 <= self.severity <= 10:
            raise ValueError("severity must be between 0 and 10")
        for name in ("src_ip", "dst_ip"):
            value = getattr(self, name)
            if value and value not in {"-", "::", "unknown"}:
                setattr(self, name, str(ipaddress.ip_address(value)))
            elif value:
                setattr(self, name, "")
        for name in ("src_port", "dst_port"):
            value = getattr(self, name)
            if value in (None, "", "-"):
                setattr(self, name, None)
            else:
                converted = int(value)
                if not 0 <= converted <= 65535 or str(converted) != str(value):
                    raise ValueError("invalid port")
                setattr(self, name, converted)
        if len(self.to_json().encode("utf-8")) > MAX_EVENT_BYTES:
            raise ValueError("event exceeds size limit")

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), allow_nan=False)

    def to_event(self) -> Event:
        # Only trusted normalization sets provenance. Raw payload is retained in
        # telemetry storage, never copied wholesale into the model prompt.
        data = dict(self.metadata.get("legacy_fields", {}))
        data.update({k: getattr(self, k) for k in (
            "src_ip", "dst_ip", "src_port", "dst_port", "username", "user_id",
            "process_name", "process_id", "parent_process", "command_line",
            "file_path", "file_hash", "cloud_account", "resource_id") if getattr(self, k) not in ("", None)})
        if self.username:
            data["user"] = self.username
        if self.file_path:
            data["path"] = self.file_path
        if self.process_name:
            data["process"] = self.process_name
        data.pop("_telemetry", None)
        if self.metadata.get("normalized_by") != "legacy":
            data["_telemetry"] = {"source": self.source_type, "category": self.event_category}
        if self.metadata.get("correlation"):
            data["correlation"] = self.metadata["correlation"]
        return Event(source=self.source_type, host=self.hostname, event_type=self.event_type,
                     message=self.message, severity=self.severity, timestamp=self.timestamp,
                     id=self.event_id, fields=data)
