"""Bounded in-memory upload parsing. Filenames are labels, never paths."""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import io
from pathlib import PureWindowsPath
import uuid

from .normalization import normalize
from .schema import now, safe_json

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_UPLOAD_EVENTS = 5000


@dataclass
class ImportResult:
    filename: str
    detected_format: str
    events: list = field(default_factory=list)
    invalid_events: int = 0
    errors: list = field(default_factory=list)

    def summary(self):
        return {"filename": self.filename, "detected_format": self.detected_format,
                "number_of_events": len(self.events) + self.invalid_events,
                "valid_events": len(self.events), "invalid_events": self.invalid_events,
                "errors": self.errors}


def parse_upload(filename: str, content: str, source="auto") -> ImportResult:
    if not isinstance(filename, str) or not isinstance(content, str):
        raise ValueError("filename and text content required")
    # Reject path-like names, including Unix and Windows paths; never write upload.
    if not filename or len(filename) > 200 or "/" in filename or "\\" in filename or ":" in filename or "\x00" in filename:
        raise ValueError("filename must be a plain name")
    if len(content.encode("utf-8")) > MAX_UPLOAD_BYTES:
        raise ValueError("upload exceeds 5 MiB")
    ext = PureWindowsPath(filename).suffix.lower()
    if ext not in {".json", ".jsonl", ".csv"}:
        raise ValueError("supported formats: JSON, JSONL, CSV")
    result = ImportResult(filename, ext[1:])
    if ext == ".json":
        data = safe_json(content)
        if isinstance(data, dict) and isinstance(data.get("Records"), list):
            objects = data["Records"]
        elif isinstance(data, dict) and isinstance(data.get("Findings"), list):
            objects = data["Findings"]
        else:
            objects = data if isinstance(data, list) else [data]
    elif ext == ".jsonl":
        objects = []
        for n, line in enumerate(content.splitlines(), 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if len(objects) + result.invalid_events >= MAX_UPLOAD_EVENTS:
                raise ValueError("upload exceeds 5000 events")
            try:
                objects.append(safe_json(line))
            except ValueError:
                result.invalid_events += 1
                if len(result.errors) < 20:
                    result.errors.append(f"Line {n}: invalid JSON")
    else:
        reader = csv.DictReader(io.StringIO(content))
        objects = []
        try:
            for row in reader:
                if len(objects) >= MAX_UPLOAD_EVENTS:
                    raise ValueError("upload exceeds 5000 events")
                if row.get("fields"):
                    try:
                        row["fields"] = safe_json(row["fields"])
                    except ValueError:
                        row["fields"] = None
                objects.append({k: v for k, v in row.items() if v != ""})
        except csv.Error as exc:
            raise ValueError("malformed CSV or oversized field") from exc
    if len(objects) + result.invalid_events > MAX_UPLOAD_EVENTS:
        raise ValueError("upload exceeds 5000 events")
    for n, obj in enumerate(objects, 1):
        try:
            result.events.append(normalize(obj, source))
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            result.invalid_events += 1
            if len(result.errors) < 20:
                result.errors.append(f"Record {n}: invalid or unsupported event")
    return result


def schedule(events, speed="instant"):
    speeds = {"original": 1, "1x": 1, "2x": 2, "5x": 5, "10x": 10, "instant": 0}
    if speed not in speeds:
        raise ValueError("unsupported replay speed")
    base = datetime.now(timezone.utc)
    ordered = sorted(events, key=lambda e: e.timestamp) if speeds[speed] else events
    first = datetime.fromisoformat(ordered[0].timestamp) if ordered else base
    for event in ordered:
        delay = max(0, (datetime.fromisoformat(event.timestamp) - first).total_seconds()) / speeds[speed] if speeds[speed] else 0
        if delay > 86400:
            raise ValueError("replay span exceeds 24 hours; choose a faster speed")
        # Original timestamp is retained for correlation and forensic review.
        event.event_id = uuid.uuid4().hex
        event.received_at = now()
        event.tags = [*event.tags, "replay"]
        yield event, (base + timedelta(seconds=delay)).isoformat()
