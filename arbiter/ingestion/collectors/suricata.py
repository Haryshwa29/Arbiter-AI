"""Bounded EVE tailer; cursor advances only after durable enqueue."""
from __future__ import annotations

from pathlib import Path

from ..base import Collector
from ..schema import safe_json


class SuricataCollector(Collector):
    interval = 1.0

    def collect(self):
        path = Path(self.config["path"])
        stat = path.stat()
        generation = [stat.st_dev, stat.st_ino]
        offset = int(self.checkpoint.get("offset", 0))
        if self.checkpoint.get("generation") != generation or stat.st_size < offset:
            offset = 0
        self.checkpoint.update(generation=generation, offset=offset)
        with path.open("rb") as stream:
            stream.seek(offset)
            for _ in range(500):
                position = stream.tell()
                line = stream.readline(256 * 1024 + 1)
                if not line:
                    break
                if len(line) > 256 * 1024:
                    # Drain an oversized line, without holding it in memory.
                    while line and not line.endswith(b"\n"):
                        line = stream.readline(256 * 1024)
                    self.errors += 1
                    self.error = "Oversized EVE record skipped"
                    self.checkpoint["offset"] = stream.tell()
                    continue
                if not line.endswith(b"\n"):
                    stream.seek(position)
                    break  # incomplete writer line, retry later
                try:
                    raw = safe_json(line)
                    if not isinstance(raw, dict):
                        raise ValueError("not an object")
                    if raw.get("event_type") in {"alert", "dns", "http", "tls", "flow", "fileinfo"}:
                        yield raw
                except ValueError:
                    self.errors += 1
                    self.error = "Malformed EVE record skipped"
                self.checkpoint["offset"] = stream.tell()
        self.status = "Connected"
