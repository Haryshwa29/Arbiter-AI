"""Read local Wazuh manager alerts; never invoke Wazuh active response."""
from pathlib import Path

from ..base import Collector
from ..schema import MAX_EVENT_BYTES, safe_json


class WazuhCollector(Collector):
    interval = 1.0

    def collect(self):
        path = Path(self.config["path"])
        # Inspect the opened file, so rotation cannot mismatch identity and data.
        with path.open("rb") as stream:
            import os
            stat = os.fstat(stream.fileno())
            generation = [str(path.resolve()), stat.st_dev, stat.st_ino]
            offset = int(self.checkpoint.get("offset", 0))
            if "generation" not in self.checkpoint:
                offset = 0 if self.config["read_existing"] else stat.st_size
            elif self.checkpoint["generation"] != generation or stat.st_size < offset:
                offset = 0
            self.checkpoint.update(generation=generation, offset=offset)
            stream.seek(offset)
            for _ in range(500):
                position = stream.tell()
                line = stream.readline(MAX_EVENT_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_EVENT_BYTES:
                    while line and not line.endswith(b"\n"):
                        line = stream.readline(MAX_EVENT_BYTES)
                    if not line:
                        break  # retry from saved offset until writer completes
                    self.errors += 1
                    self.error = "Oversized Wazuh alert skipped"
                elif not line.endswith(b"\n"):
                    stream.seek(position)
                    break
                else:
                    try:
                        raw = safe_json(line)
                        if not isinstance(raw, dict):
                            raise ValueError("alert must be an object")
                    except ValueError:
                        self.errors += 1
                        self.error = "Malformed Wazuh alert skipped"
                    else:
                        yield raw  # failed enqueue leaves offset unchanged
                self.checkpoint["offset"] = stream.tell()
        self.status = "Error" if self.error else "Connected"
