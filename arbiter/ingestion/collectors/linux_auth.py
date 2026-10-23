"""Local OpenSSH authentication log tail, checkpointed after durable enqueue."""
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import socket

from ..base import Collector
from ..schema import SecurityEvent


AUTH = re.compile(r"\bsshd(?:-session)?\[\d+\]: (Failed|Accepted) (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)")


def parse_auth(line, identity, hostname=None, clock=None):
    match = AUTH.search(line)
    if not match:
        return None
    clock = clock or datetime.now(timezone.utc)
    # RFC3339 rsyslog format, or traditional RFC3164 local-time timestamp.
    first = line.split(" ", 1)[0]
    if "T" in first:
        stamp = datetime.fromisoformat(first.replace("Z", "+00:00"))
        if stamp.tzinfo is None: raise ValueError("log timestamp needs an offset")
    else:
        naive = datetime.strptime(f"{clock.year} {line[:15]}", "%Y %b %d %H:%M:%S")
        stamp = naive.astimezone()
        if (stamp - clock).total_seconds() > 86400:
            stamp = stamp.replace(year=stamp.year - 1)
    state, user, source, port = match.groups()
    return SecurityEvent(source_type="linux_auth", hostname=hostname or socket.gethostname(),
        event_type="auth_failure" if state == "Failed" else "auth_success",
        event_category="authentication", severity=2 if state == "Failed" else 1,
        message=f"OpenSSH {state.lower()} authentication for {user} from {source}",
        timestamp=stamp.astimezone(timezone.utc).isoformat(), username=user,
        src_ip=source, src_port=port, raw_event=line,
        event_id=hashlib.sha256(str(identity).encode()).hexdigest(),
        metadata={"normalized_by": "linux_auth"})


class LinuxAuthCollector(Collector):
    interval = 1.0

    def normalize(self, raw):
        return raw

    def collect(self):
        path = Path(self.config["path"])
        with path.open("rb") as stream:
            info = os.fstat(stream.fileno())
            generation = [str(path.resolve()), info.st_dev, info.st_ino]
            offset = int(self.checkpoint.get("offset", 0))
            if "generation" not in self.checkpoint:
                offset = 0 if self.config["read_existing"] else info.st_size
            elif self.checkpoint["generation"] != generation or info.st_size < offset:
                offset = 0
            self.checkpoint.update(generation=generation, offset=offset)
            stream.seek(offset)
            for _ in range(500):
                position = stream.tell()
                line = stream.readline(32769)
                if len(line) > 32768:
                    self.errors += 1
                    self.error = "Oversized authentication record; collection paused"
                    break
                if not line or not line.endswith(b"\n"):
                    break  # incomplete record is retried at the saved offset
                try:
                    event = parse_auth(line.decode("utf-8", errors="replace"),
                                       (generation, position, line.hex()))
                except (ValueError, OverflowError):
                    self.errors += 1
                    self.error = "Malformed authentication record skipped"
                else:
                    if event:
                        yield event  # rejected enqueue leaves the checkpoint unchanged
                self.checkpoint["offset"] = stream.tell()
