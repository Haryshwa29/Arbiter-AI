"""RFC3164/5424 datagrams. Loopback default; private bindings need allowlist."""
from __future__ import annotations

from datetime import datetime, timezone
import re
import socket

from ..base import Collector
from ..schema import SecurityEvent


def parse_syslog(text: str, peer="127.0.0.1") -> SecurityEvent:
    match = re.match(r"^<(\d{1,3})>(.*)$", text, re.S)
    if not match or not 0 <= int(match[1]) <= 191:
        raise ValueError("invalid syslog PRI")
    pri, payload = int(match[1]), match[2]
    stamp = ""
    rfc5424 = re.match(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (.*)$", payload, re.S)
    if rfc5424:
        stamp, host, app, pid, msgid, remainder = rfc5424.groups()
        structured, message = _structured(remainder)
        metadata = {"format": "RFC5424", "app_name": app, "process_id": pid, "msgid": msgid,
                    "structured_data": structured}
    else:
        legacy = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) (\S+) (.*)$", payload, re.S)
        if not legacy:
            raise ValueError("invalid RFC3164 header")
        time_part, host, message = legacy.groups()
        current = datetime.now(timezone.utc)
        dt = datetime.strptime(f"{current.year} {time_part}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        if (dt - current).days > 1:
            dt = dt.replace(year=dt.year - 1)
        stamp = dt.isoformat()
        metadata = {"format": "RFC3164", "timestamp_assumption": "current/previous year, UTC"}
    metadata.update(facility=pri // 8, priority=pri % 8, peer=peer, normalized_by="syslog")
    return SecurityEvent(source_type="syslog", hostname=host if host != "-" else peer,
        event_type="syslog_message", event_category="system", severity=[9, 8, 7, 6, 4, 2, 1, 0][pri % 8],
        timestamp="" if stamp == "-" else stamp, message=message, raw_event=text, src_ip=peer, metadata=metadata)


def _structured(remainder):
    if remainder == "-" or remainder.startswith("- "):
        return "-", remainder[2:] if len(remainder) > 1 else ""
    pos = 0
    while pos < len(remainder) and remainder[pos] == "[":
        quoted = escaped = False
        pos += 1
        while pos < len(remainder):
            char = remainder[pos]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = not quoted
            elif char == "]" and not quoted:
                pos += 1
                break
            pos += 1
        else:
            raise ValueError("unterminated syslog structured data")
    if pos == 0 or (pos < len(remainder) and remainder[pos] != " "):
        raise ValueError("invalid syslog structured data")
    return remainder[:pos], remainder[pos + 1:]


class SyslogCollector(Collector):
    interval = .1

    def __init__(self, config, checkpoint=None):
        super().__init__(config, checkpoint)
        self.sock = None

    def collect(self):
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.config.get("host", "127.0.0.1"), self.config.get("port", 5514)))
            self.sock.settimeout(.2)
        self.status = "Listening"
        import ipaddress
        allow = [ipaddress.ip_network(v) for v in self.config.get("allowed_senders", ["127.0.0.0/8"])]
        for _ in range(100):
            try:
                data, peer = self.sock.recvfrom(65536)
            except socket.timeout:
                return
            if any(ipaddress.ip_address(peer[0]) in network for network in allow):
                yield {"text": data.decode("utf-8", errors="strict"), "peer": peer[0]}
            else:
                self.errors += 1
                self.error = "Sender rejected by allowlist"

    def normalize(self, raw):
        return parse_syslog(raw["text"], raw["peer"])

    def stop(self):
        super().stop()
        if self.sock:
            self.sock.close()
            self.sock = None
