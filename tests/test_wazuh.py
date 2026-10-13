"""Wazuh integration checks use isolated files and databases only."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from arbiter.guardrails import guardrail_check
from arbiter.ingestion.collectors.wazuh import WazuhCollector
from arbiter.ingestion.normalization import normalize
from arbiter.ingestion.protection import Protection
from arbiter.ingestion.registry import default_registry
from arbiter.ingestion.schema import MAX_EVENT_BYTES
from arbiter.ingestion.service import IngestionService
from arbiter.ingestion.store import BufferFull
from arbiter.memory import Memory
from arbiter.store import AuditStore


ALERT = {"timestamp": "2026-10-11T12:00:00.000+0000", "id": "1791720000.1",
    "rule": {"id": "5710", "level": 10, "description": "SSH authentication failed",
             "groups": ["sshd", "authentication_failed"], "mitre": {"id": ["T1110"]}},
    "agent": {"id": "001", "name": "server-01", "ip": "192.168.1.10"},
    "manager": {"name": "wazuh-01"}, "data": {"srcip": "192.168.1.20", "dstuser": "alice", "srcport": "4242"}}


class WazuhTests(unittest.TestCase):
    def test_mapping_identity_and_raw_evidence(self):
        event = normalize(ALERT)
        self.assertEqual(event.source_type, "wazuh")
        self.assertEqual((event.hostname, event.device_id, event.event_type), ("server-01", "001", "auth_failure"))
        self.assertEqual((event.username, event.src_ip, event.src_port), ("alice", "192.168.1.20", 4242))
        self.assertAlmostEqual(event.severity, 10 * 10 / 15)
        self.assertEqual(event.raw_event, ALERT)
        self.assertEqual(event.event_id, normalize(deepcopy(ALERT)).event_id)
        other = deepcopy(ALERT); other["manager"]["name"] = "another-manager"
        self.assertNotEqual(event.event_id, normalize(other).event_id)
        self.assertEqual(event.timestamp, "2026-10-11T12:00:00+00:00")

    def test_file_integrity_and_guardrail_evidence(self):
        raw = deepcopy(ALERT)
        raw["rule"]["groups"] = ["syscheck"]
        raw["syscheck"] = {"path": "/etc/passwd", "sha256_after": "abc", "event": "modified"}
        event = normalize(raw, "wazuh")
        self.assertEqual((event.event_type, event.file_path, event.file_hash), ("file_change", "/etc/passwd", "abc"))
        raw["rule"]["description"] = "Routine activity"
        raw["data"] = {"command": "powershell -enc payload"}
        self.assertIsNotNone(guardrail_check(normalize(raw, "wazuh").to_event()))

    def test_invalid_records_and_severity(self):
        for level in (-1, 16, True, "10", float("nan"), 3.5):
            raw = deepcopy(ALERT); raw["rule"]["level"] = level
            with self.assertRaises(ValueError): normalize(raw, "wazuh")
        for key, value in (("agent", []), ("data", []), ("syscheck", "bad"), ("timestamp", "bad")):
            raw = deepcopy(ALERT); raw[key] = value
            with self.assertRaises(ValueError): normalize(raw, "wazuh")

    def test_tail_partial_resume_rotation_and_queue_pressure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alerts.json"
            line = json.dumps(ALERT).encode() + b"\n"
            path.write_bytes(line + line[:30])
            config = {"path": str(path), "read_existing": True, "adapter": "wazuh"}
            collector = WazuhCollector(config)
            self.assertEqual(len(list(collector.collect())), 1)
            self.assertEqual(collector.checkpoint["offset"], len(line))
            with path.open("ab") as stream: stream.write(line[30:])
            resumed = WazuhCollector(config, collector.checkpoint)
            self.assertEqual(len(list(resumed.collect())), 1)
            # The generator must not commit a record rejected by the queue.
            path.write_bytes(line)
            pressured = WazuhCollector(config)
            iterator = pressured.collect(); next(iterator); iterator.close()
            self.assertEqual(pressured.checkpoint["offset"], 0)
            self.assertEqual(len(list(pressured.collect())), 1)
            path.replace(Path(tmp) / "alerts.old")
            path.write_bytes(line)
            self.assertEqual(len(list(resumed.collect())), 1)

    def test_new_only_and_bad_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alerts.json"
            line = json.dumps(ALERT).encode() + b"\n"
            path.write_bytes(line)
            collector = WazuhCollector({"path": str(path), "read_existing": False})
            self.assertEqual(list(collector.collect()), [])
            with path.open("ab") as stream:
                stream.write(b"bad\n[]\n" + b"x" * (MAX_EVENT_BYTES + 1) + b"\n" + line)
            self.assertEqual(len(list(collector.collect())), 1)
            self.assertEqual(collector.errors, 3)
            self.assertEqual(collector.checkpoint["offset"], path.stat().st_size)

    def test_registry_and_pipeline_no_protection(self):
        registry = default_registry()
        self.assertTrue(registry.get("wazuh").implemented)
        for config in ({"path": "relative.json"}, {"path": "/tmp/x", "token": "secret"}, {"read_existing": "yes"}):
            with self.assertRaises(ValueError): registry.validate("wazuh", config)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mem, audit = Memory(root / "memory.db"), AuditStore(root / "audit.db")
            service = IngestionService(root / "events.db", mem, audit, capacity=1)
            try:
                raw = deepcopy(ALERT); raw["rule"]["level"] = 15
                self.assertTrue(service.submit(raw, "wazuh", "wazuh"))
                self.assertFalse(service.submit(raw, "wazuh", "wazuh"))
                other = deepcopy(raw); other["id"] = "another"
                with self.assertRaises(BufferFull): service.submit(other, "wazuh", "wazuh")
                self.assertTrue(service.pipeline.process_one())
                row = service.buffer.detail(normalize(raw).event_id)
                self.assertEqual(row["state"], "done")
                self.assertEqual(row["analysis"]["decision"], "escalate")
                self.assertEqual(len(audit.query()), 1)
                self.assertTrue(row["analysis"]["rationale"])
                self.assertIsNone(Protection(service.buffer, audit).proposal(row))
                self.assertFalse(any(c["enabled"] for c in service.status()["connectors"] if c["name"] == "wazuh"))
            finally:
                service.stop(); mem.close(); audit.close()
