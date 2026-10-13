import json
from pathlib import Path
import socket
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from arbiter.ingestion.collectors.security import security
from arbiter.ingestion.collectors.windows import WindowsCollector
from arbiter.ingestion.correlation import correlate
from arbiter.ingestion.normalization import normalize
from arbiter.ingestion.protection import Protection
from arbiter.ingestion.schema import SecurityEvent, now
from arbiter.ingestion.service import IngestionService
from arbiter.ingestion.store import EventBuffer, SCHEMA
from arbiter.guardrails import guardrail_check
from arbiter.llm import LLMVerdict, OllamaBackend
from arbiter.memory import Memory
from arbiter.schema import Decision, Tier, Verdict
from arbiter.prefilter import prefilter
from arbiter.ingestion.evidence import own_log_query
from arbiter.store import AuditStore


def malware(host="pc", path=r"file:_C:\Temp\bad.exe"):
    return normalize({"System": {"EventID": 1116, "EventRecordID": "1", "Computer": host,
        "Channel": "Microsoft-Windows-Windows Defender/Operational", "TimeCreated": now()},
        "EventData": {"Path": path, "Threat Name": "Test malware"}}, "defender")


class ToolDecisionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.memory, self.audit = Memory(root / "memory.db"), AuditStore(root / "audit.db")
        self.service = IngestionService(root / "events.db", self.memory, self.audit)

    def tearDown(self):
        self.service.stop(); self.memory.close(); self.audit.close(); self.tmp.cleanup()

    def test_malware_cannot_be_suppressed_by_model_or_fact(self):
        event = malware()
        self.memory.add_fact("pc routine scheduled maintenance", scope="pc")
        model = Mock()
        model.triage.return_value = LLMVerdict(Decision.SUPPRESS, 1, "", "maintenance")
        self.service.pipeline.engine.llm = model
        self.service.buffer.enqueue(event, "defender")
        self.service.pipeline.process_one()
        analysis = self.service.buffer.detail(event.event_id)["analysis"]
        self.assertEqual((analysis["decision"], analysis["tier"]), ("escalate", "guardrail"))
        self.assertIn("NON_SUPPRESSIBLE_TOOL_FINDING", analysis["rationale"])
        model.triage.assert_not_called()

    def test_untrusted_normalized_upload_cannot_claim_tool_floor(self):
        event = malware()
        uploaded = normalize(event.to_dict(), "normalized").to_event()
        self.assertNotIn("_tool_finding", uploaded.fields)
        event.metadata["legacy_fields"] = {"_tool_finding": {"high_priority": True}}
        event.metadata["normalized_by"] = "legacy"
        self.assertNotIn("_tool_finding", event.to_event().fields)

    def test_osquery_detects_dangerous_startup_commands_but_not_inventory_prose(self):
        raw = {"hostname": "pc", "table": "startup_items", "rows": [{"path": "launch.exe", "command": "powershell -enc payload"}]}
        event = normalize(raw, "osquery")
        self.assertEqual(event.severity, 8)
        self.assertIsNotNone(guardrail_check(event.to_event()))
        self.assertTrue(event.metadata["security_findings"])
        raw["table"] = "programs"
        event = normalize(raw, "osquery")
        self.assertEqual(event.severity, 0)
        self.assertFalse(event.metadata["security_findings"])

    def test_posture_gaps_alert_unknowns_do_not_claim_healthy(self):
        data = {"hostname": "pc", "defender": {name: True for name in (
            "AntivirusEnabled", "RealTimeProtectionEnabled", "BehaviorMonitorEnabled", "IoavProtectionEnabled")},
            "firewall": [{"Name": "Public", "Enabled": 1}]}
        healthy = security(data)
        self.assertEqual(healthy.severity, 0)
        self.service.buffer.enqueue(healthy, "windows_security")
        self.service.pipeline.process_one()
        self.assertEqual(self.service.buffer.detail(healthy.event_id)["analysis"]["decision"], "suppress")
        data["firewall"][0]["Enabled"] = 0
        gap = security(data)
        self.assertIsNotNone(guardrail_check(gap.to_event()))
        data["firewall"][0]["Enabled"] = 2
        unknown = security(data)
        self.assertEqual(unknown.severity, 3)
        self.assertIn("unknown", unknown.message)

    def test_exact_artifact_correlates_and_wrong_host_or_path_does_not(self):
        detected = malware()
        network = SecurityEvent("sysmon", "pc", "network_connection", "connect",
            process_name=r"c:\temp\BAD.exe", process_id="7", dst_ip="8.8.8.8")
        matches = correlate(network, [detected])
        self.assertEqual(matches[0]["rule"], "malware_process_network")
        self.assertFalse(matches[0]["verified_tool_source"])
        self.assertFalse(correlate(network, [malware("another-host")]))
        self.assertFalse(correlate(network, [malware(path=r"file:_C:\Temp\bad.exe.backup")]))
        detected.metadata["_collector_origin"] = "defender"
        self.assertTrue(correlate(network, [detected])[0]["verified_tool_source"])
        self.assertEqual(correlate(detected, [network])[0]["rule"], "malware_related_process_activity")
        network.event_type = "process_exec"
        self.assertEqual(correlate(network, [detected])[0]["rule"], "malware_process_execution")

    def test_response_eligibility_requires_real_defender_transport_and_approval(self):
        host = socket.gethostname()
        finding = malware(host)
        self.service.buffer.enqueue(finding, "api")
        self.service.pipeline.process_one()
        network = SecurityEvent("sysmon", host, "network_connection", "connect",
            process_name=r"C:\Temp\bad.exe", dst_ip="8.8.8.8")
        self.service.buffer.enqueue(network, "sysmon")
        self.service.pipeline.process_one()
        firewall = Mock()
        protection = Protection(self.service.buffer, self.audit, firewall)
        self.assertIsNone(protection.proposal(self.service.buffer.detail(network.event_id)))
        # Only a collector-owned row may enable this proposal; metadata cannot spoof it.
        with self.service.buffer.lock, self.service.buffer.conn:
            self.service.buffer.conn.execute("UPDATE telemetry SET connector='defender' WHERE event_id=?", (finding.event_id,))
        second = SecurityEvent("sysmon", host, "network_connection", "connect",
            process_name=r"C:\Temp\bad.exe", dst_ip="8.8.8.8")
        self.service.buffer.enqueue(second, "sysmon")
        self.service.pipeline.process_one()
        self.assertIsNotNone(protection.proposal(self.service.buffer.detail(second.event_id)))
        firewall.block.assert_not_called()

    def test_priority_and_fifo_share_progress_without_discarding_events(self):
        oldest = SecurityEvent("test", "pc", "context", "oldest", severity=0)
        self.service.buffer.enqueue(oldest)
        for n in range(101):
            self.service.buffer.enqueue(SecurityEvent("test", "pc", "urgent", str(n), severity=10))
        claims = [self.service.buffer.claim() for _ in range(100)]
        self.assertNotEqual(claims[0]["event_id"], oldest.event_id)
        self.assertEqual(claims[99]["event_id"], oldest.event_id)
        self.assertEqual(self.service.buffer.metrics()["events_ingested"], 102)

    def test_old_store_migration_preserves_verdict_and_backfills_metrics(self):
        path = Path(self.tmp.name) / "old.db"
        old_schema = SCHEMA.replace(",\n decision TEXT, tier TEXT, priority REAL", "")
        conn = sqlite3.connect(path)
        conn.executescript(old_schema)
        event = malware()
        conn.execute("INSERT INTO telemetry(event_id,received_at,timestamp,source,host,severity,category,username,src_ip,dst_ip,connector,cloud_account,payload,state,due_at,analysis,latency_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event.event_id, event.received_at, event.timestamp, "defender", "pc", 8, "security", "", "", "", "defender", "", event.to_json(), "done", now(), json.dumps({"decision": "escalate", "tier": "guardrail"}), 12))
        conn.commit(); conn.close()
        migrated = EventBuffer(path)
        try:
            self.assertEqual(migrated.metrics()["alerts_created"], 1)
            self.assertEqual(migrated.detail(event.event_id)["analysis"]["decision"], "escalate")
            plan = " ".join(str(tuple(r)) for r in migrated.conn.execute("EXPLAIN QUERY PLAN SELECT COUNT(*),MAX(received_at) FROM telemetry WHERE connector='defender'"))
            self.assertIn("COVERING INDEX", plan)
        finally: migrated.close()

    def test_windows_query_timeout_is_retryable(self):
        import subprocess
        collector = WindowsCollector({"adapter": "sysmon"})
        with patch("arbiter.ingestion.collectors.windows.subprocess.run", side_effect=subprocess.TimeoutExpired("wevtutil", 15)):
            with self.assertRaises(OSError): collector._query("test")

    def test_broad_host_history_does_not_suppress_a_new_executable(self):
        event = SecurityEvent("sysmon", "pc", "process_exec", "New executable", severity=1,
            process_name=r"C:\Temp\new.exe", metadata={"normalized_by": "sysmon"}).to_event()
        for n in range(6):
            self.memory.record_verdict(Verdict(str(n), event.signature, Decision.SUPPRESS, 1, Tier.LLM, "different benign executable"))
        self.assertEqual(prefilter(event, self.memory).decision, Decision.AMBIGUOUS)

    def test_cached_history_observes_external_feedback_and_cannot_be_mutated(self):
        verdict = Verdict("one", "signature", Decision.SUPPRESS, 1, Tier.LLM, "benign")
        self.memory.record_verdict(verdict)
        first = self.memory.history("signature")
        first.total = 999
        self.assertEqual(self.memory.history("signature").total, 1)
        other = Memory(Path(self.tmp.name) / "memory.db")
        try:
            other.label_verdicts("signature", "overruled")
            self.assertEqual(self.memory.history("signature").overruled, 1)
            other.record_verdict(Verdict("two", "signature", Decision.ESCALATE, 8, Tier.GUARDRAIL, "dangerous"))
            self.assertEqual(self.memory.history("signature").total, 2)
        finally: other.close()

    def test_exact_process_learning_requires_five_real_model_assessments(self):
        model = Mock(name="local-model")
        model.name, model.model = "ollama", "test-local"
        model.triage.return_value = LLMVerdict(Decision.SUPPRESS, .99, "Exact process assessed", "Expected worker")
        self.service.pipeline.engine.llm = model
        def submit(command="app.exe --worker", digest="a", user="alice"):
            event = SecurityEvent("sysmon", "pc", "process_exec", command, severity=1,
                process_name=r"C:\Apps\app.exe", command_line=command, username=user,
                parent_process=r"C:\Apps\launcher.exe", file_hash="SHA256=" + digest * 64,
                metadata={"normalized_by": "sysmon"})
            self.service.buffer.enqueue(event, "sysmon")
            self.service.pipeline.process_one()
            return self.service.buffer.detail(event.event_id)["analysis"]
        for _ in range(5): self.assertEqual(submit()["tier"], "llm")
        learned = submit()
        self.assertEqual(learned["tier"], "prefilter")
        self.assertIn("Exact native process hash", learned["rationale"])
        self.assertEqual(submit(digest="b")["tier"], "llm")
        self.assertEqual(submit(user="another-user")["tier"], "llm")
        self.assertEqual(submit(command="app.exe --new-action")["tier"], "llm")
        self.memory.label_verdicts("sysmon:process_exec:pc", "overruled")
        self.assertEqual(submit()["tier"], "llm")

    def test_cheap_context_is_processed_before_ambiguous_model_work(self):
        ambiguous = SecurityEvent("sysmon", "pc", "process_exec", "New program", severity=1,
            process_name=r"C:\Apps\unknown.exe", metadata={"normalized_by": "sysmon"})
        passive = SecurityEvent("sysmon", "pc", "dns_query", "DNS context", severity=0,
            metadata={"normalized_by": "sysmon"})
        self.service.buffer.enqueue(ambiguous)
        self.service.buffer.enqueue(passive)
        self.assertEqual(self.service.buffer.claim()["event_id"], passive.event_id)

    def test_recovery_preserves_recorded_reasoning_backend(self):
        event = SecurityEvent("test", "pc", "unknown", "neutral", severity=4)
        self.service.buffer.enqueue(event)
        self.service.pipeline.process_one()
        self.assertEqual(self.service.buffer.detail(event.event_id)["analysis"]["backend"], "mock")
        model = Mock()
        model.name, model.model = "ollama", "test-local"
        self.service.pipeline.engine.llm = model
        with self.service.buffer.lock, self.service.buffer.conn:
            self.service.buffer.conn.execute("UPDATE telemetry SET state='pending' WHERE event_id=?", (event.event_id,))
        self.service.pipeline.process_one()
        self.assertEqual(self.service.buffer.detail(event.event_id)["analysis"]["backend"], "mock")
        model.triage.assert_not_called()

    def test_only_owned_fixed_log_reads_are_cheap_not_arbitrary_wevtutil(self):
        import os
        import sys
        import subprocess
        image = os.environ.get("SystemRoot", r"C:\Windows").rstrip("\\/") + r"\System32\wevtutil.exe"
        args = [image, "qe", "Security", "/f:xml", "/uni:true", "/rd:false", "/c:200", "/q:*[System[(EventRecordID > 123)]]"]
        event = SecurityEvent("sysmon", socket.gethostname(), "process_exec", "read log", severity=1,
            process_name=image, command_line=subprocess.list2cmdline(args), parent_process=sys.executable,
            metadata={"normalized_by": "sysmon", "legacy_fields": {"ParentProcessId": str(os.getpid())}})
        self.assertTrue(own_log_query(event, "sysmon"))
        self.assertFalse(own_log_query(event, "api"))
        event.metadata["legacy_fields"]["ParentProcessId"] = "another-process"
        self.assertFalse(own_log_query(event, "sysmon"))
        event.metadata["legacy_fields"]["ParentCommandLine"] = ' '.join('"' + str(arg) + '"' for arg in sys.orig_argv)
        self.assertTrue(own_log_query(event, "sysmon"))
        event.command_line = subprocess.list2cmdline([image, "cl", "Security"])
        self.assertFalse(own_log_query(event, "sysmon"))

    def test_non_finite_model_confidence_fails_toward_escalation(self):
        model = Mock()
        model.triage.return_value = LLMVerdict(Decision.SUPPRESS, float('nan'), "", "benign")
        self.service.pipeline.engine.llm = model
        event = SecurityEvent("test", "pc", "unknown", "neutral", severity=4)
        self.service.buffer.enqueue(event)
        self.service.pipeline.process_one()
        self.assertEqual(self.service.buffer.detail(event.event_id)["analysis"]["decision"], "escalate")

    def test_remote_alias_is_rejected_before_event_data_is_sent(self):
        import io
        backend = OllamaBackend("apparently-local")
        backend._opener = Mock()
        backend._opener.open.side_effect = [io.BytesIO(json.dumps({"models": [{"name": "apparently-local"}]}).encode()),
            io.BytesIO(json.dumps({"remote_host": "https://ollama.com", "remote_model": "remote"}).encode())]
        event = SecurityEvent("test", "pc", "unknown", "PRIVATE_EVENT_SENTINEL").to_event()
        with self.assertRaises(ValueError): backend.triage(event, 1, "", [])
        request = backend._opener.open.call_args.args[0]
        self.assertNotIn(b"PRIVATE_EVENT_SENTINEL", request.data)
        self.assertEqual(backend._opener.open.call_count, 2)

    def test_cloud_named_model_never_contacts_the_service(self):
        backend = OllamaBackend("nemotron:cloud")
        backend._opener = Mock()
        with self.assertRaises(ValueError): backend.triage(SecurityEvent("test", "pc", "unknown", "private").to_event(), 1, "", [])
        backend._opener.open.assert_not_called()

    def test_older_healthy_posture_cannot_overwrite_newer_disabled_control(self):
        data = {"hostname": "pc", "defender": {name: True for name in (
            "AntivirusEnabled", "RealTimeProtectionEnabled", "BehaviorMonitorEnabled", "IoavProtectionEnabled")},
            "firewall": [{"Name": "Public", "Enabled": 1}]}
        older = security(data)
        older.received_at = "2026-10-12T10:00:00+00:00"
        data["firewall"][0]["Enabled"] = 0
        newer = security(data)
        newer.received_at = "2026-10-12T11:00:00+00:00"
        self.service.buffer.asset(newer)
        self.service.buffer.asset(older)
        asset = self.service.buffer.assets()[0]
        self.assertEqual(asset["last_seen"], newer.received_at)
        self.assertEqual(asset["context"]["protection_status"]["firewall"][0]["Enabled"], 0)
