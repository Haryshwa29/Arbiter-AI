"""Telemetry tests use fixtures, temporary stores and fake APIs, never credentials."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from arbiter.ingestion.collectors.aws import AWSCollector
from arbiter.ingestion.collectors.suricata import SuricataCollector
from arbiter.ingestion.collectors.syslog import SyslogCollector, parse_syslog
from arbiter.ingestion.collectors.windows import WindowsCollector, parse_xml
from arbiter.ingestion.correlation import correlate
from arbiter.ingestion.files import parse_upload, schedule
from arbiter.ingestion.normalization import normalize
from arbiter.ingestion.registry import default_registry
from arbiter.ingestion.schema import SecurityEvent, now, safe_json
from arbiter.ingestion.service import IngestionService
from arbiter.ingestion.store import BufferFull, EventBuffer
from arbiter.memory import Memory
from arbiter.schema import Event
from arbiter.store import AuditStore
from tests.test_api import Client
from arbiter.api.server import Ctx, Hub, build_httpd
from arbiter.iam import IAM

FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "telemetry.json").read_text())


class NormalizationTests(unittest.TestCase):
    def test_legacy_and_labelled_case_preserve_signature_fields(self):
        ev = Event("sshd", "lab", "auth_failure", "failed", 4, fields={"user": "alice", "src_ip": "10.0.0.1"})
        event = normalize({"event": json.loads(ev.to_json()), "expected": "escalate"})
        self.assertEqual(event.to_event().signature, ev.signature)
        self.assertEqual(event.to_event().fields["user"], "alice")
        self.assertNotIn("_telemetry", event.to_event().fields)
        self.assertEqual(event.raw_event["expected"], "escalate")

    def test_windows_mapping_not_alert_by_event_id(self):
        event = normalize(FIXTURES["windows"])
        self.assertEqual((event.event_type, event.username, event.src_ip), ("auth_failure", "lab-user", "192.168.1.20"))
        self.assertEqual(event.severity, 2)
        self.assertEqual(event.schema_version, "1.0")

    def test_sysmon_mapping(self):
        event = normalize(FIXTURES["sysmon"])
        self.assertEqual(event.source_type, "sysmon")
        self.assertEqual(event.process_id, "400")
        self.assertEqual(event.to_event().fields["process"], r"C:\Windows\System32\cmd.exe")

    def test_group_membership_correlates_member_sid_not_group_name(self):
        system = FIXTURES["windows"]["System"]
        created = normalize({"System": {**system, "EventID": 4720}, "EventData": {"TargetUserName": "alice", "TargetUserSid": "S-1-5-21-123-1001"}}, "windows")
        group = normalize({"System": {**system, "EventID": 4732, "EventRecordID": 13}, "EventData": {"TargetUserName": "Administrators", "MemberName": "CN=alice,OU=Lab", "MemberSid": "S-1-5-21-123-1001"}}, "windows")
        self.assertEqual(group.username, "CN=alice,OU=Lab")
        self.assertEqual(correlate(group, [created])[0]["rule"], "new_user_group_change")

    def test_windows_xml_namespaced_and_user_data(self):
        text = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4624</EventID><EventRecordID>1</EventRecordID><Computer>pc</Computer><Channel>Security</Channel><TimeCreated SystemTime="2026-10-09T12:00:00Z"/></System><EventData><Data Name="TargetUserName">test</Data></EventData></Event>'
        records = parse_xml(text)
        self.assertEqual(normalize(records[0], "windows").username, "test")
        with self.assertRaises(ValueError):
            parse_xml('<!DOCTYPE x [<!ENTITY xx "danger">]><Event/>')

    def test_all_sysmon_and_windows_prioritized_types(self):
        from arbiter.ingestion.normalization import SYSMON_TYPES, WINDOWS_TYPES
        for source, types in [("windows", WINDOWS_TYPES), ("sysmon", SYSMON_TYPES)]:
            for eid, (kind, category, _) in types.items():
                data = {"System": {**FIXTURES[source]["System"], "EventID": eid}, "EventData": {}}
                event = normalize(data, source)
                self.assertEqual((event.event_type, event.event_category), (kind, category))

    def test_suricata_supported_types_and_severity(self):
        event = normalize(FIXTURES["suricata"])
        self.assertEqual(event.rule_id, "1")
        self.assertEqual(event.severity, 5)
        for kind in ("dns", "http", "tls", "flow", "fileinfo"):
            data = {**FIXTURES["suricata"], "event_type": kind}
            self.assertEqual(normalize(data).severity, 0)

    def test_cloudtrail_aws_envelope_and_null_response(self):
        event = normalize({"CloudTrailEvent": json.dumps(FIXTURES["cloudtrail"]), "EventTime": datetime.now(timezone.utc)})
        self.assertEqual(event.event_type, "iam_change")
        self.assertEqual(event.action, "CreateUser")
        self.assertEqual(event.cloud_account, "123456789012")
        self.assertEqual(event.severity, 4)

    def test_guardduty_updated_findings_have_distinct_identity(self):
        first = normalize(FIXTURES["guardduty"])
        updated = normalize({**FIXTURES["guardduty"], "UpdatedAt": now()})
        self.assertEqual(first.severity, 5)
        self.assertEqual(first.resource_id, "i-fixture")
        self.assertNotEqual(first.event_id, updated.event_id)

    def test_readonly_cloud_context_is_routine_but_secret_reads_are_not(self):
        from arbiter.prefilter import routine_telemetry
        raw = {**FIXTURES["cloudtrail"], "eventName": "DescribeInstances", "eventSource": "ec2.amazonaws.com", "readOnly": True}
        self.assertTrue(routine_telemetry(normalize(raw, "cloudtrail").to_event()))
        secret = {**raw, "eventName": "GetSecretValue", "eventSource": "secretsmanager.amazonaws.com"}
        self.assertFalse(routine_telemetry(normalize(secret, "cloudtrail").to_event()))
        failed = {**raw, "errorCode": "AccessDenied"}
        self.assertFalse(routine_telemetry(normalize(failed, "cloudtrail").to_event()))

    def test_validation(self):
        for value in ([], None, "text", {"source": "sshd"}):
            with self.assertRaises((ValueError, TypeError)):
                normalize(value)
        for severity in (-1, 11, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                normalize({"source": "test", "host": "lab", "event_type": "test", "message": "x", "severity": severity})
        with self.assertRaises(ValueError):
            SecurityEvent("test", "lab", "test", "x", schema_version="2.0")
        with self.assertRaises(ValueError):
            SecurityEvent("test", "lab", "test", "x", dst_port=99999)
        with self.assertRaises(ValueError):
            safe_json('{"severity":NaN}')

    def test_error_level_is_not_filtered_as_routine(self):
        from arbiter.prefilter import routine_telemetry
        raw = {"System": {**FIXTURES["windows"]["System"], "EventID": 1000, "Level": 2}, "EventData": {}}
        self.assertFalse(routine_telemetry(normalize(raw, "windows").to_event()))

    def test_normalized_upload_cannot_claim_trusted_provenance(self):
        event = normalize(FIXTURES["sysmon"])
        uploaded = normalize(event.to_dict())
        self.assertNotIn("_telemetry", uploaded.to_event().fields)

    def test_rendered_message_cannot_hide_command_line_guardrail(self):
        from arbiter.guardrails import guardrail_check
        raw = {**FIXTURES["sysmon"], "Message": "Routine launch", "EventData": {"CommandLine": "powershell -enc payload"}}
        self.assertIsNotNone(guardrail_check(normalize(raw, "sysmon").to_event()))


class FileTests(unittest.TestCase):
    def test_json_jsonl_csv_and_invalid_counts(self):
        raw = {"source": "test", "host": "lab", "event_type": "test", "message": "x"}
        self.assertEqual(len(parse_upload("events.json", json.dumps([raw])).events), 1)
        result = parse_upload("events.jsonl", json.dumps(raw) + '\nnot-json\n[]\n')
        self.assertEqual((len(result.events), result.invalid_events), (1, 2))
        self.assertEqual(len(parse_upload("events.csv", "source,host,event_type,message,severity\ntest,lab,test,x,2\n").events), 1)
        self.assertEqual(len(parse_upload("cloud.json", json.dumps({"Records": [FIXTURES["cloudtrail"]]})).events), 1)

    def test_paths_formats_and_limits_rejected(self):
        for name in ("../events.json", r"..\events.json", "C:events.json", "evil.exe"):
            with self.assertRaises(ValueError):
                parse_upload(name, "{}")
        with self.assertRaises(ValueError):
            parse_upload("events.json", "x" * (5 * 1024 * 1024 + 1))
        with self.assertRaises(ValueError):
            parse_upload("events.json", json.dumps([{}] * 5001))
        with self.assertRaises(ValueError):
            parse_upload("events.csv", "message\n" + "x" * 200000)

    def test_replay_timing_and_original_timestamp(self):
        a = SecurityEvent("test", "lab", "test", "a", timestamp="2026-10-09T12:00:00Z")
        b = SecurityEvent("test", "lab", "test", "b", timestamp="2026-10-09T12:00:10Z")
        old_id = a.event_id
        rows = list(schedule([b, a], "2x"))
        self.assertEqual((datetime.fromisoformat(rows[1][1]) - datetime.fromisoformat(rows[0][1])).total_seconds(), 5)
        self.assertNotEqual(a.event_id, old_id)
        self.assertEqual(a.timestamp, "2026-10-09T12:00:00+00:00")

    def test_every_existing_dataset_normalizes(self):
        root = Path(__file__).resolve().parents[1]
        for file in (root / "samples").glob("*.jsonl"):
            result = parse_upload(file.name, file.read_text())
            self.assertEqual(result.invalid_events, 0, (file.name, result.errors))


class RegistryTests(unittest.TestCase):
    def test_catalog_and_duplicate_validation(self):
        registry = default_registry()
        self.assertIn("windows", registry.specs)
        with self.assertRaises(ValueError):
            registry.register(registry.get("windows"))
        for name in ("zeek", "azure", "gcp", "security_hub"):
            self.assertFalse(registry.get(name).implemented)
            with self.assertRaises(ValueError):
                registry.create(name, {})

    def test_no_secrets_and_no_public_listener(self):
        registry = default_registry()
        with self.assertRaises(ValueError):
            registry.validate("cloudtrail", {"access_key": "never-store"})
        for host in ("0.0.0.0", "8.8.8.8", "::", "localhost"):
            with self.assertRaises(ValueError):
                registry.validate("syslog", {"host": host})
        self.assertEqual(registry.validate("syslog", {})["host"], "127.0.0.1")
        with self.assertRaises(ValueError):
            registry.validate("osquery", {"path": str(Path.cwd() / "powershell.exe")})


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.mem = Memory(root / "memory.db")
        self.audit = AuditStore(root / "audit.db")
        self.service = IngestionService(root / "events.db", self.mem, self.audit)

    def tearDown(self):
        self.service.stop()
        self.mem.close(); self.audit.close(); self.tmp.cleanup()

    def drain(self):
        while self.service.pipeline.process_one():
            pass

    def test_routine_and_guardrail_share_engine_no_ai_for_routine(self):
        routine = normalize(FIXTURES["sysmon"])
        malicious = normalize({**FIXTURES["sysmon"], "System": {**FIXTURES["sysmon"]["System"], "EventRecordID": "21"},
            "EventData": {"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": "powershell -enc attack"}})
        self.service.pipeline.engine.llm = Mock(side_effect=AssertionError("LLM should not run"))
        self.service.buffer.enqueue(routine); self.service.buffer.enqueue(malicious)
        self.drain()
        rows = self.service.buffer.query()
        self.assertEqual(rows[0]["analysis"]["kind"], "alert")
        self.assertEqual(rows[0]["analysis"]["tier"], "guardrail")
        self.assertEqual(rows[1]["analysis"]["kind"], "observation")
        self.assertEqual(self.service.buffer.metrics()["events_escalated_to_ai"], 0)
        self.assertEqual(len(self.audit.query()), 2)

    def test_queue_bound_dedupe_and_atomic_import(self):
        self.service.buffer.capacity = 1
        event = normalize(FIXTURES["windows"])
        self.assertTrue(self.service.buffer.enqueue(event))
        self.assertFalse(self.service.buffer.enqueue(event))
        with self.assertRaises(BufferFull):
            self.service.buffer.enqueue(normalize(FIXTURES["sysmon"]))
        with self.assertRaises(BufferFull):
            self.service.import_file("events.json", json.dumps(FIXTURES["sysmon"]))
        self.assertEqual(self.service.buffer.metrics()["events_ingested"], 1)

    def test_recovery_and_scheduled_replay(self):
        event = normalize(FIXTURES["windows"])
        self.service.buffer.enqueue(event)
        claimed = self.service.buffer.claim()
        self.assertIsNotNone(claimed)
        path = Path(self.tmp.name) / "events.db"
        self.service.buffer.close()
        self.service.buffer = EventBuffer(path)
        self.service.pipeline.buffer = self.service.buffer
        self.drain()
        self.assertEqual(self.service.buffer.detail(event.event_id)["state"], "done")
        future = SecurityEvent("test", "lab", "test", "later")
        self.service.buffer.enqueue(future, due_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
        self.assertIsNone(self.service.buffer.claim())

    def test_failed_then_success_login_correlation(self):
        for n in range(6):
            raw = {"System": {**FIXTURES["windows"]["System"], "EventRecordID": str(30 + n), "EventID": "4625" if n < 5 else "4624"},
                   "EventData": FIXTURES["windows"]["EventData"]}
            self.service.buffer.enqueue(normalize(raw, "windows"))
            self.drain()
        row = self.service.buffer.query()[0]
        self.assertEqual(row["analysis"]["kind"], "alert")
        self.assertEqual(len(row["related"]), 5)
        self.assertEqual(row["analysis"]["correlation"][0]["rule"], "failed_then_successful_login")

    def test_import_preview_is_read_only_and_legacy_pipeline_compatible(self):
        raw = {"source": "sshd", "host": "lab", "event_type": "auth_bruteforce", "message": "failed logins", "severity": 9}
        preview = self.service.import_file("demo.json", json.dumps(raw), preview=True)
        self.assertEqual(preview["valid_events"], 1)
        self.assertEqual(self.service.buffer.metrics()["events_ingested"], 0)
        result = self.service.import_file("demo.json", json.dumps(raw))
        self.assertEqual(result["accepted_events"], 1)
        self.drain()
        self.assertEqual(self.service.buffer.query()[0]["analysis"]["tier"], "prefilter")

    def test_osquery_asset_context_does_not_overwrite_curated_criticality(self):
        self.mem.upsert_asset("lab-pc", 2, "protected", True)
        self.service.submit({"hostname": "lab-pc", "table": "listening_ports", "rows": [{"port": "80"}]}, "osquery")
        self.drain()
        self.assertEqual(self.mem.asset_criticality("lab-pc"), 2)
        self.assertEqual(self.service.buffer.assets()[0]["context"]["listening_ports"][0]["port"], "80")
        self.assertEqual(self.service.buffer.asset_summary(normalize(FIXTURES["windows"]))["listening_ports"], ["80"])
        self.assertEqual(self.service.buffer.assets()[0]["context"]["ip_addresses"], [])

    def test_completed_verdict_reused_after_worker_recovery(self):
        event = normalize(FIXTURES["windows"])
        self.service.buffer.enqueue(event)
        self.drain()
        with self.service.buffer.lock, self.service.buffer.conn:
            self.service.buffer.conn.execute("UPDATE telemetry SET state='pending'")
        self.service.pipeline.engine.triage = Mock(side_effect=AssertionError("must reuse verdict"))
        self.drain()
        self.assertEqual(len(self.audit.query()), 1)
        self.assertEqual(self.service.buffer.query()[0]["state"], "done")


class CollectorTests(unittest.TestCase):
    def test_suricata_partial_line_checkpoint_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "eve.json"
            path.write_text(json.dumps(FIXTURES["suricata"]) + '\n{"unfinished":')
            collector = SuricataCollector({"adapter": "suricata", "path": str(path)})
            records = list(collector.collect())
            self.assertEqual(len(records), 1)
            offset = collector.checkpoint["offset"]
            self.assertGreater(offset, 0)
            self.assertEqual(list(collector.collect()), [])
            path.write_text('{}\n')
            list(collector.collect())
            self.assertEqual(collector.checkpoint["offset"], path.stat().st_size)

    def test_windows_first_enable_skips_history_and_queries_fixed_channels(self):
        collector = WindowsCollector({"adapter": "windows", "channels": ["System"], "read_existing": False})
        record = {**FIXTURES["windows"], "System": {**FIXTURES["windows"]["System"], "EventRecordID": "100"}}
        collector._query = Mock(side_effect=[[record], []])
        self.assertEqual(list(collector.collect()), [])
        self.assertEqual(collector.checkpoint["System"], 100)

    def test_cloudtrail_pagination_and_checkpoint(self):
        collector = AWSCollector({"adapter": "cloudtrail", "region": "us-east-1"})
        collector.client = Mock()
        collector.client.lookup_events.side_effect = [{"Events": [{"CloudTrailEvent": json.dumps(FIXTURES["cloudtrail"])}], "NextToken": "next"}, {"Events": []}]
        with patch.object(collector.stop_event, "wait", return_value=False):
            records = list(collector.collect())
        self.assertEqual(len(records), 1)
        self.assertEqual(collector.client.lookup_events.call_args_list[1].kwargs["NextToken"], "next")
        self.assertIn("since", collector.checkpoint)

    def test_guardduty_fake_api_no_credentials(self):
        collector = AWSCollector({"adapter": "guardduty", "region": "us-east-1", "detector_id": "fixture"})
        collector.client = Mock()
        collector.client.list_findings.return_value = {"FindingIds": ["sample"]}
        collector.client.get_findings.return_value = {"Findings": [FIXTURES["guardduty"]]}
        self.assertEqual(len(list(collector.collect())), 1)
        self.assertEqual(collector.client.get_findings.call_args.kwargs["FindingIds"], ["sample"])

    def test_rfc3164_and_rfc5424(self):
        first = parse_syslog('<34>Oct  9 12:00:00 lab sshd: failed login', "192.168.1.1")
        self.assertEqual(first.hostname, "lab")
        second = parse_syslog('<165>1 2026-10-09T12:00:00Z lab app 123 ID [example x="a\\]b"][next y="z"] hello')
        self.assertEqual(second.message, "hello")
        self.assertEqual(second.metadata["format"], "RFC5424")
        for malformed in ("bad log", "<999>bad", '<165>1 - lab app - - [unclosed'):
            with self.assertRaises(ValueError):
                parse_syslog(malformed)

    def test_real_loopback_syslog_datagram(self):
        collector = SyslogCollector({"adapter": "syslog", "host": "127.0.0.1", "port": 0, "allowed_senders": ["127.0.0.0/8"]})
        try:
            list(collector.collect())
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sender.sendto(b'<165>1 - lab app - - - hello', collector.sock.getsockname())
            records = list(collector.collect())
            self.assertEqual(collector.normalize(records[0]).message, "hello")
        finally:
            collector.stop()


class IngestionApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.mem, self.audit = Memory(root / "memory.db"), AuditStore(root / "audit.db")
        self.iam = IAM(root / "iam.db", secret=b"x" * 32)
        self.iam.create_user("admin", "test-password", "admin")
        self.iam.create_user("analyst", "test-password", "analyst")
        self.service = IngestionService(root / "events.db", self.mem, self.audit)
        from arbiter.ingestion.demo import DemoManager
        self.simulator = DemoManager()
        self.ctx = Ctx(self.audit, self.iam, self.mem, Hub(), ingestion=self.service, simulator=self.simulator)
        self.server = build_httpd(self.ctx, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = Client(self.server.server_port)

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(2)
        self.simulator.close(); self.service.stop(); self.mem.close(); self.audit.close(); self.iam.close(); self.tmp.cleanup()

    def login(self, user="admin"):
        self.client.get("/api/me")
        return self.client.post("/api/login", {"username": user, "password": "test-password"})

    def test_auth_and_csrf_and_admin_gate(self):
        self.assertEqual(self.client.get("/api/events")[0], 401)
        self.assertEqual(self.client.get("/health")[0], 401)
        self.login("analyst")
        self.assertEqual(self.client.get("/api/ingestion/status")[0], 200)
        self.assertEqual(self.client.post("/api/ingestion/configure", {"name": "windows", "enabled": False})[0], 403)
        self.login()
        self.assertEqual(self.client.post("/api/ingestion/import", {}, csrf=False)[0], 403)

    def test_l1_response_routes_require_session_csrf_and_admin(self):
        from arbiter.ingestion.response_workflow import ResponseWorkflow
        self.ctx.responses = ResponseWorkflow(self.service.buffer, self.audit)
        self.assertEqual(self.client.get("/api/response/status")[0], 401)
        self.login("analyst")
        self.assertEqual(self.client.get("/api/response/status")[0], 200)
        self.assertEqual(self.client.post("/api/response/control", {"command": "stop"})[0], 403)
        self.login()
        self.assertEqual(self.client.post("/api/response/control", {"command": "stop"}, csrf=False)[0], 403)
        self.assertEqual(self.client.post("/api/response/control", {"command": "stop"})[0], 200)
        self.assertTrue(self.client.get("/api/response/status")[1]["stopped"])
        self.assertEqual(self.client.post("/api/response/control", {"command": "schedule", "event_id": "missing"})[0], 400)
        self.assertEqual(self.client.post("/api/response/control", {"command": "resume"})[0], 200)

    def test_l1_event_detail_returns_durable_review_and_guidance(self):
        from arbiter.ingestion.response_workflow import ResponseWorkflow
        self.ctx.responses = ResponseWorkflow(self.service.buffer, self.audit)
        event = SecurityEvent(source_type="dpkg", hostname="test-db", event_type="package_update", message="Update", severity=5)
        self.service.buffer.enqueue(event, "api")
        row = self.service.buffer.claim()
        self.service.buffer.finish(row["id"], {"decision": "escalate", "tier": "llm", "score": 5, "rationale": "Review update", "evidence": "package update", "backend": "mock"}, [], 0)
        self.login()
        code, detail = self.client.get("/api/event?id=" + event.event_id)
        self.assertEqual(code, 200)
        self.assertEqual(detail["response_case"]["severity"], "medium")
        self.assertEqual(detail["analysis"]["guidance"]["source"], "policy")
        self.assertEqual(self.client.post("/api/response/control", {"event_id": event.event_id, "command": "reviewed", "reason": "Approved maintenance"})[0], 200)
        self.assertEqual(self.client.get("/api/event?id=" + event.event_id)[1]["response_case"]["state"], "reviewed")

    def test_upload_events_details_and_bad_path(self):
        self.login()
        code, result = self.client.post("/api/ingestion/submit", {"source": "sysmon", "event": FIXTURES["sysmon"]})
        self.assertEqual(code, 202)
        self.assertTrue(result["accepted"])
        self.service.pipeline.process_one()
        code, body = self.client.get("/api/events?host=lab-pc")
        self.assertEqual(len(body["events"]), 1)
        event_id = body["events"][0]["event_id"]
        self.assertEqual(self.client.get("/api/event?id=" + event_id)[1]["analysis"]["kind"], "observation")
        self.assertEqual(self.client.post("/api/ingestion/import", {"filename": "../bad.json", "content": "{}"})[0], 400)
        self.assertEqual(self.client.post("/api/ingestion/dataset", {"dataset": "../../arbiter_iam.db.secret"})[0], 400)

    def test_configuration_defaults_and_coming_soon(self):
        self.login()
        code, body = self.client.get("/api/ingestion/status")
        self.assertFalse(any(c["enabled"] for c in body["connectors"] if c["name"] == "windows"))
        self.assertEqual(self.client.post("/api/ingestion/configure", {"name": "windows", "enabled": False, "configuration": {}})[0], 200)
        self.assertEqual(self.client.post("/api/ingestion/configure", {"name": "azure", "enabled": True})[0], 400)

    def test_queue_pressure_returns_429_without_partial_import(self):
        self.login()
        self.service.buffer.capacity = 1
        self.client.post("/api/ingestion/submit", {"source": "windows", "event": FIXTURES["windows"]})
        code, _ = self.client.post("/api/ingestion/submit", {"source": "sysmon", "event": FIXTURES["sysmon"]})
        self.assertEqual(code, 429)
        self.assertEqual(self.service.buffer.metrics()["events_ingested"], 1)

    def test_simulator_auth_and_separation(self):
        self.assertEqual(self.client.get("/api/demo/status")[0], 401)
        self.login("analyst")
        self.assertEqual(self.client.post("/api/demo/start", {"datasets": ["events.jsonl"]})[0], 403)
        self.login()
        self.assertEqual(self.client.post("/api/demo/start", {"datasets": ["events.jsonl"]}, csrf=False)[0], 403)
        code, status = self.client.post("/api/demo/start", {"datasets": ["events.jsonl"], "speed": "1x"})
        self.assertEqual(code, 200)
        self.assertEqual(status["delivered"], 0)
        session = self.simulator.session
        session.service.pipeline.stop()
        session.tick(); session.service.pipeline.process_one()
        event_id = session.service.buffer.query()[0]["event_id"]
        self.assertEqual(self.client.get("/api/demo/event?id=" + event_id)[0], 200)
        self.assertEqual(self.client.get("/api/event?id=" + event_id)[0], 404)
        self.assertEqual(self.client.get("/api/events")[1]["events"], [])
        self.assertEqual(self.client.get("/api/record")[1]["rows"], [])
        self.assertEqual(self.client.get("/api/summary")[1]["lifetime"]["triaged"], 0)

    def test_permission_request_admin_and_failure_preserve_server(self):
        self.login("analyst")
        self.assertEqual(self.client.post("/api/permissions/request", {})[0], 403)
        self.login()
        callback = Mock(side_effect=ValueError("cancelled"))
        self.ctx.elevate = callback
        self.assertEqual(self.client.post("/api/permissions/request", {})[0], 400)
        self.assertEqual(self.client.get("/api/summary")[0], 200)
        callback.assert_called_once()

    def test_legacy_demo_routes_cannot_pollute_monitoring(self):
        self.login()
        for route, body in (("/api/ingestion/dataset", {"dataset": "events.jsonl"}),
                            ("/api/ingestion/import", {"filename": "demo.json", "content": json.dumps(FIXTURES["sysmon"])})):
            self.assertEqual(self.client.post(route, body)[0], 400)
            self.assertEqual(self.service.buffer.metrics()["events_ingested"], 0)
        code, preview = self.client.post("/api/demo/preview", {"datasets": ["events.jsonl"]})
        self.assertEqual(code, 200)
        self.assertEqual(preview["files"][0]["valid_events"], 22)
        self.assertEqual(self.simulator.status()["delivered"], 0)
