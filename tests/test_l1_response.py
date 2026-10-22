import json
import socket
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from arbiter.ingestion.protection import Protection
from arbiter.ingestion.recommendations import guidance
from arbiter.ingestion.response_workflow import ResponseWorkflow, WINDOWS
from arbiter.ingestion.schema import SecurityEvent
from arbiter.ingestion.store import EventBuffer
from arbiter.llm import parse_response
from arbiter.store import AuditStore


class L1ResponseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.buffer = EventBuffer(Path(self.temp.name) / "events.db")
        self.audit = AuditStore(Path(self.temp.name) / "audit.db")
        self.now = time.time()
        self.firewall = Mock()
        self.firewall.active.return_value = True
        self.firewall.removed.return_value = True
        self.protection = Protection(self.buffer, self.audit, self.firewall, verify=True)
        self.workflow = ResponseWorkflow(self.buffer, self.audit, self.protection, clock=lambda: self.now)

    def tearDown(self):
        self.workflow.close(); self.buffer.close(); self.audit.close(); self.temp.cleanup()

    def event(self, severity=8, kind="auth_failure", rule="repeated_login_failures", connector="windows", tags=None, target="8.8.8.8"):
        event = SecurityEvent(source_type="windows", hostname=socket.gethostname(),
                              event_type=kind, message="test", severity=severity, username="alice", src_ip=target,
                              tags=tags or [])
        self.buffer.enqueue(event, connector)
        row = self.buffer.claim()
        self.buffer.finish(row["id"], {"decision": "escalate", "tier": "prefilter",
                "score": 10, "rationale": "test", "evidence": "test", "correlation": [{"rule": rule}] if rule else [],
                "responses": [{"kind": "block_ip", "target": target}]}, [], 0)
        return self.buffer.detail(event.event_id)

    def enroll(self, row, workflow=None):
        workflow = workflow or self.workflow
        case = workflow.ensure(row)
        case["deadline"] = self.now + 1
        workflow.save(case)
        return workflow.control(row["event_id"], "schedule", "admin", protected=["192.168.0.0/16"])

    def test_deadlines_use_source_severity_not_model_score(self):
        for score, severity in [(9, "critical"), (7, "high"), (4, "medium"), (3, "low")]:
            case = self.workflow.ensure(self.event(score, rule=None))
            self.assertEqual(case["severity"], severity)
            self.assertEqual(case["window"], WINDOWS[severity])
            if score == 3: self.assertIsNone(case["deadline"])
        critical = self.workflow.ensure(self.event(3, rule="malware_process_network"))
        self.assertEqual(critical["severity"], "low")  # unverified metadata cannot promote severity

    def test_default_expiry_marks_overdue_without_actuation(self):
        row = self.event()
        case = self.workflow.ensure(row)
        self.now = case["deadline"] + 1
        self.workflow.tick()
        self.assertEqual(self.workflow.get(row["event_id"])["state"], "overdue")
        self.firewall.block.assert_not_called()

    def test_defer_is_bounded_reject_cancels_and_deadline_does_not_reset(self):
        row = self.event()
        original = self.workflow.ensure(row)
        case = self.workflow.control(row["event_id"], "defer", "admin", "Investigating")
        self.assertEqual(case["deadline"], original["deadline"] + 300)
        with self.assertRaises(ValueError): self.workflow.control(row["event_id"], "defer", "admin", "Again")
        self.assertEqual(self.workflow.ensure(row)["deadline"], case["deadline"])
        self.workflow.control(row["event_id"], "reject", "admin", "Authorized maintenance")
        self.now = case["deadline"] + 1
        self.workflow.tick()
        self.assertEqual(self.workflow.get(row["event_id"])["state"], "rejected")
        self.firewall.block.assert_not_called()

    def test_enrollment_requires_narrow_rule_scope_and_verified_actuator(self):
        for row in [self.event(rule=None), self.event(rule="suspicious_process_network"), self.event(connector="api"), self.event(tags=["demo"])]:
            self.workflow.ensure(row)
            with self.assertRaises(ValueError): self.workflow.control(row["event_id"], "schedule", "admin", protected=["192.168.0.0/16"])
        row = self.event()
        self.workflow.ensure(row)
        for protected in ([], ["8.8.8.8/32"], ["not-a-network"]):
            with self.assertRaises(ValueError): self.workflow.control(row["event_id"], "schedule", "admin", protected=protected)
        self.protection.verify = False
        with self.assertRaises(ValueError): self.workflow.control(row["event_id"], "schedule", "admin", protected=["192.168.0.0/16"])

    def test_success_rebuilds_auth_evidence_verifies_native_block_and_undo(self):
        for _ in range(4): self.event(rule=None)
        row = self.event()
        self.enroll(row)
        self.now += 2
        self.workflow.tick()
        case = self.workflow.get(row["event_id"])
        self.assertEqual(case["state"], "executed")
        self.firewall.block.assert_called_once()
        self.firewall.active.assert_called_once()
        self.workflow.control(row["event_id"], "undo", "admin")
        self.assertEqual(self.workflow.get(row["event_id"])["state"], "undone")
        self.firewall.removed.assert_called_once()
        self.workflow.tick()
        self.firewall.block.assert_called_once()

    def test_stale_or_untrusted_support_fails_closed_without_retry(self):
        for _ in range(4): self.event(rule=None, connector="api")
        row = self.event()
        self.enroll(row)
        self.now += 2
        self.workflow.tick()
        self.assertEqual(self.workflow.get(row["event_id"])["state"], "needs_review")
        self.firewall.block.assert_not_called()
        self.workflow.tick()
        self.firewall.block.assert_not_called()

    def test_stale_evidence_does_not_authorize_execution(self):
        for _ in range(4): self.event(rule=None)
        row = self.event()
        self.enroll(row)
        self.now += 301
        self.workflow.tick()
        self.assertEqual(self.workflow.get(row["event_id"])["state"], "needs_review")
        self.firewall.block.assert_not_called()

    def test_restart_preserves_deadline_stop_cancels_enrollments_and_resume_does_not_rearm(self):
        row = self.event()
        case = self.enroll(row)
        restarted = ResponseWorkflow(self.buffer, self.audit, self.protection, clock=lambda: self.now)
        self.assertEqual(restarted.get(row["event_id"])["deadline"], case["deadline"])
        restarted.control("", "stop", "admin")
        restarted = ResponseWorkflow(self.buffer, self.audit, self.protection, clock=lambda: self.now)
        self.assertTrue(restarted.stopped())
        restarted.control("", "resume", "admin")
        self.now += 2
        restarted.tick()
        self.assertEqual(restarted.get(row["event_id"])["state"], "overdue")
        self.firewall.block.assert_not_called()

    def test_interrupted_execution_and_native_failure_are_visible_without_retry(self):
        row = self.event()
        case = self.workflow.ensure(row)
        case["state"] = "executing"
        self.workflow.save(case)
        restarted = ResponseWorkflow(self.buffer, self.audit, self.protection, clock=lambda: self.now)
        self.assertEqual(restarted.get(row["event_id"])["state"], "needs_review")
        self.firewall.block.assert_not_called()

    def test_native_verification_failure_requires_review_and_cleanup(self):
        for _ in range(4): self.event(rule=None)
        row = self.event()
        self.enroll(row)
        self.firewall.active.return_value = False
        self.now += 2
        self.workflow.tick()
        self.assertEqual(self.workflow.get(row["event_id"])["state"], "needs_review")
        self.assertEqual(self.protection.actions(row["event_id"])[0]["status"], "failed")
        self.firewall.undo.assert_called_once()

    def test_demo_timers_and_undo_never_construct_or_invoke_actuator(self):
        row = self.event(connector="demo", tags=["demo"])
        simulation = ResponseWorkflow(self.buffer, self.audit, simulation=True, clock=lambda: self.now)
        with patch("arbiter.ingestion.response_workflow.Protection", side_effect=AssertionError("demo touched actuator")):
            self.enroll(row, simulation)
            self.now += 2
            simulation.tick()
            self.assertEqual(simulation.get(row["event_id"])["state"], "executed")
            simulation.control(row["event_id"], "undo", "admin")
            self.assertEqual(simulation.get(row["event_id"])["state"], "undone")
        self.firewall.block.assert_not_called()

    def test_package_update_guidance_and_model_advice_never_grant_authority(self):
        row = self.event(kind="package_update", rule=None)
        detail = self.workflow.enrich(row)
        self.assertEqual(detail["analysis"]["guidance"]["source"], "policy")
        self.assertIn("package source", " ".join(detail["analysis"]["guidance"]["steps"]))
        with self.assertRaises(ValueError): self.workflow.control(row["event_id"], "schedule", "admin", protected=["192.168.0.0/16"])
        answer = parse_response(json.dumps({"decision": "escalate", "confidence": .8, "recommended_steps": ["Check the maintenance record", 42, "x" * 501]}))
        self.assertEqual(answer.recommended_steps, ["Check the maintenance record"])
        info = guidance(row["event"], {"decision": "escalate", "backend": "ollama", "recommended_steps": answer.recommended_steps})
        self.assertEqual(info["source"], "model")

    def test_model_steps_survive_pipeline_without_changing_stable_verdict_contract(self):
        from arbiter.ingestion.service import IngestionService
        from arbiter.memory import Memory
        from arbiter.llm import LLMVerdict
        from arbiter.schema import Decision
        memory = Memory(Path(self.temp.name) / "memory.db")
        service = IngestionService(Path(self.temp.name) / "model-events.db", memory, self.audit)
        try:
            event = SecurityEvent(source_type="dpkg", hostname="database", event_type="package_update", message="Version update", severity=4)
            llm = Mock()
            llm.name = "ollama"; llm.model = "fixture-local"
            llm.triage.return_value = LLMVerdict(Decision.ESCALATE, .9, "Package version changed", "Verify authorization", ["Check the maintenance record"])
            service.pipeline.engine.llm = llm
            service.buffer.enqueue(event, "api")
            service.pipeline.process_one()
            result = service.buffer.detail(event.event_id)
            self.assertEqual(result["analysis"]["guidance"]["source"], "model")
            self.assertEqual(result["analysis"]["guidance"]["steps"], ["Check the maintenance record"])
            self.assertEqual(result["state"], "done")
        finally:
            service.stop(); memory.close()

    def test_out_of_order_completion_never_skips_or_delays_urgent_review(self):
        old = SecurityEvent(source_type="dpkg", hostname="db", event_type="package_update", message="slow", severity=4)
        self.buffer.enqueue(old)
        urgent = self.event(9, rule=None)
        # event() claims the urgent priority row, leaving the older record pending.
        self.workflow.tick()
        self.assertIsNotNone(self.workflow.get(urgent["event_id"]))
        pending = self.buffer.claim()
        self.buffer.finish(pending["id"], {"decision": "escalate", "tier": "prefilter", "correlation": []}, [], 0)
        self.workflow.tick()
        self.assertIsNotNone(self.workflow.get(old.event_id))


if __name__ == "__main__": unittest.main()
