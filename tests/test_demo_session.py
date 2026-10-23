import tempfile
from dataclasses import replace
import unittest
from pathlib import Path
from unittest.mock import patch

from arbiter.ingestion.demo import DemoManager
from arbiter.ingestion.files import parse_upload
from arbiter.ingestion.service import IngestionService
from arbiter.memory import Memory
from arbiter.store import AuditStore
from arbiter.api.server import _row_msg


class DemoSessionTests(unittest.TestCase):
    def setUp(self):
        self.manager = DemoManager()
        self.events = parse_upload("events.jsonl", Path("samples/events.jsonl").read_text(encoding="utf-8")).events

    def tearDown(self):
        self.manager.close()

    def test_delivery_is_paced_not_prequeued_and_pause_stops_arrivals(self):
        result = self.manager.start([self.events], "1x")
        self.assertEqual(result["delivered"], 0)
        self.assertEqual(result["events"], [])
        session = self.manager.session
        self.manager.control("pause")
        self.assertFalse(session.tick())
        self.manager.control("resume")
        self.assertTrue(session.tick())
        self.assertEqual(session.sent, 1)
        self.manager.control("stop")
        self.assertFalse(session.tick())
        self.assertEqual(session.sent, 1)

    def test_demo_cannot_change_live_data_or_execute_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            memory = Memory(Path(tmp) / "memory.db")
            audit = AuditStore(Path(tmp) / "audit.db")
            live = IngestionService(Path(tmp) / "events.db", memory, audit)
            try:
                with patch("arbiter.respond.Responder._execute", side_effect=AssertionError("actuator called")):
                    self.manager.start([self.events])
                    session = self.manager.session
                    session.service.pipeline.stop()
                    session.tick()
                    session.service.pipeline.process_one()
                    row = session.service.buffer.query()[0]
                    self.assertEqual(row["state"], "done")
                    self.assertIn("demo", row["event"]["tags"])
                    self.assertIsNotNone(self.manager.detail(row["event_id"]))
                    self.assertEqual(live.buffer.metrics()["events_ingested"], 0)
                    self.assertEqual(audit.lifetime_counts()["triaged"], 0)
            finally:
                live.stop(); memory.close(); audit.close()

    def test_random_order_is_repeatable_and_speed_has_a_real_interval(self):
        self.manager.start([self.events], "2x", "random", 42)
        first = [e.event_id for e in self.manager.session.events]
        self.assertEqual(self.manager.session.interval, 1.5)
        self.manager.control("stop")
        self.manager.start([self.events], "2x", "random", 42)
        self.assertEqual(first, [e.event_id for e in self.manager.session.events])

    def test_rejects_invalid_settings_and_concurrent_start(self):
        with self.assertRaises(ValueError): self.manager.start([self.events], "instant")
        for speed in ("5x", "10x"):
            with self.assertRaises(ValueError): self.manager.start([self.events], speed)
        with self.assertRaises(ValueError): self.manager.start([self.events], traffic="bursts")
        with self.assertRaises(ValueError): self.manager.start([self.events], seed=-1)
        self.manager.start([self.events])
        with self.assertRaises(ValueError): self.manager.start([self.events])

    def test_slow_analysis_prevents_delivery_backlog_even_at_2x(self):
        self.manager.start([self.events], "2x")
        session = self.manager.session
        session.service.pipeline.stop()
        self.assertTrue(session.tick())
        self.assertFalse(session.tick())
        self.assertEqual(session.sent, 1)
        session.service.pipeline.process_one()
        self.assertTrue(session.tick())
        self.assertEqual(session.sent, 2)

    def test_history_preserves_live_identity_and_pending_to_final_decision(self):
        self.manager.start([self.events])
        session = self.manager.session
        session.service.pipeline.stop()
        session.tick()
        pending = self.manager.history()["events"][0]
        self.assertIsNone(pending["analysis"])
        self.assertEqual(pending["event_id"], self.manager.status()["events"][0]["event_id"])
        session.service.pipeline.process_one()
        final = self.manager.history()["events"][0]
        self.assertEqual(final["event_id"], pending["event_id"])
        self.assertEqual(final["analysis"], self.manager.status()["events"][0]["analysis"])
        self.assertEqual(self.manager.history(100)["events"], [])

    def test_history_filters_before_pagination_and_combines_fields(self):
        self.manager.start([self.events])
        self.manager.control("pause")
        session = self.manager.session
        session.service.pipeline.stop()
        for index in range(101):
            event = replace(self.events[0], event_id=f"filter-{index}", hostname="needle-host" if index == 0 else "other-host")
            session.service.buffer.enqueue(event, connector="demo")
        result = self.manager.history(filters={"host": "NEEDLE", "search": "filter-0", "decision": "pending", "response": "pending"})
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["events"][0]["event_id"], "filter-0")
        self.assertEqual(self.manager.history(filters={"host": "needle", "decision": "suppress"})["total"], 0)
        self.assertEqual(self.manager.history(filters={"event_type": "no-such-type"})["events"], [])
        self.assertEqual(len(self.manager.history(100)["events"]), 1)

    def test_audit_lookup_and_stream_keep_event_identity(self):
        self.manager.start([self.events])
        session = self.manager.session
        session.service.pipeline.stop()
        session.tick(); session.service.pipeline.process_one()
        event_id = session.service.buffer.query()[0]["event_id"]
        row = session.audit.query(event_id=event_id)[0]
        self.assertEqual(_row_msg(row)["event_id"], event_id)


if __name__ == "__main__": unittest.main()
