"""End-to-end orchestrator tests: policy invariants live here."""

import json
import tempfile
import unittest
from pathlib import Path

from arbiter.llm import LLMBackend, LLMVerdict, MockBackend
from arbiter.memory import Memory
from arbiter.schema import Decision, Event, Tier
from arbiter.triage import TriageEngine


class FailingBackend(LLMBackend):
    name = "failing"

    def triage(self, *a, **kw):
        raise ConnectionError("ollama is down")


class TimidSuppressor(LLMBackend):
    """Always suppresses, but below the confidence floor."""
    name = "timid"

    def triage(self, *a, **kw):
        return LLMVerdict(Decision.SUPPRESS, 0.4, "", "probably fine")


def make_event(**overrides):
    base = dict(source="auditd", host="dev-laptop-42", event_type="process_exec",
                message="some ambiguous activity", severity=5.0)
    base.update(overrides)
    return Event(**base)


class TriageTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.audit = Path(self.tmp.name) / "audit.jsonl"
        self.mem = Memory(":memory:")
        self.mem.upsert_asset("dev-laptop-42", 0.5, "dev laptop")

    def tearDown(self):
        self.mem.close()
        self.tmp.cleanup()

    def engine(self, llm, **kw):
        return TriageEngine(self.mem, llm, audit_path=self.audit, **kw)

    def test_llm_failure_escalates_by_policy(self):
        v = self.engine(FailingBackend()).triage(make_event())
        self.assertIs(v.decision, Decision.ESCALATE)
        self.assertIs(v.tier, Tier.LLM)
        self.assertIn("escalating by policy", v.rationale)

    def test_low_confidence_suppress_upgraded_to_escalate(self):
        v = self.engine(TimidSuppressor()).triage(make_event())
        self.assertIs(v.decision, Decision.ESCALATE)
        self.assertIn("upgraded to escalate", v.rationale)

    def test_prefilter_escalation_skips_llm(self):
        self.mem.upsert_asset("db-prod-01", 2.0)
        engine = self.engine(FailingBackend())  # would blow up if consulted
        v = engine.triage(make_event(host="db-prod-01", severity=9.0,
                                     message="Failed password for root x50"))
        self.assertIs(v.decision, Decision.ESCALATE)
        self.assertIs(v.tier, Tier.PREFILTER)
        self.assertEqual(engine.stats.prefilter_decided, 1)

    def test_audit_trail_and_memory_updated(self):
        engine = self.engine(MockBackend())
        e = make_event()
        engine.triage(e)
        entries = [json.loads(l) for l in
                   self.audit.read_text().splitlines()]
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0]["shadow"])  # shadow mode is the default
        self.assertEqual(entries[0]["event"]["host"], "dev-laptop-42")
        self.assertEqual(self.mem.history(e.signature).total, 1)

    def test_no_silent_verdicts(self):
        # Every verdict carries a rationale; escalations carry evidence.
        engine = self.engine(MockBackend())
        v = engine.triage(make_event(message="sudo su - attempted by www-data"))
        self.assertTrue(v.rationale)
        if v.decision is Decision.ESCALATE:
            self.assertTrue(v.evidence)


if __name__ == "__main__":
    unittest.main()
