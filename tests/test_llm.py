import unittest

from arbiter.llm import MockBackend, parse_response
from arbiter.schema import Decision, Event


def make_event(message, host="h1", **kw):
    return Event(source="auditd", host=host, event_type="process_exec",
                 message=message, **kw)


class TestParseResponse(unittest.TestCase):
    def test_digs_json_out_of_prose_and_fences(self):
        text = ('Sure! Here is my analysis:\n```json\n'
                '{"decision": "escalate", "confidence": 0.9, '
                '"evidence": "check sshd", "rationale": "brute force"}\n```')
        v = parse_response(text)
        self.assertIs(v.decision, Decision.ESCALATE)
        self.assertEqual(v.confidence, 0.9)

    def test_confidence_clamped(self):
        v = parse_response('{"decision": "suppress", "confidence": 7}')
        self.assertEqual(v.confidence, 1.0)

    def test_rejects_ambiguous(self):
        with self.assertRaises(ValueError):
            parse_response('{"decision": "ambiguous", "confidence": 0.5}')

    def test_raises_when_no_json(self):
        with self.assertRaises(ValueError):
            parse_response("I could not decide.")


class TestMockBackend(unittest.TestCase):
    def setUp(self):
        self.llm = MockBackend()

    def test_hot_indicator_escalates(self):
        v = self.llm.triage(make_event("curl | sh from unknown IP"),
                            1.0, "first occurrence", [])
        self.assertIs(v.decision, Decision.ESCALATE)
        self.assertTrue(v.evidence)  # escalations must carry evidence

    def test_environment_fact_explains_anomaly(self):
        v = self.llm.triage(
            make_event("nightly IO spike on db-prod-01", host="db-prod-01"),
            2.0, "seen 3x", ["backups run at 02:00 — nightly IO spike on db-prod-01 is normal"])
        self.assertIs(v.decision, Decision.SUPPRESS)
        self.assertTrue(v.rationale)  # suppressions must carry a rationale

    def test_default_leans_escalate(self):
        # Asymmetric costs: with no benign explanation, err toward escalation.
        v = self.llm.triage(make_event("some unremarkable event"),
                            1.0, "first occurrence", [])
        self.assertIs(v.decision, Decision.ESCALATE)


if __name__ == "__main__":
    unittest.main()
