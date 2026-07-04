"""Schema is the stable collector↔brain boundary — these tests pin it."""

import json
import unittest

from arbiter.schema import Decision, Event, Tier, Verdict


def make_event(**overrides):
    base = dict(source="sshd", host="web-prod-01", event_type="auth_failure",
                message="Failed password for root")
    base.update(overrides)
    return Event(**base)


class TestEvent(unittest.TestCase):
    def test_ingest_fills_id_and_timestamp(self):
        e = make_event()
        self.assertTrue(e.id)
        self.assertTrue(e.timestamp)

    def test_severity_clamped_to_0_10(self):
        self.assertEqual(make_event(severity=99).severity, 10.0)
        self.assertEqual(make_event(severity=-3).severity, 0.0)

    def test_signature_groups_same_alert(self):
        e = make_event()
        self.assertEqual(e.signature, "sshd:auth_failure:web-prod-01")
        self.assertEqual(e.signature, make_event(message="different text").signature)

    def test_json_roundtrip(self):
        e = make_event(fields={"src_ip": "10.0.0.9", "user": "root"})
        e2 = Event.from_json(e.to_json())
        self.assertEqual(e2, e)

    def test_from_json_rejects_unknown_keys(self):
        # A collector emitting fields outside the contract must fail loudly.
        bad = json.dumps({"source": "x", "host": "h", "event_type": "t",
                          "message": "m", "not_in_contract": 1})
        with self.assertRaises(TypeError):
            Event.from_json(bad)


class TestVerdict(unittest.TestCase):
    def test_to_json_serializes_enums_as_strings(self):
        v = Verdict(event_id="abc", signature="s:t:h",
                    decision=Decision.ESCALATE, score=8.0, tier=Tier.PREFILTER,
                    rationale="why", evidence="what to check")
        d = json.loads(v.to_json())
        self.assertEqual(d["decision"], "escalate")
        self.assertEqual(d["tier"], "prefilter")
        self.assertTrue(d["timestamp"])


if __name__ == "__main__":
    unittest.main()
