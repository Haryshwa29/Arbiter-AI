"""Pin the asymmetric-cost behavior: escalation is cheap, suppression is earned."""

import unittest

from arbiter.memory import Memory
from arbiter.prefilter import MIN_HISTORY_TO_SUPPRESS, prefilter
from arbiter.schema import Decision, Event, Tier, Verdict


def make_event(host="h1", severity=5.0, **kw):
    return Event(source="sshd", host=host, event_type="auth_failure",
                 message="Failed password", severity=severity, **kw)


class TestPrefilter(unittest.TestCase):
    def setUp(self):
        self.mem = Memory(":memory:")

    def tearDown(self):
        self.mem.close()

    def seed_benign_history(self, signature, n=MIN_HISTORY_TO_SUPPRESS):
        for _ in range(n):
            self.mem.record_verdict(Verdict(
                event_id="e", signature=signature, decision=Decision.SUPPRESS,
                score=1.0, tier=Tier.PREFILTER, rationale="benign"))

    def test_high_score_escalates_without_history(self):
        self.mem.upsert_asset("db-prod-01", 2.0)
        r = prefilter(make_event(host="db-prod-01", severity=9.0), self.mem)
        self.assertIs(r.decision, Decision.ESCALATE)

    def test_low_score_alone_does_not_suppress(self):
        # No history yet → must punt to the LLM, never silently suppress.
        self.mem.upsert_asset("lab-box", 0.3)
        r = prefilter(make_event(host="lab-box", severity=2.0), self.mem)
        self.assertIs(r.decision, Decision.AMBIGUOUS)

    def test_low_score_plus_benign_history_suppresses(self):
        self.mem.upsert_asset("lab-box", 0.3)
        e = make_event(host="lab-box", severity=2.0)
        self.seed_benign_history(e.signature)
        r = prefilter(e, self.mem)
        self.assertIs(r.decision, Decision.SUPPRESS)
        self.assertTrue(r.rationale)  # suppression always carries a rationale

    def test_human_overrule_blocks_suppression(self):
        self.mem.upsert_asset("lab-box", 0.3)
        e = make_event(host="lab-box", severity=2.0)
        self.seed_benign_history(e.signature)
        self.mem.label_verdicts(e.signature, "overruled")
        r = prefilter(e, self.mem)
        self.assertIsNot(r.decision, Decision.SUPPRESS)

    def test_unknown_host_scores_higher_than_known_baseline(self):
        self.mem.upsert_asset("known", 1.0)
        from arbiter.prefilter import score_event
        unknown = score_event(make_event(host="mystery", severity=5.0), self.mem)
        known = score_event(make_event(host="known", severity=5.0), self.mem)
        self.assertGreater(unknown, known)


if __name__ == "__main__":
    unittest.main()
