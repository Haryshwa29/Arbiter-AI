"""Feedback loop CLI (review.py): grouping, labeling, fact creation."""

import unittest

from arbiter.memory import Memory
from arbiter.review import (apply_feedback, group_items, interactive_review,
                            load_audit)
from arbiter.schema import Decision, Tier, Verdict


def entry(sig, decision, msg="m", host="h1", etype="io_anomaly"):
    return {"signature": sig, "decision": decision, "tier": "llm",
            "rationale": "r", "shadow": True,
            "event": {"source": sig.split(":")[0], "host": host,
                      "type": etype, "message": msg}}


def scripted(*answers):
    it = iter(answers)
    return lambda prompt="": next(it)


class GroupingTests(unittest.TestCase):
    def test_dedupes_by_signature_and_counts(self):
        entries = [entry("a:x:h1", "suppress", "first"),
                   entry("a:x:h1", "suppress", "latest"),
                   entry("b:y:h2", "escalate")]
        items = group_items(entries)
        self.assertEqual(len(items), 2)
        a = next(i for i in items if i.signature == "a:x:h1")
        self.assertEqual((a.count, a.message), (2, "latest"))

    def test_decision_filter(self):
        entries = [entry("a:x:h1", "suppress"), entry("b:y:h2", "escalate")]
        self.assertEqual([i.signature for i in group_items(entries, "escalate")],
                         ["b:y:h2"])


class FeedbackTests(unittest.TestCase):
    def setUp(self):
        self.mem = Memory(":memory:")
        self.sig = "sshd:auth_failure:h1"
        for _ in range(3):
            self.mem.record_verdict(Verdict(
                event_id="e", signature=self.sig, decision=Decision.SUPPRESS,
                score=1.0, tier=Tier.LLM, rationale="benign"))

    def tearDown(self):
        self.mem.close()

    def test_overrule_labels_history(self):
        item = group_items([entry(self.sig, "suppress")])[0]
        self.assertEqual(apply_feedback(self.mem, item, "o"), "overruled")
        self.assertEqual(self.mem.history(self.sig).overruled, 3)

    def test_confirm_labels_history(self):
        item = group_items([entry(self.sig, "suppress")])[0]
        self.assertEqual(apply_feedback(self.mem, item, "c"), "confirmed")
        self.assertEqual(self.mem.history(self.sig).overruled, 0)

    def test_overruled_escalation_creates_scoped_fact(self):
        item = group_items([entry("smartd:disk_degradation:nas-01",
                                  "escalate", host="nas-01",
                                  etype="disk_degradation")])[0]
        answers = scripted(
            "o",                                     # overrule the escalation
            "SMART disk alerts on nas-01 are hardware ops, not intrusions",
            "",                                      # scope host: default
            "",                                      # event types: default
            "", "", "")                              # user/path/window: none
        stats = interactive_review(self.mem, [item], input_fn=answers,
                                   print_fn=lambda *a, **k: None)
        self.assertEqual(stats.overruled, 1)
        self.assertEqual(len(stats.facts_added), 1)
        (f,) = self.mem.facts_for("nas-01", "smartd")
        self.assertEqual(f.event_types, ("disk_degradation",))
        self.assertIn("hardware ops", f.text)

    def test_quit_stops_early_and_skip_counts(self):
        items = group_items([entry("a:x:h1", "suppress"),
                             entry("b:y:h2", "suppress"),
                             entry("c:z:h3", "suppress")])
        stats = interactive_review(self.mem, items,
                                   input_fn=scripted("s", "q"),
                                   print_fn=lambda *a, **k: None)
        self.assertEqual((stats.skipped, stats.confirmed, stats.overruled),
                         (1, 0, 0))


class OverruleDirectionTests(unittest.TestCase):
    """The feedback-loop fix: an overruled ESCALATION (false alarm) must
    never boost the signature like an overruled SUPPRESSION (missed attack)
    does — the human said benign; alerting louder is backwards."""

    def setUp(self):
        self.mem = Memory(":memory:")

    def tearDown(self):
        self.mem.close()

    def _verdict(self, sig, decision):
        return Verdict(event_id="e", signature=sig, decision=decision,
                       score=1.0, tier=Tier.LLM, rationale="r")

    def test_false_alarm_counts_separately_and_feeds_decay(self):
        sig = "smartd:disk_degradation:db-prod-01"
        self.mem.record_verdict(self._verdict(sig, Decision.ESCALATE))
        self.mem.label_verdicts(sig, "overruled")
        h = self.mem.history(sig)
        self.assertEqual((h.overruled, h.false_alarms), (0, 1))
        self.assertEqual(h.false_positive_rate, 1.0)

    def test_missed_attack_still_counts_as_overruled(self):
        sig = "sshd:login:hr-srv-01"
        self.mem.record_verdict(self._verdict(sig, Decision.SUPPRESS))
        self.mem.label_verdicts(sig, "overruled")
        h = self.mem.history(sig)
        self.assertEqual((h.overruled, h.false_alarms), (1, 0))

    def test_overruled_escalations_do_not_block_prefilter_suppression(self):
        from arbiter.prefilter import prefilter
        from arbiter.schema import Event
        sig_host = "db-prod-01"
        self.mem.upsert_asset(sig_host, 1.0, "db", True)
        event = Event(source="smartd", host=sig_host,
                      event_type="disk_degradation",
                      message="SMART reallocated sectors rising",
                      severity=2.0)
        # 5 escalations, all overruled as false alarms → decayed score,
        # no standing escalations, no missed attacks: cheap suppression OK.
        for _ in range(5):
            self.mem.record_verdict(self._verdict(event.signature,
                                                  Decision.ESCALATE))
        self.mem.label_verdicts(event.signature, "overruled")
        result = prefilter(event, self.mem)
        self.assertIs(result.decision, Decision.SUPPRESS)


class LoadTests(unittest.TestCase):
    def test_missing_file_is_empty(self):
        self.assertEqual(load_audit("/nonexistent/audit.jsonl"), [])


if __name__ == "__main__":
    unittest.main()
