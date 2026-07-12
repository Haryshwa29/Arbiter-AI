import unittest

from arbiter.memory import Memory
from arbiter.schema import Decision, Tier, Verdict


def suppress_verdict(signature):
    return Verdict(event_id="e", signature=signature,
                   decision=Decision.SUPPRESS, score=1.0,
                   tier=Tier.PREFILTER, rationale="benign")


class TestMemory(unittest.TestCase):
    def setUp(self):
        self.mem = Memory(":memory:")

    def tearDown(self):
        self.mem.close()

    def test_unknown_asset_is_suspicious_not_neutral(self):
        # Design invariant: unrecognized hosts get 1.3, above baseline 1.0.
        self.assertEqual(self.mem.asset_criticality("never-seen"), 1.3)
        self.assertFalse(self.mem.is_known_asset("never-seen"))

    def test_upsert_asset_and_update(self):
        self.mem.upsert_asset("db-prod-01", 2.0, "prod db", confirmed=True)
        self.assertEqual(self.mem.asset_criticality("db-prod-01"), 2.0)
        self.mem.upsert_asset("db-prod-01", 1.5)
        self.assertEqual(self.mem.asset_criticality("db-prod-01"), 1.5)
        self.assertTrue(self.mem.is_known_asset("db-prod-01"))

    def test_history_counts_by_decision(self):
        sig = "sshd:auth_failure:h1"
        for _ in range(3):
            self.mem.record_verdict(suppress_verdict(sig))
        h = self.mem.history(sig)
        self.assertEqual((h.total, h.suppressed, h.escalated), (3, 3, 0))
        self.assertEqual(h.false_positive_rate, 1.0)

    def test_label_verdicts_marks_overruled(self):
        sig = "sshd:auth_failure:h1"
        self.mem.record_verdict(suppress_verdict(sig))
        self.mem.label_verdicts(sig, "overruled")
        self.assertEqual(self.mem.history(sig).overruled, 1)

    def test_facts_scoped_to_host_source_or_global(self):
        self.mem.add_fact("backups at 02:00", scope="db-prod-01")
        self.mem.add_fact("company uses tailscale", scope="*")
        self.mem.add_fact("irrelevant", scope="other-host")
        facts = [f.text for f in self.mem.facts_for("db-prod-01", "auditd")]
        self.assertIn("backups at 02:00", facts)
        self.assertIn("company uses tailscale", facts)
        self.assertNotIn("irrelevant", facts)

    def test_scoped_fact_round_trips_constraints(self):
        self.mem.add_fact("backups run at 02:00", scope="db-prod-01",
                          user="postgres", path="/backup",
                          event_types=("process_exec",), window="01:45-02:30")
        (f,) = self.mem.facts_for("db-prod-01", "auditd")
        self.assertEqual(f.user, "postgres")
        self.assertEqual(f.path, "/backup")
        self.assertEqual(f.event_types, ("process_exec",))
        self.assertEqual(f.window, "01:45-02:30")
        self.assertTrue(f.scoped)


if __name__ == "__main__":
    unittest.main()
