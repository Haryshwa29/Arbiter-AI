"""Scope checking for environment facts (facts.py) — the fact-overreach fix.

The two 2026-07-12 gauntlet misses drive these tests: a fact must cover
ONLY the behavior it names, and the checker must separate the near-twin
pairs (same host, same fact, opposite verdicts).
"""

import unittest

from arbiter.facts import ScopedFact, render, render_all, scope_check, texts
from arbiter.llm import MockBackend
from arbiter.schema import Decision, Event


BACKUP_FACT = ScopedFact(
    text="backups run at 02:00 on db-prod-01, written to /backup",
    user="postgres", path="/backup", window="01:45-02:30")

CHURN_FACT = ScopedFact(
    text="ci-runner-01 spawns many short-lived containers; process churn is expected",
    event_types=("process_anomaly", "process_exec"))


def ev(**kw):
    base = dict(source="auditd", host="db-prod-01", event_type="process_exec",
                message="", severity=3.0)
    base.update(kw)
    return Event(**base)


class ScopeCheckTests(unittest.TestCase):
    def test_unscoped_fact_renders_unchanged(self):
        f = ScopedFact(text="company uses tailscale")
        e = ev(message="anything at all")
        self.assertEqual(scope_check(f, e).status, "unscoped")
        self.assertEqual(render(f, e), "company uses tailscale")

    # -- the fact_overreach_trap pair ------------------------------------

    def test_backup_fact_mismatches_pg_dump_to_home_dir(self):
        e = ev(message="pg_dump of customers db piped to gzip at 02:05 "
                       "and written to /home/tempuser/x.gz",
               fields={"user": "tempuser"})
        r = scope_check(BACKUP_FACT, e)
        self.assertEqual(r.status, "mismatch")
        # both the wrong user and the wrong path are named
        joined = " ".join(r.violations)
        self.assertIn("tempuser", joined)
        self.assertIn("/backup", joined)
        self.assertIn("SCOPE MISMATCH", render(BACKUP_FACT, e))

    def test_backup_fact_verifies_real_backup(self):
        e = ev(message="postgres user created nightly base-backup tar "
                       "in /backup/base at 02:00",
               fields={"user": "postgres"})
        self.assertEqual(scope_check(BACKUP_FACT, e).status, "verified")
        self.assertIn("scope verified", render(BACKUP_FACT, e))

    def test_window_violation_alone_is_a_mismatch(self):
        e = ev(message="postgres user created base-backup tar in /backup "
                       "at 14:30", fields={"user": "postgres"})
        r = scope_check(BACKUP_FACT, e)
        self.assertEqual(r.status, "mismatch")
        self.assertIn("14:30", " ".join(r.violations))

    # -- the token_theft / ci_churn pair ---------------------------------

    def test_churn_fact_mismatches_auth_anomaly(self):
        e = ev(source="idp", host="ci-runner-01", event_type="auth_anomaly",
               message="ci bot oauth token minted on ci-runner-01 reused "
                       "4 minutes later from a different ASN")
        r = scope_check(CHURN_FACT, e)
        self.assertEqual(r.status, "mismatch")
        self.assertIn("auth_anomaly", " ".join(r.violations))

    def test_churn_fact_verifies_container_churn(self):
        e = ev(host="ci-runner-01", event_type="process_anomaly",
               message="ci-runner-01 spawned 340 short-lived containers "
                       "during pipeline run 5521")
        self.assertEqual(scope_check(CHURN_FACT, e).status, "verified")

    # -- partial / undecidable ------------------------------------------

    def test_undecidable_constraints_stay_with_the_model(self):
        f = ScopedFact(text="scanner runs weekly", process="nessusd")
        e = ev(event_type="netflow_anomaly",
               message="port sweep observed from 10.0.9.9")  # no process info
        r = scope_check(f, e)
        self.assertEqual(r.status, "partial")
        self.assertIn("apply only if", render(f, e))

    def test_wraparound_window(self):
        f = ScopedFact(text="nightly sync", window="23:00-01:00")
        inside = ev(message="sync ran at 00:30")
        outside = ev(message="sync ran at 12:00")
        self.assertEqual(scope_check(f, inside).status, "verified")
        self.assertEqual(scope_check(f, outside).status, "mismatch")

    # -- plumbing ---------------------------------------------------------

    def test_from_obj_accepts_strings_and_dicts(self):
        self.assertFalse(ScopedFact.from_obj("plain fact").scoped)
        f = ScopedFact.from_obj({"text": "t", "user": "u",
                                 "event_types": ["login"]})
        self.assertEqual((f.user, f.event_types), ("u", ("login",)))

    def test_texts_strips_scope_for_downgrade_matching(self):
        self.assertEqual(texts([BACKUP_FACT, CHURN_FACT]),
                         [BACKUP_FACT.text, CHURN_FACT.text])


class MockBackendScopeTests(unittest.TestCase):
    """The mock must honor the code-side verdict: a [SCOPE MISMATCH] fact
    can never explain an event, whatever the word overlap."""

    def test_mock_ignores_mismatched_fact(self):
        e = ev(message="pg_dump of customers db piped to gzip at 02:05 "
                       "and written to /home/tempuser/x.gz",
               fields={"user": "tempuser"})
        rendered = render_all([BACKUP_FACT], e)
        v = MockBackend().triage(e, 2.0, "first occurrence", rendered)
        self.assertIs(v.decision, Decision.ESCALATE)

    def test_mock_still_suppresses_verified_fact(self):
        e = ev(message="postgres user created nightly base-backup tar "
                       "in /backup/base at 02:00",
               fields={"user": "postgres"})
        rendered = render_all([BACKUP_FACT], e)
        v = MockBackend().triage(e, 2.0, "seen 30x before: 30 suppressed",
                                 rendered)
        self.assertIs(v.decision, Decision.SUPPRESS)


if __name__ == "__main__":
    unittest.main()
