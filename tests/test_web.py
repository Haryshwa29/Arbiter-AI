"""Tests for the dashboard's store + IAM layers.

Focus on the security-critical invariants from ADR-001:
- the public aggregate view exposes no identifiers
- sessions are tamper-evident (HMAC), expire, and reject forgery
- password auth locks out after repeated failures
"""

import tempfile
import time
import unittest
from pathlib import Path

from arbiter.iam import IAM
from arbiter.store import AuditStore
from arbiter.schema import Decision, Event, Tier, Verdict


def _verdict(host="web-prod-01", decision=Decision.ESCALATE):
    ev = Event(source="sshd", host=host, event_type="auth_bruteforce",
               message="48 failed root logins from 185.220.101.7",
               severity=8.5, fields={"src_ip": "185.220.101.7"})
    v = Verdict(event_id=ev.id, signature=ev.signature, decision=decision,
                score=9.0, tier=Tier.PREFILTER, rationale="test", evidence="e")
    return ev, v


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = AuditStore(Path(self.tmp.name) / "s.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_lifetime_counts_are_aggregate_only(self):
        for _ in range(3):
            self.store.record_verdict(*_verdict(decision=Decision.SUPPRESS))
        self.store.record_verdict(*_verdict(decision=Decision.ESCALATE))
        c = self.store.lifetime_counts()
        self.assertEqual(c, {"triaged": 4, "suppressed": 3, "escalated": 1})
        # The public counts dict must never carry identifiers.
        for key in c:
            self.assertNotIn(key, ("host", "signature", "src_ip", "message"))

    def test_query_filters(self):
        self.store.record_verdict(*_verdict(decision=Decision.ESCALATE))
        self.store.record_verdict(*_verdict(decision=Decision.SUPPRESS))
        esc = self.store.query(decision="escalate")
        self.assertTrue(all(r["decision"] == "escalate" for r in esc))

    def test_prune_removes_old_rows(self):
        ev, v = _verdict()
        v.timestamp = "2000-01-01T00:00:00+00:00"  # ancient
        self.store.record_verdict(ev, v)
        self.assertEqual(self.store.lifetime_counts()["triaged"], 1)
        self.store.prune(days=30)
        self.assertEqual(self.store.lifetime_counts()["triaged"], 0)


class IAMTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.iam = IAM(Path(self.tmp.name) / "i.db")
        self.iam.create_user("priya", "correct horse", "analyst")

    def tearDown(self):
        self.tmp.cleanup()

    def test_auth_success_and_failure(self):
        self.assertIsNotNone(self.iam.authenticate("priya", "correct horse"))
        self.assertIsNone(self.iam.authenticate("priya", "wrong"))
        self.assertIsNone(self.iam.authenticate("ghost", "x"))

    def test_session_roundtrip_and_role(self):
        user = self.iam.authenticate("priya", "correct horse")
        tok = self.iam.issue_session(user)
        got = self.iam.verify_session(tok)
        self.assertEqual(got["username"], "priya")
        self.assertEqual(got["role"], "analyst")

    def test_forged_session_rejected(self):
        user = self.iam.authenticate("priya", "correct horse")
        tok = self.iam.issue_session(user)
        body, _, sig = tok.partition(".")
        forged = body[:-2] + "ff" + "." + sig  # tamper the payload
        self.assertIsNone(self.iam.verify_session(forged))
        self.assertIsNone(self.iam.verify_session("garbage"))
        self.assertIsNone(self.iam.verify_session(None))

    def test_lockout_after_repeated_failures(self):
        for _ in range(5):
            self.iam.authenticate("priya", "nope")
        # even the correct password is refused while locked out
        self.assertIsNone(self.iam.authenticate("priya", "correct horse"))

    def test_expired_session_rejected(self):
        user = self.iam.authenticate("priya", "correct horse")
        import arbiter.iam as iam_mod
        orig = iam_mod.SESSION_TTL
        iam_mod.SESSION_TTL = -1  # already expired
        try:
            tok = self.iam.issue_session(user)
        finally:
            iam_mod.SESSION_TTL = orig
        self.assertIsNone(self.iam.verify_session(tok))


if __name__ == "__main__":
    unittest.main()
