"""Response actuator policy tests.

The invariants under test:
- suppressions and unknown event types produce NO actions
- AUTO requires prefilter tier AND an auto-safe catalog entry
- LLM-tier escalations are always RECOMMEND (model proposes, rules dispose)
- service-endangering actions (crown-jewel quarantine, edge mode) are
  never AUTO regardless of tier
- dry-run never executes; every planned action is audited
"""

import json
import tempfile
import unittest
from pathlib import Path

from arbiter.respond import ActionKind, ActionMode, Responder, plan
from arbiter.schema import Decision, Event, Tier, Verdict


def make_verdict(event: Event, decision=Decision.ESCALATE,
                 tier=Tier.PREFILTER) -> Verdict:
    return Verdict(event_id=event.id, signature=event.signature,
                   decision=decision, score=9.0, tier=tier,
                   rationale="test", evidence="test")


class PlanPolicyTests(unittest.TestCase):
    def test_suppression_yields_no_actions(self):
        ev = Event(source="sshd", host="web-prod-01",
                   event_type="auth_bruteforce", message="x",
                   fields={"src_ip": "203.0.113.7"})
        v = make_verdict(ev, decision=Decision.SUPPRESS)
        self.assertEqual(plan(ev, v), [])

    def test_unknown_event_type_is_alert_only(self):
        ev = Event(source="smartd", host="ci-runner-01",
                   event_type="disk_degradation", message="x")
        self.assertEqual(plan(ev, make_verdict(ev)), [])

    def test_bruteforce_prefilter_is_auto_block_with_ttl(self):
        ev = Event(source="sshd", host="web-prod-01",
                   event_type="auth_bruteforce", message="x",
                   fields={"src_ip": "185.220.101.7"})
        actions = plan(ev, make_verdict(ev, tier=Tier.PREFILTER))
        self.assertEqual(len(actions), 1)
        a = actions[0]
        self.assertEqual(a.kind, ActionKind.BLOCK_IP)
        self.assertEqual(a.mode, ActionMode.AUTO)
        self.assertEqual(a.target, "185.220.101.7")
        self.assertIsNotNone(a.ttl_minutes)  # never permanent

    def test_llm_tier_never_auto(self):
        ev = Event(source="webapp", host="web-prod-01",
                   event_type="geo_anomaly_login", message="x",
                   fields={"user": "devops", "src_ip": "45.146.26.8"})
        actions = plan(ev, make_verdict(ev, tier=Tier.LLM))
        self.assertTrue(actions)
        for a in actions:
            self.assertEqual(a.mode, ActionMode.RECOMMEND)

    def test_geo_actions_are_surgical(self):
        ev = Event(source="vpn", host="vpn-gw-01",
                   event_type="geo_impossible_travel", message="x",
                   fields={"user": "maria", "src_ip": "203.0.113.50"})
        actions = plan(ev, make_verdict(ev, tier=Tier.PREFILTER))
        kinds = {a.kind for a in actions}
        self.assertEqual(kinds, {ActionKind.KILL_SESSION,
                                 ActionKind.LOCK_ACCOUNT,
                                 ActionKind.BLOCK_IP})
        targets = {a.kind: a.target for a in actions}
        self.assertEqual(targets[ActionKind.LOCK_ACCOUNT], "maria")

    def test_service_endangering_actions_never_auto(self):
        tamper = Event(source="aide", host="db-prod-01",
                       event_type="file_integrity", message="x")
        flood = Event(source="nginx", host="web-prod-01",
                      event_type="request_flood", message="x")
        for ev in (tamper, flood):
            for a in plan(ev, make_verdict(ev, tier=Tier.PREFILTER)):
                self.assertEqual(a.mode, ActionMode.RECOMMEND,
                                 f"{ev.event_type} must never auto-execute")

    def test_ransomware_kills_process_and_quarantines(self):
        ev = Event(source="auditd", host="nas-01",
                   event_type="mass_file_rename", message="x",
                   fields={"binary": "/tmp/updater"})
        actions = plan(ev, make_verdict(ev, tier=Tier.PREFILTER))
        kinds = {a.kind for a in actions}
        self.assertEqual(kinds, {ActionKind.KILL_PROCESS,
                                 ActionKind.QUARANTINE_HOST})


class ResponderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.audit = Path(self.tmp.name) / "response_audit.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    def test_dry_run_never_executes_but_audits(self):
        ev = Event(source="sshd", host="web-prod-01",
                   event_type="auth_bruteforce", message="x",
                   fields={"src_ip": "185.220.101.7"})
        r = Responder(audit_path=self.audit, dry_run=True)
        actions = r.respond(ev, make_verdict(ev, tier=Tier.PREFILTER))
        self.assertEqual(len(actions), 1)
        self.assertFalse(actions[0].executed)
        self.assertTrue(actions[0].dry_run)
        lines = self.audit.read_text().splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["kind"], "block_ip")
        self.assertEqual(entry["mode"], "auto")
        self.assertFalse(entry["executed"])

    def test_no_audit_entry_for_suppressions(self):
        ev = Event(source="nginx", host="web-prod-01",
                   event_type="traffic_spike", message="x")
        r = Responder(audit_path=self.audit, dry_run=True)
        r.respond(ev, make_verdict(ev, decision=Decision.SUPPRESS))
        self.assertFalse(self.audit.exists())


if __name__ == "__main__":
    unittest.main()
