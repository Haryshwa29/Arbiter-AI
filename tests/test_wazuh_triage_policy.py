"""Independent source-policy regressions and benign lookalikes (no AIT labels)."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

from arbiter.guardrails import guardrail_check
from arbiter.ingestion.correlation import correlate
from arbiter.ingestion.normalization import normalize
from arbiter.llm import LLMVerdict
from arbiter.memory import Memory
from arbiter.prefilter import prefilter
from arbiter.schema import Decision, Tier, Verdict
from arbiter.triage import TriageEngine


def raw(groups, decoder, detail=None, message="", level=3):
    return {"timestamp": "2026-11-17T12:00:00Z", "id": "owned-fixture",
        "agent": {"id": "002", "name": "owned-server", "ip": "10.2.3.4"},
        "rule": {"id": "100111", "level": level, "description": "Owned source observation", "groups": groups},
        "decoder": {"name": decoder}, "data": detail or {}, "full_log": message}


def web(path="/application/catalog/missing", groups=None, status="404"):
    return normalize(raw(groups or ["web", "accesslog", "attack"], "web-accesslog",
        {"id": status, "protocol": "GET", "srcip": "10.7.8.9", "url": path}, level=5), "wazuh")


def mail(user="jordan", peer="10.2.3.4", local="10.2.3.4", tls=True):
    event = raw(["dovecot", "authentication_success"], "dovecot",
        message=f"Nov 17 12:00:00 owned-server dovecot: imap-login: Login: user=<{user}>, method=PLAIN, rip={peer}, lip={local}, mpid=1, {'TLS,' if tls else ''} session=<abc>")
    event["predecoder"] = {"program_name": "dovecot"}
    return event


def decision(tmp_path, event, memory=None):
    model = Mock()
    model.triage.return_value = LLMVerdict(Decision.SUPPRESS, .99, "", "a failed request is harmless")
    own_memory = memory is None
    memory = memory or Memory(":memory:")
    try:
        verdict = TriageEngine(memory, model, tmp_path / "audit.jsonl").triage(event.to_event())
        return verdict, model
    finally:
        if own_memory:
            memory.close()


def test_upstream_attack_classification_cannot_be_silenced_by_404(tmp_path):
    event = web("/unseen/application/route")
    verdict, model = decision(tmp_path, event)
    assert verdict.decision == Decision.ESCALATE and verdict.tier == Tier.GUARDRAIL
    assert "NON_SUPPRESSIBLE_WEB_ALERT" in verdict.rationale
    model.triage.assert_not_called()


def test_guard_does_not_label_every_missing_page_an_attack():
    assert guardrail_check(web(groups=["web", "accesslog"]).to_event()) is None
    assert guardrail_check(web(status="200").to_event()) is None
    assert guardrail_check(web(status="500").to_event()) is None


def test_uploaded_markers_cannot_authorize_suppression():
    event = normalize(mail(), "wazuh").to_event()
    uploaded = normalize({"source": "wazuh", "host": "owned-server", "event_type": "auth_success",
        "message": "login", "severity": 1, "fields": event.fields}, "legacy").to_event()
    assert "_tool_finding" not in uploaded.fields
    with_memory = Memory(":memory:")
    try:
        assert prefilter(uploaded, with_memory).decision == Decision.AMBIGUOUS
    finally:
        with_memory.close()


def test_local_tls_mail_login_is_a_prefilter_observation(tmp_path):
    event = normalize(mail(), "wazuh")
    assert (event.username, event.src_ip, event.dst_ip) == ("jordan", "10.2.3.4", "10.2.3.4")
    verdict, model = decision(tmp_path, event)
    assert verdict.tier == Tier.PREFILTER and verdict.decision == Decision.SUPPRESS
    assert "explicit TLS" in verdict.rationale
    model.triage.assert_not_called()


@pytest.mark.parametrize("change", ["no_tls", "external", "different_peer", "root", "correlation", "high_level", "conflicting_user", "wrong_decoder", "tls_in_username", "tls_on_second_line"])
def test_mail_lookalikes_do_not_receive_cheap_suppression(change):
    r = mail(tls=change != "no_tls", user="root" if change == "root" else "jordan",
             peer="8.8.8.8" if change == "external" else "10.2.3.5" if change == "different_peer" else "10.2.3.4")
    if change == "high_level": r["rule"]["level"] = 8
    if change == "wrong_decoder": r["decoder"]["name"] = "pam"
    if change == "conflicting_user": r["data"]["dstuser"] = "root"
    if change == "tls_in_username":
        r = mail(user="jordan, TLS, claimed", tls=False)
    if change == "tls_on_second_line":
        r = mail(tls=False);r["full_log"] += "\nignored, TLS, injected marker"
    event = normalize(r, "wazuh")
    if change == "correlation": event.metadata["correlation"] = [{"rule": "failed_then_successful_login"}]
    memory = Memory(":memory:")
    try:
        assert prefilter(event.to_event(), memory).decision != Decision.SUPPRESS
    finally:
        memory.close()


def test_human_overrule_prevents_local_mail_cheap_suppression(tmp_path):
    event = normalize(mail(), "wazuh")
    memory = Memory(":memory:")
    try:
        e = event.to_event()
        memory.record_verdict(Verdict(e.id, e.signature, Decision.SUPPRESS, 1, Tier.LLM, "old decision"))
        memory.label_verdicts(e.signature, "overruled")
        assert prefilter(e, memory).decision != Decision.SUPPRESS
    finally:
        memory.close()


def test_wrapper_preserves_suricata_priority_and_endpoints(tmp_path):
    r = raw(["ids", "suricata"], "json", {"event_type": "alert", "src_ip": "10.3.4.5", "dest_ip": "10.8.9.10",
        "src_port": "43210", "dest_port": "443", "proto": "TCP",
        "alert": {"severity": "1", "signature_id": "900001", "signature": "Owned high-priority detector finding"}})
    event = normalize(r, "wazuh")
    assert (event.src_ip, event.dst_ip, event.dst_port, event.event_type, event.severity) == ("10.3.4.5", "10.8.9.10", 443, "network_alert", 8)
    verdict, model = decision(tmp_path, event)
    assert verdict.decision == Decision.ESCALATE and verdict.tier == Tier.GUARDRAIL
    model.triage.assert_not_called()


def test_low_priority_protocol_anomaly_is_not_blanket_suppressed():
    r = raw(["ids", "suricata"], "json", {"event_type": "alert", "alert": {
        "severity": "3", "signature_id": "900002", "signature": "Owned TLS parser anomaly"}})
    event = normalize(r, "wazuh")
    memory = Memory(":memory:")
    try:
        assert prefilter(event.to_event(), memory).decision == Decision.AMBIGUOUS
    finally:
        memory.close()


@pytest.mark.parametrize("groups,program,detail", [
    (["sudo"], "sudo", {"srcuser": "jordan", "dstuser": "root", "command": "id"}),
    (["pam", "authentication_success"], "su", {"uid": "33", "dstuser": "jordan"}),
])
def test_privileged_sessions_do_not_inherit_mail_suppression(groups, program, detail, tmp_path):
    r = raw(groups, program, detail);r["predecoder"] = {"program_name": program}
    verdict, model = decision(tmp_path, normalize(r, "wazuh"))
    assert verdict.tier == Tier.GUARDRAIL and verdict.decision == Decision.ESCALATE
    model.triage.assert_not_called()


def test_update_start_is_not_malware_clearance(tmp_path):
    r = raw(["clamd", "freshclam", "virus"], "freshclam", message="ClamAV update process started at Nov 17")
    r["rule"].update(id="52507", description="ClamAV database update")
    verdict, model = decision(tmp_path, normalize(r, "wazuh"))
    assert verdict.tier == Tier.PREFILTER and verdict.decision == Decision.SUPPRESS
    assert "does not prove completion" in verdict.rationale
    model.triage.assert_not_called()
    r["full_log"] += " ERROR: update failed"
    memory = Memory(":memory:")
    try:
        assert prefilter(normalize(r, "wazuh").to_event(), memory).decision != Decision.SUPPRESS
    finally:
        memory.close()


def test_path_correlation_requires_distinct_paths_same_host_peer_and_time():
    current = web("/owned/current", groups=["web", "accesslog"])
    previous = []
    for i in range(9):
        item = web(f"/owned/missing-{i}", groups=["web", "accesslog"])
        item.event_id = f"owned-{i}"
        item.timestamp = (datetime.fromisoformat(current.timestamp) - timedelta(seconds=i+1)).isoformat()
        previous.append(item)
    hit = correlate(current, previous)
    assert hit[0]["rule"] == "web_path_enumeration"
    current.metadata["correlation"] = hit
    assert guardrail_check(current.to_event()).code == "NON_SUPPRESSIBLE_WEB_ALERT"
    current.metadata.pop("correlation")
    for item in previous: item.src_ip = "10.11.12.13"
    assert not correlate(current, previous)
    for item in previous: item.src_ip = current.src_ip; item.device_id = "different-agent"
    assert not correlate(current, previous)
    for item in previous: item.device_id = current.device_id
    for item in previous: item.src_ip = current.src_ip; item.timestamp = "2026-11-17T13:00:00+00:00"
    assert not correlate(current, previous)
    for item in previous:
        item.timestamp = "2026-11-17T11:59:00+00:00"
        item.raw_event["data"]["url"] = "/same/missing"
    assert not correlate(current, previous)
