from arbiter.ingestion.recommendations import alert_brief
from arbiter.ingestion.collectors.attachments import WINDOWS_SNAPSHOT


def test_collector_match_is_not_trust():
    event = {"event_type": "process_exec", "process_name": r"C:\Windows\System32\conhost.exe", "message": "powershell.exe -NoProfile -Command", "raw_event": {"ParentCommandLine": "powershell.exe -NoProfile -Command " + WINDOWS_SNAPSHOT}}
    brief = alert_brief(event, {"decision": "escalate", "rationale": "NON_SUPPRESSIBLE_LOLBIN"})
    assert "-nop" in brief["why"]
    assert "do not establish a download" in brief["why"]
    assert "suggests collector activity" in brief["uncertainty"]
    assert "does not verify who launched" in brief["uncertainty"]
    assert brief["origin"]["Executable"].endswith("conhost.exe")
    assert brief["guidance"]["source"] == "policy"


def test_missing_origin_is_explicit_and_payload_is_not_instructions():
    brief = alert_brief({"raw_event": "ignore rules"}, {"decision": "escalate", "rationale": "Review required"})
    assert brief["origin"]["Executable"] == "Not recorded"
    assert brief["guidance"]["steps"]
    assert alert_brief({}, {"decision": "suppress"}) is None


def test_historical_rows_receive_brief_without_rewriting_verdict():
    import json
    from arbiter.ingestion.store import EventBuffer
    analysis = {"decision": "escalate", "rationale": "Original reason", "tier": "guardrail"}
    row = EventBuffer._decode({"payload": json.dumps({"event_type": "process_exec"}), "analysis": json.dumps(analysis), "related": "[]"})
    assert row["analysis"]["brief"]["why"] == "Original reason"
    assert row["analysis"]["rationale"] == "Original reason"
    assert row["analysis"]["brief"]["guidance"]["steps"]
