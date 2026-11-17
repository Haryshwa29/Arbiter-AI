"""Evidence integrity checks for the offline public-data evaluation tool."""
import copy
import json
from datetime import datetime

import pytest

from tools.public_dataset_eval import check_match, event_from_raw, metrics, wilson
from arbiter.llm import build_prompt


def test_alignment_rejects_wrong_rule_and_host():
    raw = {"rule": {"description": "ClamAV database update"}, "agent": {"ip": "10.0.0.1"}}
    row = {"name": "Wazuh: ClamAV database update", "ip": "10.0.0.1"}
    check_match(raw, row)
    with pytest.raises(ValueError):
        check_match(raw, {**row, "ip": "10.0.0.2"})
    with pytest.raises(ValueError):
        check_match(raw, {**row, "name": "different"})


def test_native_adapter_preserves_evidence_without_label_input():
    raw = {"rule": {"description": "ClamAV database update", "id": "52507", "level": 3, "groups": ["clamd"]},
        "agent": {"ip": "10.0.0.1", "id": "1", "name": "mail"}, "@timestamp": "2022-01-21T00:02:27Z",
        "id": "original", "full_log": "freshclam: update completed"}
    before = copy.deepcopy(raw)
    event = event_from_raw(raw)
    prompt = build_prompt(event, 1, "first occurrence of this signature", [])
    assert raw == before
    assert event.severity == 2
    assert datetime.fromisoformat(event.timestamp) == datetime.fromisoformat(raw["@timestamp"])
    assert "freshclam: update completed" in prompt
    assert "event_label" not in prompt and "expected_attack" not in prompt and "time_label" not in prompt
    raw["data"] = {"srcip": "192.168.128.4:48308"}
    event = event_from_raw(raw)
    assert event.fields["src_ip"] == "192.168.128.4"
    assert event.fields["src_port"] == 48308
    assert raw["data"]["srcip"] == "192.168.128.4:48308"


def test_metrics_do_not_reward_always_escalate_as_noise_reduction():
    rows = [{"expected_attack": b, "decision": "escalate"} for b in [True, True, False, False]]
    m = metrics(rows)
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (2, 0, 2, 0)
    assert m["attack_label_recall"] == 1
    assert m["negative_label_suppression"] == 0
    assert m["sample_precision"] == .5


def test_empty_denominators_are_undefined_and_intervals_are_bounded():
    m = metrics([])
    assert m["attack_label_recall"] is None
    assert m["sample_precision"] is None
    assert wilson(0, 0) is None
    assert 0 <= wilson(0, 8)[0] < wilson(0, 8)[1] < 1
    assert 0 < wilson(8, 8)[0] < wilson(8, 8)[1] <= 1
