from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import subprocess
from unittest.mock import Mock

import pytest

from arbiter.agent import Agent, StateLock
from arbiter.ingestion.collectors.linux_auth import LinuxAuthCollector, parse_auth
from arbiter.ingestion.containment import ContainmentScope, LinuxFirewall
from arbiter.ingestion.schema import SecurityEvent


def scope():
    return ContainmentScope(["10.20.0.0/24"], ["10.20.0.1", "10.20.0.2"])


@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.1.2", "224.0.0.1", "0.0.0.0",
    "10.20.0.0", "10.20.0.255", "10.20.0.1", "10.20.0.2", "10.21.0.10", "8.8.8.8",
    "10.20.0.5; whoami"])
def test_scope_rejects_special_protected_and_unenrolled_addresses(address):
    assert not scope().permits(address)


def test_private_addresses_need_explicit_enrollment():
    assert scope().permits("10.20.0.5")
    with pytest.raises(ValueError): ContainmentScope(["0.0.0.0/0"], ["10.20.0.1"])
    with pytest.raises(ValueError): ContainmentScope(["10.20.0.0/24"], [])
    ipv6 = ContainmentScope(["fd00::/64"], ["fd00::1"])
    assert ipv6.permits("fd00::2")
    assert not ipv6.permits("fd00::1")


def test_state_directory_excludes_second_worker(tmp_path):
    lock = StateLock(tmp_path / "lock")
    try:
        with pytest.raises(ValueError): StateLock(tmp_path / "lock")
    finally:
        lock.close()
    StateLock(tmp_path / "lock").close()


def auth_event(index, source="10.20.0.5", tags=None, stamp=None):
    stamp = stamp or datetime.now(timezone.utc).isoformat()
    return SecurityEvent(source_type="linux_auth", hostname=socket.gethostname(),
        event_type="auth_failure", event_category="authentication", username="labuser",
        src_ip=source, message="Failed OpenSSH password authentication", severity=2,
        event_id=f"auth-{index}", timestamp=stamp, tags=tags or [])


def ingest(agent, source="10.20.0.5", connector="linux_auth", tags=None, stamp=None):
    for index in range(5):
        event = auth_event(index, source, tags, stamp)
        agent.service.buffer.enqueue(event, connector)
        assert agent.service.pipeline.process_one()
    return event.event_id


@pytest.fixture
def agent(tmp_path):
    firewall = Mock()
    firewall.active.return_value = True
    firewall.removed.return_value = True
    instance = Agent(tmp_path, scope=scope(), firewall=firewall)
    yield instance
    instance.close()


@pytest.mark.parametrize("connector", ["linux_auth", "windows"])
def test_real_pipeline_manual_approval_and_verified_undo(agent, connector):
    event_id = ingest(agent, connector=connector)
    proposal = agent.events()[0]["proposal"]
    assert proposal and proposal["target"] == "10.20.0.5"
    agent.protection.firewall.block.assert_not_called()
    with pytest.raises(ValueError): agent.command(f"approve {event_id} 10.20.0.6")
    result = agent.command(f"approve {event_id} 10.20.0.5")
    assert result["native_rule_verified"]
    assert not result["connectivity_verified"]
    with pytest.raises(ValueError): agent.command(f"approve {event_id} 10.20.0.5")
    action = result["actions"][0]
    assert agent.command(f"undo {action['id']}")["native_removal_verified"]
    assert agent.protection.actions(event_id)[0]["status"] == "undone"


@pytest.mark.parametrize("kwargs", [
    {"source": "10.20.0.1"}, {"connector": "api"}, {"tags": ["demo"]},
    {"stamp": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()},
])
def test_no_action_for_protected_untrusted_simulated_or_stale_events(agent, kwargs):
    event_id = ingest(agent, **kwargs)
    assert agent.events()[0]["proposal"] is None
    with pytest.raises(ValueError): agent.command(f"approve {event_id} 10.20.0.5")
    agent.protection.firewall.block.assert_not_called()


def test_failed_verification_rolls_back_and_records_failure(agent):
    event_id = ingest(agent)
    agent.protection.firewall.active.return_value = False
    with pytest.raises(ValueError): agent.command(f"approve {event_id} 10.20.0.5")
    agent.protection.firewall.undo.assert_called_once()
    assert agent.protection.actions(event_id)[0]["status"] == "failed"


def test_unverified_cleanup_is_visible_and_prevents_reapproval(agent):
    event_id = ingest(agent)
    agent.protection.firewall.active.return_value = False
    agent.protection.firewall.removed.return_value = False
    with pytest.raises(ValueError): agent.command(f"approve {event_id} 10.20.0.5")
    assert agent.protection.actions(event_id)[0]["status"] == "cleanup_failed"
    with pytest.raises(ValueError): agent.command(f"approve {event_id} 10.20.0.5")


def test_restart_recovers_pending_and_expired_actions(tmp_path):
    first = Agent(tmp_path, scope=scope(), firewall=Mock())
    event_id = ingest(first)
    action = first.command(f"approve {event_id} 10.20.0.5")["actions"][0]
    with first.service.buffer.lock, first.service.buffer.conn:
        first.service.buffer.conn.execute("UPDATE protection_actions SET status='pending' WHERE id=?", (action["id"],))
    first.close()
    firewall = Mock()
    firewall.removed.return_value = True
    second = Agent(tmp_path, scope=scope(), firewall=firewall)
    try:
        firewall.block.assert_not_called()
        firewall.undo.assert_called_once_with(action["id"])
        assert second.protection.actions(event_id)[0]["status"] == "recovered"
    finally:
        second.close()


def test_expired_action_is_removed_and_recorded_without_reblocking(agent):
    event_id = ingest(agent)
    action_id = agent.command(f"approve {event_id} 10.20.0.5")["actions"][0]["id"]
    with agent.service.buffer.lock, agent.service.buffer.conn:
        agent.service.buffer.conn.execute("UPDATE protection_actions SET expires_at=? WHERE id=?",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), action_id))
    result = agent.command("actions")
    assert result["actions"][0]["status"] == "expired"
    agent.protection.firewall.block.assert_called_once()
    agent.protection.firewall.undo.assert_called_once_with(action_id)


def test_observer_cannot_approve(agent):
    event_id = ingest(agent)
    agent.scope = None
    with pytest.raises(ValueError, match="containment is disabled"):
        agent.command(f"approve {event_id} 10.20.0.5")
    agent.protection.firewall.block.assert_not_called()


def test_new_protection_scope_releases_a_previously_allowed_peer(agent):
    event_id = ingest(agent)
    action_id = agent.command(f"approve {event_id} 10.20.0.5")["actions"][0]["id"]
    agent.protection.scope = ContainmentScope(["10.20.0.0/24"], ["10.20.0.5"])
    assert agent.command("actions")["actions"][0]["status"] == "recovered"
    agent.protection.firewall.undo.assert_called_once_with(action_id)


def test_rules_only_is_never_reported_as_model_inference(agent):
    event_id = ingest(agent)
    first = agent.service.buffer.detail("auth-0")
    assert first["analysis"]["backend"] == "rules-only-policy"
    assert agent.service.buffer.detail(event_id)["analysis"]["decision"] == "escalate"
    metrics = agent.service.buffer.metrics()
    assert metrics["events_escalated_to_ai"] == 0
    assert metrics["events_handled_deterministically"] == 5


def test_linux_parser_preserves_account_source_and_offset_timestamp():
    event = parse_auth("2026-10-19T12:00:00+00:00 vm sshd[123]: Failed password for invalid user bob from 10.20.0.5 port 4567 ssh2", "record")
    assert (event.username, event.src_ip, event.src_port) == ("bob", "10.20.0.5", 4567)
    assert event.event_type == "auth_failure"
    assert parse_auth("ordinary unrelated daemon output", "ignored") is None


def test_file_tail_does_not_ingest_history_and_retries_uncommitted_line(tmp_path):
    path = tmp_path / "auth.log"
    line = b"2026-10-19T12:00:00+00:00 vm sshd[123]: Failed password for bob from 10.20.0.5 port 4567 ssh2\n"
    path.write_bytes(line)
    collector = LinuxAuthCollector({"path": str(path), "read_existing": False})
    assert list(collector.collect()) == []
    with path.open("ab") as output: output.write(line)
    iterator = iter(collector.collect())
    event = next(iterator)
    iterator.close()  # simulate rejected enqueue: cursor has not advanced
    assert list(collector.collect())[0].event_id == event.event_id
    assert list(collector.collect()) == []
    # A partial line is not consumed until its newline arrives.
    with path.open("ab") as output: output.write(line[:-1])
    assert list(collector.collect()) == []
    with path.open("ab") as output: output.write(b"\n")
    assert len(list(collector.collect())) == 1


def test_linux_adapter_uses_atomic_native_ttl_without_shell(monkeypatch):
    monkeypatch.setattr("arbiter.ingestion.containment.platform.system", lambda: "Linux")
    run = Mock(return_value=Mock(returncode=0, stdout=""))
    monkeypatch.setattr("arbiter.ingestion.containment.subprocess.run", run)
    firewall = LinuxFirewall("/usr/sbin/nft")
    firewall.block("a" * 32, "10.20.0.5")
    script = run.call_args.kwargs["input"]
    assert "timeout 300s" in script
    assert "hook input" in script and "hook output" in script
    assert "flush" not in script
    assert not run.call_args.kwargs.get("shell", False)
    with pytest.raises(ValueError): firewall.block("a" * 32, "10.20.0.5; whoami")
    with pytest.raises(ValueError): firewall.undo("invalid")
