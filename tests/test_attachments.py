"""Owned fixtures for passive edge monitoring; no network probes or device writes."""
import copy
import os
import socket
import subprocess
import sys
from unittest.mock import Mock

import pytest

from arbiter.guardrails import guardrail_check
from arbiter.ingestion.collectors.attachments import AttachmentCollector, beneath, linux_snapshot, LIMIT
from arbiter.ingestion.normalization import normalize
from arbiter.ingestion.registry import default_registry
from arbiter.ingestion.service import IngestionService
from arbiter.memory import Memory
from arbiter.prefilter import routine_telemetry
from arbiter.store import AuditStore


def snapshot(**updates):
    return {"devices": [], "interfaces": [], "neighbors": [], "executions": [],
            "connections": [], "errors": {}, **updates}


USB = {"id": "USB\\FIXTURE", "name": "Owned test phone", "class": "WPD"}
PEER = {"ip": "192.168.10.20", "mac": "02:00:00:00:00:20", "interface": "4"}
EXECUTION = {"id": "42:1000", "pid": "42", "path": "E:\\test.exe", "mount": "E:\\"}


def sample(collector, data):
    collector.snapshot = Mock(return_value=data)
    return list(collector.collect())


def test_initial_inventory_is_observation_not_vulnerability():
    collector = AttachmentCollector({})
    events = sample(collector, snapshot(devices=[USB], neighbors=[PEER]))
    assert len(events) == 2
    assert all(event.action == "present" and event.severity == 1 for event in events)
    assert all(routine_telemetry(event.to_event()) for event in events)
    assert all(guardrail_check(event.to_event()) is None for event in events)
    assert sample(collector, snapshot(devices=[USB], neighbors=[PEER])) == []


def test_hotplug_unplug_reconnect_and_restart():
    collector = AttachmentCollector({})
    sample(collector, snapshot())
    added = sample(collector, snapshot(devices=[USB]))
    assert len(added) == 1 and added[0].action == "added"
    assert not routine_telemetry(added[0].to_event())
    restarted = AttachmentCollector({}, copy.deepcopy(collector.checkpoint))
    assert sample(restarted, snapshot(devices=[USB])) == []
    removed = sample(restarted, snapshot())
    assert removed[0].action == "removed"
    reconnected = sample(restarted, snapshot(devices=[USB]))
    assert reconnected[0].action == "added"
    assert reconnected[0].event_id != added[0].event_id


def test_failed_category_is_not_a_disconnect_or_a_healthy_empty_snapshot():
    collector = AttachmentCollector({})
    sample(collector, snapshot(devices=[USB], neighbors=[PEER]))
    failed = snapshot(errors={"devices": "Permission denied", "neighbors": "Cache unavailable"})
    assert sample(collector, failed) == []
    assert collector.checkpoint["devices"]
    assert collector.health()["limitations"] == ["Permission denied", "Cache unavailable"]
    assert collector.health()["status"] == "Error"
    assert sample(collector, snapshot(devices=[USB], neighbors=[PEER])) == []


def test_neighbor_identity_changes_do_not_assert_malware():
    collector = AttachmentCollector({})
    sample(collector, snapshot(neighbors=[PEER]))
    event, = sample(collector, snapshot(neighbors=[{**PEER, "mac": "02:00:00:00:00:21"}]))
    assert event.action == "changed"
    assert "not evidence of compromise" in event.message


def test_readable_removable_execution_requires_review_even_in_initial_inventory():
    collector = AttachmentCollector({})
    event, = sample(collector, snapshot(executions=[EXECUTION]))
    assert event.event_type == "removable_process_exec"
    assert event.file_path == EXECUTION["path"]
    assert guardrail_check(event.to_event()) is not None
    assert not routine_telemetry(event.to_event())
    assert not event.dst_ip  # never turns this into an automatic peer-block proposal
    assert sample(collector, snapshot(executions=[EXECUTION])) == []


@pytest.mark.parametrize("port,review", [(5555, True), (23, True), (3389, False), (443, False)])
def test_only_observed_neighbor_edges_and_evidence_based_review(port, review):
    collector = AttachmentCollector({})
    events = sample(collector, snapshot(neighbors=[PEER], connections=[
        {"remote": PEER["ip"], "port": port, "local_port": 50000, "pid": "42"},
        {"remote": "203.0.113.20", "port": 5555, "local_port": 50001}]))
    edges = [event for event in events if event.event_type == "local_peer_connection"]
    assert len(edges) == 1
    assert (guardrail_check(edges[0].to_event()) is not None) is review
    assert "vulnerable" not in edges[0].message or "not proof" in edges[0].message


def test_queue_backpressure_retries_same_event_without_skipping():
    collector = AttachmentCollector({})
    collector.snapshot = Mock(return_value=snapshot(devices=[USB]))
    generator = collector.collect()
    event = next(generator)
    generator.close()  # submission raised; generator never resumed
    retry, = list(collector.collect())
    assert retry.event_id == event.event_id
    assert sample(collector, snapshot(devices=[USB])) == []


def test_overflow_preserves_previous_state_and_reports_limited_coverage():
    collector = AttachmentCollector({})
    sample(collector, snapshot(devices=[USB]))
    assert sample(collector, snapshot(devices=[USB] * (LIMIT + 1))) == []
    assert collector.checkpoint["devices"]
    assert collector.health()["limitations"]


def test_untrusted_import_cannot_forge_native_review_floor():
    event, = sample(AttachmentCollector({}), snapshot(executions=[EXECUTION]))
    imported = normalize(event.to_dict(), "normalized")
    assert "_tool_finding" not in imported.to_event().fields


def test_owned_snapshot_command_requires_exact_native_parent_and_script():
    from arbiter.ingestion.collectors.attachments import windows_command
    from arbiter.ingestion.evidence import own_log_query
    from arbiter.ingestion.schema import SecurityEvent
    command = windows_command()
    event = SecurityEvent(source_type="sysmon", hostname=socket.gethostname(),
        event_type="process_exec", process_name=command[0], parent_process=sys.executable,
        command_line=subprocess.list2cmdline(command), severity=1,
        message=subprocess.list2cmdline(command),
        metadata={"normalized_by": "sysmon", "legacy_fields": {"ParentProcessId": str(os.getpid())}})
    assert own_log_query(event, "sysmon")
    legacy = event.to_event()
    assert guardrail_check(legacy) is not None
    legacy.fields["_collector_activity"] = True
    assert guardrail_check(legacy) is None
    event.command_line += " evil"
    assert not own_log_query(event, "sysmon")
    event.command_line = subprocess.list2cmdline(command)
    event.parent_process = "/tmp/other-python"
    assert not own_log_query(event, "sysmon")
    event.parent_process = sys.executable
    imported = normalize(event.to_dict(), "normalized")
    assert not own_log_query(imported, "sysmon")


@pytest.mark.parametrize("path,mount,expected", [
    ("E:\\tool.exe", "E:\\", True), ("F:\\tool.exe", "E:\\", False),
    ("/media/usb/tool", "/media/usb", True), ("/media/usb-other/tool", "/media/usb", False),
])
def test_removable_path_component_boundary(path, mount, expected):
    assert beneath(path, mount) is expected


def test_native_linux_fixture_parses_usb_and_neighbors_without_probing(tmp_path, monkeypatch):
    sys = tmp_path / "sys"
    proc = tmp_path / "proc"
    files = {
        sys / "bus/usb/devices/1-1/idVendor": "1234",
        sys / "bus/usb/devices/1-1/idProduct": "5678",
        sys / "bus/usb/devices/1-1/product": "Owned test drive",
        sys / "bus/usb/devices/1-1/bDeviceClass": "00",
        sys / "class/net/eth0/operstate": "up",
        sys / "class/net/eth0/address": "02:00:00:00:00:01",
        # Portable stand-in for Linux's major:minor path (colon is invalid on Windows).
        sys / "dev/block/fixture-block/removable": "1",
        proc / "net/arp": "IP address HW type Flags HW address Mask Device\n192.168.10.20 0x1 0x2 02:00:00:00:00:20 * eth0\n",
        proc / "net/tcp": "header\n0: 0100007F:C350 140AA8C0:15B3 01 0 0 0 0 0 0\n",
        proc / "self/mountinfo": "1 0 fixture-block / /media/usb rw - vfat /dev/sdb1 rw\n",
        proc / "42/stat": "42 (test) " + " ".join(["0"] * 19 + ["1000"]),
    }
    for path, value in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
    monkeypatch.setattr("arbiter.ingestion.collectors.attachments.os.readlink", lambda path: "/media/usb/tool")
    result = linux_snapshot(sys, proc)
    assert result["errors"] == {}
    assert result["devices"][0]["vendor"] == "1234"
    assert result["neighbors"][0]["ip"] == PEER["ip"]
    assert result["executions"][0]["path"] == "/media/usb/tool"
    assert result["connections"][0]["remote"] == PEER["ip"]
    assert result["connections"][0]["port"] == 5555


def test_registry_interval_validation():
    registry = default_registry()
    assert registry.create("attachments", {"interval": 5}).interval == 5
    for interval in (True, 0, float("nan"), float("inf")):
        with pytest.raises(ValueError):
            registry.validate("attachments", {"interval": interval})


def test_terminal_agent_preserves_disabled_attachment_source(monkeypatch):
    from arbiter.agent import Agent
    agent = Agent.__new__(Agent)
    agent.service = Mock()
    agent.service.buffer.configs.return_value = [{"name": "attachments", "enabled": False}]
    monkeypatch.setattr("arbiter.agent.platform.system", lambda: "Linux")
    monkeypatch.setattr("arbiter.agent.Path.is_file", lambda path: False)
    agent.start()
    assert all(call.args[0] != "attachments" for call in agent.service.configure.call_args_list)
    agent.service._start.assert_not_called()


def test_auto_discovery_respects_explicitly_disabled_source(tmp_path, monkeypatch):
    memory = Memory(tmp_path / "memory.db")
    audit = AuditStore(tmp_path / "audit.db")
    service = IngestionService(tmp_path / "events.db", memory, audit)
    try:
        service.configure("attachments", False, {"interval": 15})
        monkeypatch.setattr("arbiter.ingestion.discovery.discover_local", lambda: {"attachments": {"interval": 15}})
        monkeypatch.setattr(service.discovery_stop, "wait", lambda seconds: service.discovery_stop.set())
        service._discover()
        assert service.buffer.configs()[0]["enabled"] == 0
        assert "attachments" not in service.collectors
    finally:
        service.stop()
        memory.close()
        audit.close()


def test_real_pipeline_retains_inventory_and_escalates_removable_execution(tmp_path):
    memory = Memory(tmp_path / "memory.db")
    audit = AuditStore(tmp_path / "audit.db")
    service = IngestionService(tmp_path / "events.db", memory, audit)
    try:
        events = sample(AttachmentCollector({}), snapshot(devices=[USB], executions=[EXECUTION]))
        for event in events:
            service.buffer.enqueue(event, "attachments")
            assert service.pipeline.process_one()
        inventory = service.buffer.detail(events[0].event_id)
        execution = service.buffer.detail(events[1].event_id)
        assert inventory["analysis"]["decision"] == "suppress"
        assert execution["analysis"]["decision"] == "escalate"
        assert execution["analysis"]["tier"] == "guardrail"
    finally:
        service.stop()
        memory.close()
        audit.close()
