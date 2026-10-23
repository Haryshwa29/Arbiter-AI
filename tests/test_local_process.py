from unittest.mock import Mock

import pytest

from arbiter.ingestion.collectors.local_process import LocalProcessCollector, temporary_executable


@pytest.mark.parametrize("path", [r"C:\Users\anyuser\AppData\Local\Temp\random.exe", r"C:\Windows\Temp\worker.exe", "/tmp/a", "/var/tmp/a", "/dev/shm/a"])
def test_temporary_locations_are_generic(path):
    assert temporary_executable(path)


@pytest.mark.parametrize("path", [r"C:\Program Files\Browser\browser.exe", "/usr/bin/python3", "/tmp-other/a"])
def test_normal_paths_do_not_qualify(path):
    assert not temporary_executable(path)


def snapshots(path="/tmp/worker", connected=True, reuse=False):
    return [{"processes": [{"pid": "42", "created": "2" if reuse and index == 2 else "1",
                            "cpu": index * 4, "path": path, "command": "worker"}],
             "connections": [{"pid": "42", "remote": "10.20.0.5", "port": 12345}] if connected else []}
            for index in range(3)]


def sample(monkeypatch, data):
    collector = LocalProcessCollector({})
    collector.snapshot = Mock(side_effect=data)
    monkeypatch.setattr("arbiter.ingestion.collectors.local_process.time.monotonic", Mock(side_effect=[0, 5, 10]))
    return [list(collector.collect()) for _ in range(3)]


def test_two_high_intervals_plus_same_process_network_required(monkeypatch):
    events = sample(monkeypatch, snapshots())
    assert events[0] == [] and events[1] == []
    assert len(events[2]) == 1
    event = events[2][0]
    assert event.dst_ip == "10.20.0.5"
    assert event.metadata["consecutive_high_samples"] == 2
    assert event.metadata["cpu_percent_one_core"] == 80


@pytest.mark.parametrize("kwargs", [{"path": "/usr/bin/browser"}, {"connected": False}, {"reuse": True}])
def test_no_alert_for_normal_path_no_network_or_reused_pid(monkeypatch, kwargs):
    assert sample(monkeypatch, snapshots(**kwargs)) == [[], [], []]
