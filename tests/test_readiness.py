"""Readiness must not mistake prerequisites for verified containment."""
import argparse
import json

import pytest

from arbiter import readiness


def test_linux_root_with_tools_is_not_claimed_ready(monkeypatch):
    monkeypatch.setattr(readiness.platform, "system", lambda: "Linux")
    monkeypatch.setattr(readiness.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(readiness.shutil, "which", lambda name: "/usr/bin/" + name)
    report = readiness.inspect_host()
    assert report["privileged"] is True
    assert report["local_firewall_adapter_available"]
    assert not report["cli_containment_ready"]
    assert not report["live_containment_verified"]


def test_windows_without_privilege_or_powershell(monkeypatch):
    from arbiter.ingestion import permissions
    monkeypatch.setattr(readiness.platform, "system", lambda: "Windows")
    monkeypatch.setattr(permissions, "is_elevated", lambda: False)
    monkeypatch.setattr(readiness.shutil, "which", lambda name: None)
    report = readiness.inspect_host()
    assert report["privileged"] is False
    assert not report["local_firewall_adapter_available"]
    assert any("administrator" in item for item in report["blockers"])
    assert any("PowerShell" in item for item in report["blockers"])


def test_windows_admin_does_not_imply_cli_ready(monkeypatch):
    from arbiter.ingestion import permissions
    monkeypatch.setattr(readiness.platform, "system", lambda: "Windows")
    monkeypatch.setattr(permissions, "is_elevated", lambda: True)
    monkeypatch.setattr(readiness.shutil, "which", lambda name: name)
    report = readiness.inspect_host()
    assert report["local_firewall_adapter_available"]
    assert not report["cli_containment_ready"]


def test_unsupported_os_does_not_probe_windows_privileges(monkeypatch):
    monkeypatch.setattr(readiness.platform, "system", lambda: "Darwin")
    report = readiness.inspect_host()
    assert report["privileged"] is None
    assert not report["local_firewall_adapter_available"]
    assert "unsupported" in report["blockers"][0]


def test_json_report_remains_available_when_gate_fails(monkeypatch, capsys):
    monkeypatch.setattr(readiness.platform, "system", lambda: "Linux")
    monkeypatch.setattr(readiness.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(readiness.shutil, "which", lambda name: None)
    with pytest.raises(SystemExit) as error:
        readiness.cmd_readiness(argparse.Namespace(json=True, require_ready=True))
    assert error.value.code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["os"] == "Linux"
    assert not report["cli_containment_ready"]
    assert any("nftables" in item for item in report["blockers"])
