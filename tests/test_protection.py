import base64
import json
import socket
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from arbiter.ingestion.protection import Protection, WindowsFirewall
from arbiter.ingestion.permissions import request_elevation
from arbiter.ingestion.schema import SecurityEvent
from arbiter.ingestion.store import EventBuffer
from arbiter.store import AuditStore


class ProtectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.buffer = EventBuffer(Path(self.temp.name) / "events.db")
        self.audit = AuditStore(Path(self.temp.name) / "audit.db")
        self.firewall = Mock()
        self.protection = Protection(self.buffer, self.audit, self.firewall)

    def tearDown(self):
        self.buffer.close(); self.audit.close(); self.temp.cleanup()

    def event(self, ip="8.8.8.8", connector="windows", tags=None, host=None):
        event = SecurityEvent(source_type="windows", hostname=host or socket.gethostname(),
            event_type="auth_failure", message="test repeated login failures", src_ip=ip, tags=tags or [])
        self.buffer.enqueue(event, connector)
        row = self.buffer.claim()
        self.buffer.finish(row["id"], {"decision": "escalate", "correlation": [{"rule": "repeated_login_failures"}]}, [], 0)
        return event.event_id

    def test_only_real_local_correlated_public_addresses_qualify(self):
        for kwargs in ({"ip": "127.0.0.1"}, {"ip": "192.168.1.2"}, {"connector": "api"}, {"connector": "demo"}, {"tags": ["demo"]}, {"host": "another-device"}):
            event_id = self.event(**kwargs)
            self.assertIsNone(self.protection.proposal(self.buffer.detail(event_id)))
            with self.assertRaises(ValueError): self.protection.approve(event_id, "admin")
        self.firewall.block.assert_not_called()

    def test_explicit_approval_and_undo_are_audited_and_idempotent(self):
        event_id = self.event()
        actions = self.protection.approve(event_id, "admin")
        self.assertEqual(actions[0]["status"], "executed")
        self.firewall.block.assert_called_once()
        with self.assertRaises(ValueError): self.protection.approve(event_id, "admin")
        undone = self.protection.undo(actions[0]["id"], "admin")
        self.assertEqual(undone[0]["status"], "undone")
        self.firewall.undo.assert_called_once_with(actions[0]["id"])

    def test_failure_is_not_recorded_as_executed(self):
        self.firewall.block.side_effect = ValueError("permission denied")
        event_id = self.event()
        with self.assertRaises(ValueError): self.protection.approve(event_id, "admin")
        self.assertEqual(self.protection.actions(event_id)[0]["status"], "failed")

    def test_native_commands_have_expiry_and_do_not_accept_command_strings(self):
        firewall = WindowsFirewall()
        with patch.object(firewall, "run") as run:
            firewall.block("a" * 32, "8.8.8.8")
            script = run.call_args.args[0]
            self.assertLess(script.index("Register-ScheduledTask"), script.index("New-NetFirewallRule"))
            self.assertIn("AddMinutes(5)", script)
            self.assertIn("StartWhenAvailable", script)
            with self.assertRaises(ValueError): firewall.block("a" * 32, "8.8.8.8'; whoami")
            with self.assertRaises(ValueError): firewall.undo("bad'; whoami")


class PermissionTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows UAC test")
    def test_uac_prompt_uses_server_arguments_and_waits_for_old_process(self):
        with patch("arbiter.ingestion.permissions.is_elevated", return_value=False), patch("arbiter.ingestion.permissions.subprocess.run", return_value=Mock(returncode=0)) as run:
            request_elevation(["-u", "C:/My Files/app.pyz", "serve"], 8787)
            command = run.call_args.args[0][-1]
            self.assertIn("-Verb RunAs", command)
            self.assertFalse(run.call_args.kwargs.get("shell", False))
            encoded = command.split("'-EncodedCommand','")[1].split("'")[0]
            script = base64.b64decode(encoded).decode("utf-16le")
            self.assertIn("Get-Process -Id", script)
            self.assertIn("C:/My Files/app.pyz", script)


if __name__ == "__main__": unittest.main()
