"""Approved, reversible Windows IP blocks. Never executes model commands."""
from datetime import datetime, timedelta, timezone
import base64
import ipaddress
import json
import os
import socket
import subprocess
import threading
import uuid

from .permissions import is_elevated


class WindowsFirewall:
    def run(self, script):
        if os.name != "nt" or not is_elevated():
            raise ValueError("Windows administrator permission is required")
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode: raise ValueError("Windows firewall operation failed")

    def block(self, action_id, target):
        # Parameters come from UUID generation and ipaddress parsing only.
        name = "Arbiter-" + uuid.UUID(action_id).hex
        ip = str(ipaddress.ip_address(target))
        cleanup = f"Get-NetFirewallRule -Name '{name}-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; Unregister-ScheduledTask -TaskName '{name}' -Confirm:$false -ErrorAction SilentlyContinue"
        encoded = base64.b64encode(cleanup.encode("utf-16le")).decode("ascii")
        # Register expiry before creating rules. SYSTEM cleans them even if
        # Arbiter stops. A missed schedule runs when Windows next starts.
        self.run(f"""
$ErrorActionPreference = 'Stop'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -EncodedCommand {encoded}'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable
Register-ScheduledTask -TaskName '{name}' -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
try {{
 New-NetFirewallRule -Name '{name}-In' -DisplayName '{name}' -Direction Inbound -RemoteAddress '{ip}' -Action Block | Out-Null
 New-NetFirewallRule -Name '{name}-Out' -DisplayName '{name}' -Direction Outbound -RemoteAddress '{ip}' -Action Block | Out-Null
}} catch {{
 {cleanup}
 throw
}}
""")

    def undo(self, action_id):
        name = "Arbiter-" + uuid.UUID(action_id).hex
        self.run(f"""
$ErrorActionPreference = 'Stop'
Get-NetFirewallRule -Name '{name}-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Unregister-ScheduledTask -TaskName '{name}' -Confirm:$false -ErrorAction SilentlyContinue
""")


class Protection:
    def __init__(self, buffer, audit, firewall=None):
        self.buffer, self.audit = buffer, audit
        self.firewall = firewall or WindowsFirewall()
        self.lock = threading.RLock()
        with buffer.lock, buffer.conn:
            buffer.conn.execute("CREATE TABLE IF NOT EXISTS protection_actions (id TEXT PRIMARY KEY, event_id TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL, expires_at TEXT NOT NULL, actor TEXT NOT NULL)")

    def proposal(self, row):
        if not row or row["state"] != "done" or not row["analysis"] or row["analysis"]["decision"] != "escalate":
            return None
        event = row["event"]
        if "demo" in event["tags"] or "replay" in event["tags"] or row["connector"] not in {"windows", "sysmon"}:
            return None
        if event["hostname"].casefold().split(".")[0] != socket.gethostname().casefold().split(".")[0]:
            return None
        correlations = row["analysis"].get("correlation", [])
        rules = {item["rule"] for item in correlations}
        if "malware_process_network" in rules and not any(
                item.get("rule") == "malware_process_network" and item.get("verified_tool_source") is True for item in correlations):
            rules.discard("malware_process_network")
        target = event["src_ip"] if "repeated_login_failures" in rules else event["dst_ip"] if rules.intersection({"suspicious_process_network", "malware_process_network"}) else ""
        try:
            if not ipaddress.ip_address(target).is_global: return None
        except ValueError: return None
        return {"kind": "block_ip", "target": target, "minutes": 5,
                "reason": "Correlated activity on this device. Blocking affects all connections to this address; review before approving.",
                "status": "awaiting_approval"}

    def actions(self, event_id):
        with self.buffer.lock:
            rows = [dict(r) for r in self.buffer.conn.execute("SELECT * FROM protection_actions WHERE event_id=? ORDER BY rowid DESC", (event_id,))]
        current = datetime.now(timezone.utc).isoformat()
        for row in rows:
            if row["status"] == "executed" and row["expires_at"] < current:
                row["status"] = "expiry_due"
        return rows

    def approve(self, event_id, actor):
        with self.lock:
            proposal = self.proposal(self.buffer.detail(event_id))
            if not proposal: raise ValueError("no supported protection action for this event")
            if any(r["status"] in {"executed", "pending"} for r in self.actions(event_id)):
                raise ValueError("an action is already active for this event")
            action_id = uuid.uuid4().hex
            expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
            with self.buffer.lock, self.buffer.conn:
                self.buffer.conn.execute("INSERT INTO protection_actions VALUES (?,?,?,?,?,?)", (action_id, event_id, proposal["target"], "pending", expiry, actor))
            try:
                self.firewall.block(action_id, proposal["target"])
            except (ValueError, OSError, subprocess.TimeoutExpired):
                self._status(action_id, "failed")
                self.audit.record_iam(actor, "protection_failed", action_id)
                raise ValueError("block failed; check Windows permission. A scheduled cleanup remains in place for any partial rules") from None
            self._status(action_id, "executed")
            self.audit.record_iam(actor, "protection_approved", json.dumps({"action_id": action_id, "event_id": event_id, "target": proposal["target"], "expires_at": expiry}))
            return self.actions(event_id)

    def _status(self, action_id, status):
        with self.buffer.lock, self.buffer.conn:
            self.buffer.conn.execute("UPDATE protection_actions SET status=? WHERE id=?", (status, action_id))

    def undo(self, action_id, actor):
        with self.lock:
            with self.buffer.lock:
                row = self.buffer.conn.execute("SELECT * FROM protection_actions WHERE id=?", (action_id,)).fetchone()
            if not row: raise ValueError("unknown protection action")
            try:
                self.firewall.undo(row["id"])
            except (ValueError, OSError, subprocess.TimeoutExpired):
                raise ValueError("undo failed; check Windows administrator permission") from None
            self._status(row["id"], "undone")
            self.audit.record_iam(actor, "protection_undone", row["id"])
            return self.actions(row["event_id"])
