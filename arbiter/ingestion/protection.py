"""Approved, reversible local IP blocks. Never executes model commands."""
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
        return result.stdout.decode("utf-8-sig", errors="replace")

    def active(self, action_id, target):
        name = "Arbiter-" + uuid.UUID(action_id).hex
        ip = str(ipaddress.ip_address(target))
        output = self.run(f"""
$ErrorActionPreference = 'Stop'
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
if (@($profiles | Where-Object {{ [string]$_.Enabled -ne 'True' }}).Count -gt 0) {{ throw 'Firewall profile disabled' }}
$rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {{ $_.Name -like '{name}-*' }})
$valid = @($rules | Where-Object {{ $_.Enabled -eq 'True' -and $_.Action -eq 'Block' }})
$addresses = @($valid | Get-NetFirewallAddressFilter | ForEach-Object {{ $_.RemoteAddress }})
if ($valid.Count -eq 2 -and @($valid | Select-Object -ExpandProperty Direction -Unique).Count -eq 2 -and @($addresses | Where-Object {{ $_ -ne '{ip}' }}).Count -eq 0 -and $addresses.Count -eq 2) {{ Write-Output 'ARB_ACTIVE' }}
""")
        return "ARB_ACTIVE" in output.split()

    def removed(self, action_id):
        name = "Arbiter-" + uuid.UUID(action_id).hex
        output = self.run(f"""
$ErrorActionPreference = 'Stop'
$rules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {{ $_.Name -like '{name}-*' }})
if ($rules.Count -eq 0) {{ Write-Output 'ARB_REMOVED' }}
""")
        return "ARB_REMOVED" in output.split()

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
    def __init__(self, buffer, audit, firewall=None, scope=None, verify=False):
        self.buffer, self.audit = buffer, audit
        self.firewall = firewall or WindowsFirewall()
        self.scope, self.verify = scope, verify
        self.lock = threading.RLock()
        with buffer.lock, buffer.conn:
            buffer.conn.execute("CREATE TABLE IF NOT EXISTS protection_actions (id TEXT PRIMARY KEY, event_id TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL, expires_at TEXT NOT NULL, actor TEXT NOT NULL)")

    def proposal(self, row):
        if not row or row["state"] != "done" or not row["analysis"] or row["analysis"]["decision"] != "escalate":
            return None
        event = row["event"]
        sources = {"windows", "sysmon", "linux_auth", "local_process"} if self.scope else {"windows", "sysmon"}
        if "demo" in event["tags"] or "replay" in event["tags"] or row["connector"] not in sources:
            return None
        if self.scope:
            # Scoped CLI accepts only fresh, exactly local host evidence.
            if event["hostname"].casefold() != socket.gethostname().casefold(): return None
            try:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(event["timestamp"])).total_seconds()
                if not 0 <= age <= 300: return None
            except (ValueError, TypeError):
                return None
        if event["hostname"].casefold().split(".")[0] != socket.gethostname().casefold().split(".")[0]:
            return None
        correlations = row["analysis"].get("correlation", [])
        rules = {item["rule"] for item in correlations}
        if "malware_process_network" in rules and not any(
                item.get("rule") == "malware_process_network" and item.get("verified_tool_source") is True for item in correlations):
            rules.discard("malware_process_network")
        network_rules = {"suspicious_process_network", "malware_process_network"}
        if self.scope and row["connector"] == "local_process":
            network_rules.add("sustained_cpu_temporary_network")
        target = event["src_ip"] if "repeated_login_failures" in rules else event["dst_ip"] if rules.intersection(network_rules) else ""
        try:
            if not (self.scope.permits(target) if self.scope else ipaddress.ip_address(target).is_global): return None
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

    def approve(self, event_id, actor, expected_target=None, evidence_row=None):
        with self.lock:
            proposal = self.proposal(evidence_row if evidence_row is not None else self.buffer.detail(event_id))
            if not proposal: raise ValueError("no supported protection action for this event")
            if expected_target is not None and proposal["target"] != expected_target:
                raise ValueError("approval target no longer matches the proposal")
            if self.scope:
                with self.buffer.lock:
                    active = self.buffer.conn.execute("SELECT target FROM protection_actions WHERE status IN ('pending','executed','cleanup_failed')").fetchall()
                if len(active) >= 10 or any(r["target"] == proposal["target"] for r in active):
                    raise ValueError("target already blocked or ten-action containment limit reached")
            if any(r["status"] in {"executed", "pending", "cleanup_failed"} for r in self.actions(event_id)):
                raise ValueError("an action is already active for this event")
            action_id = uuid.uuid4().hex
            expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
            with self.buffer.lock, self.buffer.conn:
                self.buffer.conn.execute("INSERT INTO protection_actions VALUES (?,?,?,?,?,?)", (action_id, event_id, proposal["target"], "pending", expiry, actor))
            try:
                self.firewall.block(action_id, proposal["target"])
                if self.verify and not self.firewall.active(action_id, proposal["target"]):
                    raise ValueError("native firewall rule verification failed")
            except (ValueError, OSError, subprocess.TimeoutExpired):
                self._status(action_id, "failed")
                if self.verify:
                    try:
                        self.firewall.undo(action_id)
                        if not self.firewall.removed(action_id): raise ValueError("cleanup unverified")
                    except (ValueError, OSError, subprocess.TimeoutExpired):
                        self._status(action_id, "cleanup_failed")
                self.audit.record_iam(actor, "protection_failed", action_id)
                raise ValueError("block or verification failed; inspect action status and native firewall cleanup") from None
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
                if self.verify and not self.firewall.removed(row["id"]):
                    raise ValueError("rule removal could not be verified")
            except (ValueError, OSError, subprocess.TimeoutExpired):
                self._status(row["id"], "cleanup_failed")
                self.audit.record_iam(actor, "protection_undo_failed", row["id"])
                raise ValueError("undo failed; check local firewall permissions and action status") from None
            self._status(row["id"], "undone")
            self.audit.record_iam(actor, "protection_undone", row["id"])
            return self.actions(row["event_id"])

    def reconcile(self):
        """Recover interrupted/expired scoped CLI actions without replaying blocks."""
        if not self.verify: return
        with self.lock:
            with self.buffer.lock:
                rows = self.buffer.conn.execute("SELECT * FROM protection_actions WHERE status IN ('pending','executed','cleanup_failed')").fetchall()
            for row in rows:
                if (row["status"] != "executed" or row["expires_at"] <= datetime.now(timezone.utc).isoformat()
                        or (self.scope and not self.scope.permits(row["target"]))):
                    try:
                        self.undo(row["id"], "agent-recovery")
                        expired = row["expires_at"] <= datetime.now(timezone.utc).isoformat()
                        self._status(row["id"], "expired" if row["status"] == "executed" and expired else "recovered")
                    except ValueError:
                        pass  # persisted cleanup_failed is visible and retryable
