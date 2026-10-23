"""Durable L1 review deadlines; narrow, explicitly enrolled timed responses.

Runs independently of inference. The model can supply advice, never authority.
Demo workflows have no actuator and persist only simulated actions.
"""
from datetime import datetime, timezone
import ipaddress
import json
import threading
import time

from .containment import ContainmentScope
from .protection import Protection
from .recommendations import guidance

WINDOWS = {"critical": 60, "high": 300, "medium": 1800, "low": None}
RULES = {"repeated_login_failures", "malware_process_network"}


class ResponseWorkflow:
    def __init__(self, buffer, audit, protection=None, simulation=False, clock=time.time):
        self.buffer, self.audit, self.protection = buffer, audit, protection
        self.simulation, self.clock = simulation, clock
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.thread = None
        self.error = ""
        self._last_reconcile = 0
        with buffer.lock, buffer.conn:
            buffer.conn.execute("CREATE TABLE IF NOT EXISTS l1_response_cases (event_id TEXT PRIMARY KEY, body TEXT NOT NULL)")
            buffer.conn.execute("CREATE TABLE IF NOT EXISTS l1_response_seen (event_id TEXT PRIMARY KEY)")
            buffer.conn.execute("CREATE TABLE IF NOT EXISTS l1_response_settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
            buffer.conn.execute("CREATE INDEX IF NOT EXISTS idx_l1_response_state ON l1_response_cases(json_extract(body,'$.state'))")
            buffer.conn.execute("CREATE INDEX IF NOT EXISTS idx_l1_response_scan ON telemetry(priority DESC,id) WHERE state='done' AND decision='escalate'")
            buffer.conn.execute("INSERT OR IGNORE INTO l1_response_settings VALUES ('stopped','false')")
        for case in self.cases(["executing"]):
            if case["state"] == "executing":
                case.update(state="needs_review", note="Interrupted action: inspect the native firewall and action record. Execution will not be retried.")
                self.save(case, "l1_interrupted")

    def cases(self, states=None):
        with self.buffer.lock:
            clause = " WHERE json_extract(body,'$.state') IN (" + ",".join("?" for _ in states) + ")" if states else ""
            return [json.loads(r[0]) for r in self.buffer.conn.execute("SELECT body FROM l1_response_cases" + clause, states or [])]

    def status(self):
        condition = "json_extract(body,'$.state') IN ('pending','overdue','needs_review')"
        with self.buffer.lock:
            total = self.buffer.conn.execute("SELECT COUNT(*) FROM l1_response_cases WHERE " + condition).fetchone()[0]
            rows = self.buffer.conn.execute("SELECT body FROM l1_response_cases WHERE " + condition +
                " ORDER BY CASE json_extract(body,'$.severity') WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, COALESCE(json_extract(body,'$.deadline'),1e20) LIMIT 50").fetchall()
        return {"stopped": self.stopped(), "error": self.error, "cases": [json.loads(r[0]) for r in rows], "total": total}

    def get(self, event_id):
        with self.buffer.lock:
            row = self.buffer.conn.execute("SELECT body FROM l1_response_cases WHERE event_id=?", (event_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def save(self, case, action=None, actor="l1-policy"):
        with self.buffer.lock, self.buffer.conn:
            self.buffer.conn.execute("INSERT OR REPLACE INTO l1_response_cases VALUES (?,?)", (case["event_id"], json.dumps(case)))
        if action: self.audit.record_iam(actor, action, json.dumps(case))

    def stopped(self):
        with self.buffer.lock:
            return self.buffer.conn.execute("SELECT value FROM l1_response_settings WHERE name='stopped'").fetchone()[0] == "true"

    def ensure(self, row):
        if not row or row.get("state") != "done" or (row.get("analysis") or {}).get("decision") != "escalate": return None
        with self.lock:
            case = self.get(row["event_id"])
            if case: return case
            score = float(row["event"]["severity"])
            if row["analysis"].get("tier") == "guardrail": score = max(score, 9)
            for c in row["analysis"].get("correlation", []):
                if c.get("rule") == "malware_process_network" and c.get("verified_tool_source") is True: score = max(score, 9)
                elif c.get("rule") == "repeated_login_failures": score = max(score, 7)
            severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
            window = WINDOWS[severity]
            try:
                created = datetime.fromisoformat(row["analysis"].get("completed_at") or row["event"]["received_at"]).timestamp()
            except (ValueError, TypeError): created = self.clock()
            case = {"event_id": row["event_id"], "severity": severity, "window": window,
                    "deadline": created + window if window is not None else None,
                    "state": "pending", "mode": "review", "deferred": False,
                    "note": "Low severity has no automatic deadline. Operator review remains available." if window is None else "Review required. Deadline expiry marks this case overdue; it does not authorize containment.",
                    "simulation": self.simulation}
            self.save(case, "l1_review_created")
            return case

    def enrich(self, row):
        if not row: return row
        row["response_case"] = self.ensure(row)
        row["response_stopped"] = self.stopped()
        row["response_workflow_error"] = self.error
        if row.get("analysis"):
            row["analysis"]["guidance"] = row["analysis"].get("guidance") or guidance(row["event"], row["analysis"])
        if self.protection:
            row["protection_proposal"] = self.protection.proposal(row)
            row["protection_actions"] = self.protection.actions(row["event_id"])
        correlations = (row.get("analysis") or {}).get("correlation", [])
        eligible_rule = any(c.get("rule") == "repeated_login_failures" or
                            (c.get("rule") == "malware_process_network" and c.get("verified_tool_source") is True) for c in correlations)
        candidate = row.get("protection_proposal") if not self.simulation else next((a for a in (row.get("analysis") or {}).get("responses", []) if a.get("kind") == "block_ip"), None)
        try:
            row["response_schedule_available"] = bool(eligible_rule and candidate and ipaddress.ip_address(candidate["target"]))
        except ValueError:
            row["response_schedule_available"] = False
        return row

    def control(self, event_id, command, actor, reason="", protected=None):
        if not isinstance(event_id, str) or len(event_id) > 128 or not isinstance(command, str) or not isinstance(reason, str):
            raise ValueError("invalid response request")
        with self.lock:
            if command in {"stop", "resume"}:
                with self.buffer.lock, self.buffer.conn:
                    self.buffer.conn.execute("UPDATE l1_response_settings SET value=? WHERE name='stopped'", ("true" if command == "stop" else "false",))
                # Stopping cancels existing enrollments. Resume never re-arms them.
                if command == "stop":
                    for case in self.cases():
                        if case["state"] == "pending" and case["mode"] == "automatic":
                            case.update(mode="review", note="Timed action cancelled by the emergency stop; existing blocks retain their expiry and Undo.")
                            self.save(case, "l1_schedule_cancelled", actor)
                self.audit.record_iam(actor, "l1_" + command, "")
                return {"stopped": self.stopped()}
            row = self.buffer.detail(event_id)
            case = self.ensure(row)
            if not case: raise ValueError("completed escalation required")
            if command == "undo":
                if case["state"] not in {"executed", "needs_review", "executing"}: raise ValueError("no timed action to undo")
                if not self.simulation:
                    actions = self.protection.actions(event_id) if self.protection else []
                    active = next((a for a in actions if a["status"] in {"executed", "expiry_due", "pending", "failed", "cleanup_failed"}), None)
                    if not active: raise ValueError("inspect the action record; no block available to undo")
                    # Real dashboard Protection uses verified native removal.
                    self.protection.undo(active["id"], actor)
                case.update(state="undone", note="Simulated block undone." if self.simulation else "Native block removal verified. Interrupted connections cannot be restored.")
            elif case["state"] not in {"pending", "overdue"}:
                raise ValueError("this review is already closed")
            elif command in {"reviewed", "reject"}:
                if not reason.strip(): raise ValueError("record a reason")
                case.update(state="reviewed" if command == "reviewed" else "rejected", mode="review", note=reason[:1000])
            elif command == "defer":
                if case["state"] != "pending" or case["deferred"] or case["deadline"] is None or self.clock() >= case["deadline"]:
                    raise ValueError("only one extension before the deadline is permitted")
                if not reason.strip(): raise ValueError("record a reason")
                case.update(deadline=case["deadline"] + case["window"], deferred=True, note=reason[:1000])
            elif command == "schedule":
                if self.stopped(): raise ValueError("timed actions are stopped")
                if case["state"] != "pending" or case["deadline"] is None or self.clock() >= case["deadline"]:
                    raise ValueError("a future severity deadline is required")
                proposal = self.protection.proposal(row) if self.protection else None
                rule = next((c["rule"] for c in row["analysis"].get("correlation", []) if c.get("rule") in RULES and
                             (c["rule"] != "malware_process_network" or c.get("verified_tool_source") is True)), None)
                if self.simulation:
                    # Demo enrollment never constructs a Protection or calls an OS adapter.
                    proposal = next((a for a in row["analysis"].get("responses", []) if a.get("kind") == "block_ip"), None)
                if not rule or not proposal: raise ValueError("no independently eligible timed IP-block proposal")
                target = str(ipaddress.ip_address(proposal["target"]))
                identity = [row["event"]["hostname"], row["event"].get("username", ""),
                            row["event"].get("process_id", ""), row["event"].get("process_name", ""),
                            row["event"].get("metadata", {}).get("process_guid", ""), rule, target]
                if any(c.get("identity") == identity and c["event_id"] != event_id for c in self.cases()):
                    raise ValueError("this incident already has a timed response review; repeated telemetry cannot re-arm it")
                if not self.simulation:
                    if not self.protection.verify: raise ValueError("native verification is required")
                    if not isinstance(protected, list) or not 1 <= len(protected) <= 128 or not all(isinstance(n, str) and len(n) <= 100 for n in protected): raise ValueError("protected service/management networks required")
                    scope = ContainmentScope([target + ("/128" if ":" in target else "/32")], protected)
                    if not scope.permits(target): raise ValueError("target is protected")
                case.update(mode="automatic", target=target, rule=rule, identity=identity, protected=protected or [], actor=actor,
                            note="Explicitly pre-authorized temporary peer block at the deadline, only if fresh evidence and native checks still pass.")
            else:
                raise ValueError("unknown response command")
            self.save(case, "l1_" + command, actor)
            return case

    def fresh_evidence(self, case):
        """Rebuild the enrolled correlation; old model prose never suffices."""
        from .correlation import correlate
        from .schema import SecurityEvent
        original = self.buffer.detail(case["event_id"])
        if not original: return None
        for candidate in self.buffer.query({"scope": "live", "host": original["event"]["hostname"]}, limit=100):
            event = candidate["event"]
            try:
                age = self.clock() - datetime.fromisoformat(event["timestamp"]).timestamp()
                if not 0 <= age <= 30: continue
            except (TypeError, ValueError): continue
            # Bind to the original account/process identity, not just a shared peer.
            fields = ("username", "user_id") if case["rule"] == "repeated_login_failures" else ("process_id", "process_name")
            if any(event.get(k) != original["event"].get(k) for k in fields): continue
            if case["rule"] == "malware_process_network":
                if not event.get("process_name") or not event.get("metadata", {}).get("process_guid"): continue
                if event["metadata"]["process_guid"] != original["event"].get("metadata", {}).get("process_guid"): continue
            if candidate["connector"] not in {"windows", "sysmon"} or set(event.get("tags", [])) & {"demo", "replay"}: continue
            obj = SecurityEvent(**event)
            previous = [e for e in self.buffer.recent(obj, scope="live") if e.metadata.get("_collector_origin") in {"windows", "sysmon", "defender"}]
            correlations = correlate(obj, previous)
            eligible = [c for c in correlations if c.get("rule") == case["rule"] and
                        (case["rule"] != "malware_process_network" or c.get("verified_tool_source") is True)]
            if not eligible: continue
            checked = {**candidate, "analysis": {"decision": "escalate", "correlation": eligible}}
            proposal = self.protection.proposal(checked)
            if proposal and proposal["target"] == case["target"]: return checked
        return None

    def tick(self):
        with self.lock:
            with self.buffer.lock:
                event_ids = [r[0] for r in self.buffer.conn.execute("SELECT event_id FROM telemetry WHERE state='done' AND decision='escalate' "
                    "AND NOT EXISTS (SELECT 1 FROM l1_response_seen s WHERE s.event_id=telemetry.event_id) ORDER BY priority DESC,id LIMIT 100")]
            # Seen identities, rather than an insertion cursor, preserve cases
            # completed out of order by the priority worker. Slow old events
            # cannot hold newly completed urgent findings out of the scheduler.
            for event_id in event_ids:
                self.ensure(self.buffer.detail(event_id))
                with self.buffer.lock, self.buffer.conn:
                    self.buffer.conn.execute("INSERT OR IGNORE INTO l1_response_seen VALUES (?)", (event_id,))
            for case in self.cases(["pending"]):
                if case["state"] != "pending" or case["deadline"] is None or self.clock() < case["deadline"]: continue
                if case["mode"] != "automatic" or self.stopped():
                    case.update(state="overdue", note="Review deadline passed. No automatic action was authorized or executed.")
                    self.save(case, "l1_overdue"); continue
                case.update(state="executing")
                self.save(case, "l1_execution_started")
                try:
                    if not self.simulation:
                        checked = self.fresh_evidence(case)
                        if not checked: raise ValueError("Fresh, independently supported evidence unavailable; human review required.")
                        scope = ContainmentScope([case["target"] + ("/128" if ":" in case["target"] else "/32")], case["protected"])
                        if not scope.permits(case["target"]): raise ValueError("Target no longer permitted.")
                        # Bind execution to this review's original event ID. A new
                        # collector row only refreshes evidence, never re-arms it.
                        checked["event_id"] = case["event_id"]
                        original = self.buffer.detail(case["event_id"])
                        # Revalidate the original proposal as well as the fresh evidence.
                        if not original or self.protection.proposal(original) != self.protection.proposal(checked):
                            raise ValueError("Original proposal no longer matches fresh evidence.")
                        executor = Protection(self.buffer, self.audit, self.protection.firewall, scope=scope, verify=True)
                        actions = executor.approve(case["event_id"], case["actor"], expected_target=case["target"], evidence_row=checked)
                        case["action_id"] = actions[0]["id"]
                    case.update(state="executed", expires_at=self.clock() + 300,
                                note="Simulated block only; device unchanged." if self.simulation else "Verified temporary peer block. Native expiry in five minutes; Undo is available.")
                    self.save(case, "l1_executed")
                except (ValueError, OSError, RuntimeError):
                    case.update(state="needs_review", note="Timed response could not pass fresh evidence, scope or native checks. Inspect the action record; no retry will run automatically.")
                    self.save(case, "l1_execution_needs_review")
            if self.protection and self.clock() - self._last_reconcile >= 10:
                self.protection.reconcile()
                self._last_reconcile = self.clock()
            for case in self.cases(["executed"]):
                if self.simulation and self.clock() >= case.get("expires_at", float("inf")):
                    case.update(state="expired", note="Simulated five-minute block expired. No device changes were made.")
                    self.save(case, "l1_expired")
                elif self.protection:
                    actions = self.protection.actions(case["event_id"])
                    action = next((a for a in actions if a["id"] == case.get("action_id")), actions[0] if actions else None)
                    if action and action["status"] in {"expired", "undone", "recovered"}:
                        case.update(state="expired" if action["status"] == "expired" else "undone", note="Native block removal verified; inspect the action record. Interrupted sessions cannot be restored.")
                        self.save(case, "l1_block_removed")

    def run(self):
        while not self.stop.is_set():
            try:
                self.tick()
                self.error = ""
            except Exception:
                self.error = "Response scheduler needs attention. Timed actions may be delayed; review alerts manually."
            self.stop.wait(1)

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(45)
            if self.thread.is_alive(): raise RuntimeError("response executor is still stopping")
