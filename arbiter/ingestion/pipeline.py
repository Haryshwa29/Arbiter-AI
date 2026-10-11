"""One analysis worker for live, API, file and replay telemetry."""
from __future__ import annotations

import threading
import time

from .correlation import correlate
from .schema import SecurityEvent, safe_json


class Pipeline:
    def __init__(self, buffer, engine, audit):
        self.buffer, self.engine, self.audit = buffer, engine, audit
        self.stop_event = threading.Event()
        self.thread = None
        self._last_prune = 0.0
        self.simulation = False
        self.last_activity = time.monotonic()

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop_event.is_set():
            self.last_activity = time.monotonic()
            if time.monotonic() - self._last_prune > 3600:
                self.buffer.prune()
                self._last_prune = time.monotonic()
            if not self.process_one():
                self.stop_event.wait(.2)

    def process_one(self):
        row = self.buffer.claim()
        if not row:
            return False
        started = time.monotonic()
        try:
            event = SecurityEvent(**safe_json(row["payload"]))
            self.buffer.asset(event)
            correlations = correlate(event, self.buffer.recent(event, scope=None if self.simulation else "live"))
            related = list(dict.fromkeys(eid for c in correlations for eid in c["events"]))
            if correlations:
                event.metadata["correlation"] = correlations
                event.severity = max(event.severity, max(c["severity"] for c in correlations))
                event.message += " | Correlation: " + "; ".join(c["reason"] for c in correlations)
            # A crash after writing an audit row can leave a pending event.
            # Reuse its completed verdict rather than ask the model twice.
            existing = self.audit.verdict_for_event(event.event_id)
            if existing:
                analysis = {k: existing[k] for k in ("decision", "tier", "score", "rationale", "evidence")}
            else:
                legacy = event.to_event()
                legacy.fields["asset_context"] = self.buffer.asset_summary(event)
                verdict = self.engine.triage(legacy)
                self.audit.record_verdict(legacy, verdict)
                analysis = safe_json(verdict.to_json())
            analysis["kind"] = "alert" if analysis["decision"] == "escalate" else "observation"
            # Planning is pure. Neither simulated nor live ingestion executes commands.
            from ..respond import plan
            from ..schema import Verdict, Decision, Tier
            decision = Verdict(event.event_id, event.to_event().signature,
                Decision(analysis["decision"]), analysis["score"], Tier(analysis["tier"]),
                analysis["rationale"], analysis["evidence"])
            analysis["responses"] = [{"status": "simulated" if self.simulation else "recommended",
                "kind": action.kind.value, "target": action.target, "reason": action.reason,
                "executed": False} for action in plan(event.to_event(), decision)]
            analysis["correlation"] = correlations
            if related and analysis["decision"] == "escalate":
                analysis["incident_id"] = self.buffer.incident(event, related, correlations[0]["rule"])
            self.buffer.finish(row["id"], analysis, related, (time.monotonic() - started) * 1000)
        except Exception:
            self.buffer.fail(row["id"])
        return True

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=130)  # existing model timeout is 120s
            if self.thread.is_alive():
                raise RuntimeError("analysis worker is still stopping")
