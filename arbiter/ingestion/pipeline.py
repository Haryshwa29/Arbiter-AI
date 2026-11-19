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
        try:
            job = self.prepare(row)
            self.finish(job, self.analyze(job))
        except Exception:
            self.buffer.fail(row["id"])
        return True

    def prepare(self, row):
        started = time.monotonic()
        backend = getattr(self.engine.llm, "name", "unrecorded")
        model = getattr(self.engine.llm, "model", "")
        backend = backend if isinstance(backend, str) else "unrecorded"
        model = model if isinstance(model, str) else ""
        event = SecurityEvent(**safe_json(row["payload"]))
        from .evidence import own_log_query
        own_query = own_log_query(event, row["connector"])
        self.buffer.asset(event)
        correlations = correlate(event, self.buffer.recent(event, scope=None if self.simulation else "live",
            sources=("defender", "suricata", "guardduty", "wazuh") if own_query else None,
            review_pending=getattr(self, 'workflow', None) is not None))
        related = list(dict.fromkeys(eid for c in correlations for eid in c["events"]))
        if correlations:
            event.metadata["correlation"] = correlations
            event.severity = max(event.severity, max(c["severity"] for c in correlations))
            event.message += " | Correlation: " + "; ".join(c["reason"] for c in correlations)
        return dict(row=row, event=event, started=started, own_query=own_query,
                    backend=backend, model=model, related=related, correlations=correlations)

    def analyze(self, job):
        row, event = job['row'], job['event']
        backend, model, own_query = job['backend'], job['model'], job['own_query']
        # A crash after writing an audit row can leave a pending event.
        # Reuse its completed verdict rather than ask the model twice.
        existing = self.audit.verdict_for_event(event.event_id)
        if existing:
            analysis = {k: existing[k] for k in ("decision", "tier", "score", "rationale", "evidence")}
            detail = safe_json(existing.get("detail") or "{}")
            reasoning = detail.get("fields", {}).get("_analysis_backend", {})
            analysis['final_guardrail']=detail.get('fields',{}).get('_final_guardrail',{})
            analysis['context_signature']=detail.get('fields',{}).get('_context_signature','')
            analysis["backend"] = reasoning.get("backend", "unrecorded") if analysis["tier"] == "llm" else "deterministic"
            analysis["model"] = reasoning.get("model", "")
        else:
            legacy = event.to_event()
            from ..learned_patterns import pattern_key
            key=pattern_key(event,row['connector'],self.engine.memory,model,self.simulation) if backend=='ollama' else None
            job['learned_l1_key']=key
            if not own_query: legacy.fields["asset_context"] = self.buffer.asset_summary(event)
            from .evidence import process_context, own_log_query
            if own_query: legacy.fields["_collector_activity"] = True
            context = process_context(event, legacy, self.engine, row["connector"])
            if context: legacy.fields["_context_signature"] = context
            legacy.fields["_analysis_backend"] = {"backend": backend, "model": model}
            verdict = self.engine.triage(legacy,learned_key=key) if key else self.engine.triage(legacy)
            legacy.fields['_final_guardrail']=getattr(verdict,'final_guardrail',{})
            self.audit.record_verdict(legacy, verdict)
            analysis = safe_json(verdict.to_json())
            analysis["recommended_steps"] = getattr(verdict, "recommended_steps", [])
            analysis['context_signature']=legacy.fields.get('_context_signature','')
            analysis['final_guardrail']=getattr(verdict,'final_guardrail',{})
            analysis['model_confidence']=getattr(verdict,'model_confidence',0)
            analysis["backend"] = backend if analysis["tier"] == "llm" else "deterministic"
            analysis["model"] = model if analysis["backend"] in {"ollama", "ollama-cloud"} else ""
        if analysis["tier"] == "llm" and analysis["rationale"].startswith("LLM tier failed ("):
            analysis["backend"] = "policy-fallback"
        if backend == "rules-only" and analysis["tier"] == "llm":
            analysis["backend"] = "rules-only-policy"
        analysis["kind"] = "alert" if analysis["decision"] == "escalate" else "observation"
        analysis['correlation'] = job['correlations']
        return analysis

    def finish(self, job, analysis):
        row, event, started = job['row'], job['event'], job['started']
        related, correlations = job['related'], job['correlations']
        key=job.get('learned_l1_key')
        if key and analysis['decision']=='suppress' and analysis['tier']=='llm' and analysis.get('model_confidence',0)>=.9:
            self.engine.memory.learn_pattern('l1',key,event.to_event(),job['model'],analysis['rationale'])
        elif key and analysis['decision']=='escalate':
            self.engine.memory.revoke_pattern('l1',key)
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
        from .recommendations import guidance
        analysis["guidance"] = guidance(event.__dict__, analysis)
        if related and analysis["decision"] == "escalate":
            analysis["incident_id"] = self.buffer.incident(event, related, correlations[0]["rule"])
        self.buffer.finish(row["id"], analysis, related, (time.monotonic() - started) * 1000)

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=130)  # existing model timeout is 120s
            if self.thread.is_alive():
                raise RuntimeError("analysis worker is still stopping")
