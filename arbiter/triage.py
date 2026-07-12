"""The triage orchestrator: prefilter → (maybe) LLM → verdict → audit.

Shadow mode: verdicts are computed and logged but flagged shadow=true;
nothing is actually suppressed until Arbiter has earned trust.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .guardrails import fact_downgrade, guardrail_check
from .llm import LLMBackend
from .memory import Memory
from .prefilter import prefilter
from .schema import Decision, Event, Tier, Verdict

# LLM suppress below this confidence gets upgraded to escalate.
MIN_SUPPRESS_CONFIDENCE = 0.7


@dataclass
class TriageStats:
    total: int = 0
    prefilter_decided: int = 0
    llm_decided: int = 0
    guardrail_decided: int = 0
    guardrail_downgraded: int = 0
    escalated: int = 0
    suppressed: int = 0


class TriageEngine:
    def __init__(self, memory: Memory, llm: LLMBackend,
                 audit_path: str | Path = "audit.jsonl",
                 shadow: bool = True) -> None:
        self.memory = memory
        self.llm = llm
        self.audit_path = Path(audit_path)
        self.shadow = shadow
        self.stats = TriageStats()

    def triage(self, event: Event) -> Verdict:
        # Security guardrail, pre-LLM: non-suppressible signals escalate
        # immediately — no fact, score, or model verdict may silence them.
        # Sole exception: an admin-curated environment fact that names this
        # host AND the specific dangerous marker downgrades the rail to an
        # LLM decision (never a suppression by itself, never the prefilter's
        # call).
        hit = guardrail_check(event)
        downgraded = None
        if hit is not None:
            facts = self.memory.facts_for(event.host, event.source)
            fact = fact_downgrade(hit, event, facts)
            if fact is None:
                verdict = Verdict(
                    event_id=event.id, signature=event.signature,
                    decision=Decision.ESCALATE, score=10.0, tier=Tier.GUARDRAIL,
                    rationale=f"Security guardrail [{hit.code}]: {hit.reason}.",
                    evidence=f"Non-suppressible signal: {event.message}",
                )
                self.stats.guardrail_decided += 1
                self.stats.total += 1
                self.stats.escalated += 1
                self.memory.record_verdict(verdict)
                self._audit(event, verdict)
                return verdict
            downgraded = (hit, fact)
            self.stats.guardrail_downgraded += 1

        pre = prefilter(event, self.memory)

        if downgraded is not None:
            # Rail fired but a standing fact corroborates the exact pattern:
            # the decision belongs to the LLM tier, with the fact in context.
            verdict = self._llm_triage(event, pre.score, downgraded=downgraded)
            self.stats.llm_decided += 1
        elif pre.decision is not Decision.AMBIGUOUS:
            verdict = Verdict(
                event_id=event.id, signature=event.signature,
                decision=pre.decision, score=pre.score, tier=Tier.PREFILTER,
                rationale=pre.rationale,
                evidence=(f"Auto-escalated by prefilter: {event.message}"
                          if pre.decision is Decision.ESCALATE else ""),
            )
            self.stats.prefilter_decided += 1
        else:
            verdict = self._llm_triage(event, pre.score)
            self.stats.llm_decided += 1

        self.stats.total += 1
        if verdict.decision is Decision.ESCALATE:
            self.stats.escalated += 1
        else:
            self.stats.suppressed += 1

        self.memory.record_verdict(verdict)
        self._audit(event, verdict)
        return verdict

    def _llm_triage(self, event: Event, pre_score: float,
                    downgraded: tuple | None = None) -> Verdict:
        history = self.memory.history(event.signature)
        summary = (
            f"seen {history.total}x before: {history.suppressed} suppressed, "
            f"{history.escalated} escalated, {history.overruled} human-overruled"
            if history.total else "first occurrence of this signature"
        )
        facts = self.memory.facts_for(event.host, event.source)
        criticality = self.memory.asset_criticality(event.host)

        try:
            llm = self.llm.triage(event, criticality, summary, facts)
        except Exception as exc:  # LLM down/garbled → fail toward escalation
            return Verdict(
                event_id=event.id, signature=event.signature,
                decision=Decision.ESCALATE, score=pre_score, tier=Tier.LLM,
                rationale=f"LLM tier failed ({exc}); escalating by policy.",
                evidence=f"Untriaged event requires human review: {event.message}",
            )

        decision, rationale = llm.decision, llm.rationale
        if (decision is Decision.SUPPRESS
                and llm.confidence < MIN_SUPPRESS_CONFIDENCE):
            decision = Decision.ESCALATE
            rationale = (f"LLM suggested suppress at confidence "
                         f"{llm.confidence:.2f} < {MIN_SUPPRESS_CONFIDENCE}; "
                         f"upgraded to escalate. LLM said: {llm.rationale}")

        # Post-LLM guardrail veto (second half of the sandwich): a suppress
        # can never stand against a non-suppressible signal, whatever the
        # model concluded from the environment facts. A rail downgraded by a
        # corroborating fact does not veto — but any OTHER rail still does.
        if decision is Decision.SUPPRESS:
            hit = guardrail_check(event)
            if hit is not None and (downgraded is None
                                    or hit.name != downgraded[0].name):
                decision = Decision.ESCALATE
                rationale = (f"Security guardrail [{hit.code}] vetoed LLM "
                             f"suppress: {hit.reason}.")

        # Transparency (invariant #2): a downgraded rail is always visible in
        # the verdict, whichever way the model decided.
        if downgraded is not None:
            d_hit, d_fact = downgraded
            rationale = (f"[guardrail {d_hit.name} downgraded to LLM decision "
                         f"by standing fact: \"{d_fact}\"] {rationale}")

        return Verdict(
            event_id=event.id, signature=event.signature,
            decision=decision, score=pre_score, tier=Tier.LLM,
            rationale=rationale, evidence=llm.evidence,
        )

    def _audit(self, event: Event, verdict: Verdict) -> None:
        entry = json.loads(verdict.to_json())
        entry["shadow"] = self.shadow
        entry["event"] = {"source": event.source, "host": event.host,
                          "type": event.event_type, "message": event.message}
        with self.audit_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
