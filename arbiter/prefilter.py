"""Tier 1: the cheap pre-filter.

Runs on every event; the LLM only sees what lands in the ambiguous band.
Score = source severity × asset criticality × history modifier, mapped
back to 0–10.

Asymmetric error costs (CONCEPT.md trust model) are baked in:
- Suppression at this tier requires BOTH a low score AND strong history
  (a signature seen many times and always benign). Low score alone punts
  to the LLM.
- Escalation needs only a high score. Missing a real breach is fatal;
  a few extra escalations are not.
"""

from __future__ import annotations

from dataclasses import dataclass

from .memory import Memory
from .schema import Decision, Event

# Tunable thresholds — the cheap/ambiguous boundary is an open question
# (CONCEPT.md); start conservative, let shadow-mode data move them.
ESCALATE_AT = 7.0          # score >= this → escalate immediately
SUPPRESS_AT = 3.0          # score < this MAY suppress, if history agrees
MIN_HISTORY_TO_SUPPRESS = 5    # signature must be seen at least this often
MAX_FP_ESCALATIONS = 0         # ...and never previously escalated


@dataclass
class PrefilterResult:
    decision: Decision
    score: float
    rationale: str


def score_event(event: Event, memory: Memory) -> float:
    criticality = memory.asset_criticality(event.host)
    history = memory.history(event.signature)

    # History modifier: signatures that always turned out benign decay
    # toward 0.5; the boost applies ONLY to overruled suppressions (missed
    # attacks). An overruled escalation is a false alarm — the human said
    # benign — and feeds the decay via false_positive_rate instead.
    modifier = 1.0
    if history.total >= MIN_HISTORY_TO_SUPPRESS:
        modifier -= 0.5 * history.false_positive_rate
    modifier += 0.3 * min(history.overruled, 3)

    raw = event.severity * criticality * modifier
    return max(0.0, min(10.0, raw))


def prefilter(event: Event, memory: Memory) -> PrefilterResult:
    score = score_event(event, memory)
    history = memory.history(event.signature)
    criticality = memory.asset_criticality(event.host)

    if score >= ESCALATE_AT:
        return PrefilterResult(
            Decision.ESCALATE, score,
            f"score {score:.1f} >= {ESCALATE_AT} "
            f"(severity {event.severity}, asset criticality {criticality})",
        )

    if (
        score < SUPPRESS_AT
        and history.total >= MIN_HISTORY_TO_SUPPRESS
        # Standing escalations block cheap suppression — but escalations a
        # human already overruled as false alarms don't count against it.
        and history.escalated - history.false_alarms <= MAX_FP_ESCALATIONS
        and history.overruled == 0
    ):
        return PrefilterResult(
            Decision.SUPPRESS, score,
            f"score {score:.1f} < {SUPPRESS_AT}; signature seen "
            f"{history.total}x, always benign, never overruled",
        )

    return PrefilterResult(
        Decision.AMBIGUOUS, score,
        f"score {score:.1f} in ambiguous band or insufficient history "
        f"({history.total} prior verdicts) — deferring to LLM tier",
    )
