"""Labeled eval harness for the LLM tier.

CONCEPT.md's biggest open question is "minimum viable local model." This
harness answers it empirically: run a backend against hand-labeled cases
(event + context -> expected decision) and report against the metric that
actually matters per the trust model — missed attacks are fatal, false
escalations are cheap. Accuracy alone would hide that asymmetry.

Runs the LLM backend directly rather than through TriageEngine: the
prefilter is deterministic and already tuned by rules, so isolating the
backend call is what tells you whether a given model is good enough.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .guardrails import fact_downgrade, guardrail_check
from .llm import LLMBackend
from .schema import Decision, Event
from .triage import MIN_SUPPRESS_CONFIDENCE


@dataclass
class EvalCase:
    event: Event
    criticality: float
    history_summary: str
    facts: list[str]
    expected: Decision
    category: str
    notes: str = ""

    @classmethod
    def from_json(cls, line: str) -> "EvalCase":
        d = json.loads(line)
        return cls(
            event=Event(**d["event"]),
            criticality=d.get("criticality", 1.0),
            history_summary=d.get("history_summary",
                                  "first occurrence of this signature"),
            facts=d.get("facts", []),
            expected=Decision(d["expected"]),
            category=d["category"],
            notes=d.get("notes", ""),
        )


def load_cases(path: str | Path) -> list[EvalCase]:
    cases = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cases.append(EvalCase.from_json(line))
    return cases


@dataclass
class CaseResult:
    case: EvalCase
    actual: Decision
    confidence: float
    latency_s: float
    error: str = ""
    guardrail: str = ""      # name of the guardrail that decided, if any
    downgraded: str = ""     # rail downgraded to an LLM decision by a fact

    @property
    def correct(self) -> bool:
        return self.actual == self.case.expected

    @property
    def missed_attack(self) -> bool:
        """The one failure mode the trust model calls fatal."""
        return (self.case.expected is Decision.ESCALATE
                and self.actual is Decision.SUPPRESS)


def run_case(backend: LLMBackend, case: EvalCase,
             use_guardrails: bool = True) -> CaseResult:
    # Pre-LLM guardrail: a non-suppressible signal escalates without the
    # model — unless an admin-curated fact corroborates the exact pattern,
    # which downgrades the rail to an LLM decision.
    downgraded = None
    if use_guardrails:
        hit = guardrail_check(case.event)
        if hit is not None:
            if fact_downgrade(hit, case.event, case.facts) is None:
                return CaseResult(case, Decision.ESCALATE, 1.0, 0.0,
                                  guardrail=hit.code)
            downgraded = hit

    start = time.monotonic()
    try:
        v = backend.triage(case.event, case.criticality,
                           case.history_summary, case.facts)
    except Exception as exc:
        # Mirrors triage.py policy: a backend failure escalates, never
        # silently drops the event.
        return CaseResult(case, Decision.ESCALATE, 0.0,
                          time.monotonic() - start, error=str(exc))

    decision = v.decision
    if decision is Decision.SUPPRESS and v.confidence < MIN_SUPPRESS_CONFIDENCE:
        decision = Decision.ESCALATE
    # Post-LLM guardrail veto (defense in depth). A downgraded rail does not
    # veto, but any other rail still does.
    if use_guardrails and decision is Decision.SUPPRESS:
        hit = guardrail_check(case.event)
        if hit is not None and (downgraded is None
                                or hit.name != downgraded.name):
            return CaseResult(case, Decision.ESCALATE, v.confidence,
                              time.monotonic() - start, guardrail=hit.name)
    return CaseResult(case, decision, v.confidence, time.monotonic() - start,
                      downgraded=downgraded.name if downgraded else "")


@dataclass
class EvalReport:
    backend_name: str
    results: list[CaseResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def accuracy(self) -> float:
        return sum(r.correct for r in self.results) / self.total if self.total else 0.0

    @property
    def missed_attacks(self) -> list[CaseResult]:
        return [r for r in self.results if r.missed_attack]

    @property
    def false_escalations(self) -> list[CaseResult]:
        return [r for r in self.results
                if r.case.expected is Decision.SUPPRESS
                and r.actual is Decision.ESCALATE]

    @property
    def attacks_total(self) -> int:
        return sum(1 for r in self.results
                   if r.case.expected is Decision.ESCALATE)

    @property
    def caught(self) -> int:
        return self.attacks_total - len(self.missed_attacks)

    @property
    def recall(self) -> float:
        return self.caught / self.attacks_total if self.attacks_total else 1.0

    @property
    def precision(self) -> float:
        flagged = self.caught + len(self.false_escalations)
        return self.caught / flagged if flagged else 1.0

    @property
    def errors(self) -> list[CaseResult]:
        return [r for r in self.results if r.error]

    def by_category(self) -> dict[str, list[CaseResult]]:
        out: dict[str, list[CaseResult]] = {}
        for r in self.results:
            out.setdefault(r.case.category, []).append(r)
        return out

    def print_summary(self) -> None:
        n_expected_suppress = sum(1 for r in self.results
                                  if r.case.expected is Decision.SUPPRESS)
        by_guardrail = sum(1 for r in self.results if r.guardrail)
        print(f"\n=== {self.backend_name} - {self.total} labeled cases ===")
        print(f"recall {self.recall:.0%} ({self.caught}/{self.attacks_total} "
              f"attacks caught)   precision {self.precision:.0%}   "
              f"accuracy {self.accuracy:.0%}")
        if by_guardrail:
            print(f"of which {by_guardrail} decided by a security guardrail "
                  f"(non-suppressible)")
        n_down = sum(1 for r in self.results if r.downgraded)
        if n_down:
            print(f"guardrail downgraded to LLM decision by a standing fact: "
                  f"{n_down}")

        # Model-only view: the cases where the LLM was the deciding tier.
        # This is where "minimum viable local model" is actually measured —
        # guardrail-decided cases say nothing about the model.
        model_rs = [r for r in self.results if not r.guardrail]
        if model_rs and by_guardrail:
            m_atk = [r for r in model_rs
                     if r.case.expected is Decision.ESCALATE]
            m_ben = [r for r in model_rs
                     if r.case.expected is Decision.SUPPRESS]
            m_caught = sum(r.actual is Decision.ESCALATE for r in m_atk)
            m_muted = sum(r.actual is Decision.SUPPRESS for r in m_ben)
            m_lat = sum(r.latency_s for r in model_rs) / len(model_rs)
            print(f"\nMODEL-ONLY SUBSET ({len(model_rs)} cases the LLM "
                  f"decided): attacks {m_caught}/{len(m_atk)}   "
                  f"benign muted {m_muted}/{len(m_ben)}   "
                  f"avg latency {m_lat:.2f}s")
            for r in model_rs:
                if not r.correct:
                    d = f" [downgraded rail: {r.downgraded}]" if r.downgraded else ""
                    print(f"  WRONG: {r.case.category} expected "
                          f"{r.case.expected.value}, got {r.actual.value}"
                          f" (conf {r.confidence:.2f}){d}")

        print(f"\nMISSED ATTACKS (fatal per trust model): "
              f"{len(self.missed_attacks)}")
        for r in self.missed_attacks:
            print(f"  - {r.case.event.signature}  ({r.case.category})")
            print(f"    {r.case.notes}")

        print(f"\nfalse escalations (cheap, informs precision): "
              f"{len(self.false_escalations)}/{n_expected_suppress}")

        if self.errors:
            print(f"\nbackend errors (auto-escalated by policy): {len(self.errors)}")
            for r in self.errors:
                print(f"  - {r.case.event.signature}: {r.error}")

        print("\nby category (attacks caught / attacks · benign muted / benign):")
        for cat, rs in sorted(self.by_category().items()):
            atk = [r for r in rs if r.case.expected is Decision.ESCALATE]
            ben = [r for r in rs if r.case.expected is Decision.SUPPRESS]
            atk_ok = sum(r.actual is Decision.ESCALATE for r in atk)
            ben_ok = sum(r.actual is Decision.SUPPRESS for r in ben)
            flag = "" if atk_ok == len(atk) else "  <-- MISSED ATTACK"
            a = f"{atk_ok}/{len(atk)} atk" if atk else "—"
            b = f"{ben_ok}/{len(ben)} ben" if ben else "—"
            print(f"  {cat:26} {a:10} {b:10}{flag}")

        avg_latency = (sum(r.latency_s for r in self.results) / self.total
                       if self.total else 0.0)
        print(f"\navg latency/case: {avg_latency:.2f}s")

        gate = "PASS" if not self.missed_attacks else "FAIL"
        print(f"\nADVERSARIAL GATE: {gate}  "
              f"({len(self.missed_attacks)} disguised attacks slipped through; "
              f"must be 0)")


def evaluate(backend: LLMBackend, cases: list[EvalCase],
             use_guardrails: bool = True) -> EvalReport:
    report = EvalReport(backend_name=backend.name)
    for case in cases:
        report.results.append(run_case(backend, case, use_guardrails))
    return report


def print_variance(reports: list["EvalReport"]) -> None:
    """Cross-run stability: a sampling model that is right once may not be
    right five times. A case is flaky if runs disagree; a flaky ATTACK case
    is a latent missed attack and must be treated as a failure to fix."""
    n = len(reports)
    print(f"\n=== VARIANCE across {n} runs ===")
    print(f"recall  min {min(r.recall for r in reports):.0%}  "
          f"max {max(r.recall for r in reports):.0%}")
    print(f"precision  min {min(r.precision for r in reports):.0%}  "
          f"max {max(r.precision for r in reports):.0%}")
    total_missed = sum(len(r.missed_attacks) for r in reports)
    print(f"missed attacks summed over all runs: {total_missed}")

    flaky = 0
    for rs in zip(*(r.results for r in reports)):
        if len({x.actual for x in rs}) > 1:
            flaky += 1
            c = rs[0].case
            esc = sum(1 for x in rs if x.actual is Decision.ESCALATE)
            tag = ("LATENT MISS" if c.expected is Decision.ESCALATE
                   else "noisy benign")
            print(f"  FLAKY [{tag}] {c.category}: escalated {esc}/{n} runs "
                  f"(expected {c.expected.value})")
    if not flaky:
        print("flaky cases: none — decisions stable across runs")
