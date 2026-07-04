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

    @property
    def correct(self) -> bool:
        return self.actual == self.case.expected

    @property
    def missed_attack(self) -> bool:
        """The one failure mode the trust model calls fatal."""
        return (self.case.expected is Decision.ESCALATE
                and self.actual is Decision.SUPPRESS)


def run_case(backend: LLMBackend, case: EvalCase) -> CaseResult:
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
    return CaseResult(case, decision, v.confidence, time.monotonic() - start)


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
        print(f"\n=== {self.backend_name} - {self.total} labeled cases ===")
        print(f"overall accuracy: {self.accuracy:.0%}")

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

        print("\nby category:")
        for cat, rs in sorted(self.by_category().items()):
            correct = sum(r.correct for r in rs)
            print(f"  {cat:32} {correct}/{len(rs)}")

        avg_latency = (sum(r.latency_s for r in self.results) / self.total
                       if self.total else 0.0)
        print(f"\navg latency/case: {avg_latency:.2f}s")


def evaluate(backend: LLMBackend, cases: list[EvalCase]) -> EvalReport:
    report = EvalReport(backend_name=backend.name)
    for case in cases:
        report.results.append(run_case(backend, case))
    return report
