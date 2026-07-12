"""Tier 2: LLM triage for ambiguous alerts.

Pluggable backends behind one interface so the brain doesn't care what's
serving inference. Ships with:

- OllamaBackend — talks to a local Ollama server (open-weights model on
  the customer's own hardware; nothing leaves the network).
- MockBackend — deterministic heuristic stand-in so the pipeline runs
  end-to-end without a model. Also useful for tests.

The LLM must answer in strict JSON: decision, confidence, evidence,
rationale. Asymmetric error costs again: a low-confidence SUPPRESS from
the model is upgraded to ESCALATE by the orchestrator.
"""

from __future__ import annotations

import json
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .schema import Decision, Event

SYSTEM_PROMPT = """You are Arbiter, a security analyst triaging one alert for a small company with no security team. You will receive the event, the asset's criticality, this alert signature's history, and known environment facts.

Respond ONLY with JSON:
{"decision": "escalate"|"suppress", "confidence": 0.0-1.0, "evidence": "<what an analyst should look at first>", "rationale": "<why, in one or two sentences>"}

Rules:
- Missing a real intrusion is far worse than a false escalation. If unsure, escalate.
- Use environment facts to explain benign anomalies, but never let a fact excuse credential abuse or lateral movement.
- A fact covers ONLY the specific behavior it names (user, path, process, event class, time). Some facts carry a code-verified scope annotation: a fact marked [SCOPE MISMATCH ...] does NOT apply to this event and must never justify suppression — activity merely adjacent to a known-benign pattern (right host, wrong user/path/action) is itself suspicious.
- Evidence must be specific: name the host, user, IP, or pattern to check."""


@dataclass
class LLMVerdict:
    decision: Decision
    confidence: float
    evidence: str
    rationale: str


def build_prompt(event: Event, criticality: float, history_summary: str,
                 facts: list[str]) -> str:
    return json.dumps({
        "event": {
            "source": event.source, "host": event.host,
            "type": event.event_type, "severity": event.severity,
            "message": event.message, "fields": event.fields,
            "timestamp": event.timestamp,
        },
        "asset_criticality": criticality,
        "signature_history": history_summary,
        "environment_facts": facts,
    }, indent=2)


def parse_response(text: str) -> LLMVerdict:
    # Models wrap JSON in prose/fences more often than not; dig it out.
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError(f"no JSON in LLM response: {text[:200]}")
    data = json.loads(text[start:end + 1])
    decision = Decision(data["decision"])
    if decision is Decision.AMBIGUOUS:
        raise ValueError("LLM may not answer 'ambiguous'")
    return LLMVerdict(
        decision=decision,
        confidence=max(0.0, min(1.0, float(data.get("confidence", 0.5)))),
        evidence=str(data.get("evidence", "")),
        rationale=str(data.get("rationale", "")),
    )


class LLMBackend(ABC):
    name: str = "llm"

    @abstractmethod
    def triage(self, event: Event, criticality: float, history_summary: str,
               facts: list[str]) -> LLMVerdict: ...


class OllamaBackend(LLMBackend):
    """Local inference via Ollama (https://ollama.com). Zero data egress."""

    name = "ollama"

    def __init__(self, model: str = "llama3.1:8b",
                 url: str = "http://localhost:11434") -> None:
        self.model = model
        self.url = url.rstrip("/")

    def triage(self, event: Event, criticality: float, history_summary: str,
               facts: list[str]) -> LLMVerdict:
        payload = json.dumps({
            "model": self.model,
            "system": SYSTEM_PROMPT,
            "prompt": build_prompt(event, criticality, history_summary, facts),
            "stream": False,
            "format": "json",
            # Hybrid-reasoning models (e.g. Qwen3-class) otherwise dump the
            # whole answer into a "thinking" field and leave "response" empty
            # when format=json is forced, which breaks parsing. Triage is a
            # cheap structured call, not a place for an open-ended reasoning
            # budget anyway.
            "think": False,
            "options": {"temperature": 0.1},
        }).encode()
        req = urllib.request.Request(
            f"{self.url}/api/generate", data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read())
        return parse_response(body["response"])


class MockBackend(LLMBackend):
    """Deterministic stand-in: keyword heuristics over the message.
    Exists so the slice runs end-to-end anywhere; replace with Ollama
    for real evaluation of 'minimum viable local model'.
    """

    name = "mock"

    _HOT = ("privilege", "sudo", "root", "reverse shell", "curl | sh",
            "mimikatz", "new user", "crontab", "authorized_keys",
            "disabled", "exfil", "base64 -d")

    @staticmethod
    def _fact_explains(fact: str, msg: str) -> bool:
        # Honor the code-side scope verdict (facts.py): a fact the scope
        # checker ruled out can never explain the event, whatever the word
        # overlap says.
        if "[SCOPE MISMATCH" in fact:
            return False
        if "[scope verified" in fact:
            return True
        fact = fact.split(" [scope", 1)[0]  # strip remaining annotations
        fact_words = {w for w in fact.lower().split() if len(w) >= 4}
        msg_words = {w for w in msg.lower().split() if len(w) >= 4}
        return len(fact_words & msg_words) >= 2

    def triage(self, event: Event, criticality: float, history_summary: str,
               facts: list[str]) -> LLMVerdict:
        msg = event.message.lower()
        hits = [k for k in self._HOT if k in msg]
        explained = any(self._fact_explains(f, msg) for f in facts)
        if hits:
            return LLMVerdict(
                Decision.ESCALATE, 0.85,
                f"Inspect {event.host}: matched indicators {hits} in {event.source} "
                f"event '{event.event_type}'. Check user/IP in fields: {event.fields}.",
                f"Message contains high-risk indicators {hits}.",
            )
        if explained:
            return LLMVerdict(
                Decision.SUPPRESS, 0.75,
                "",
                "Anomaly matches a known environment fact for this scope.",
            )
        # Default lean: escalate at modest confidence (asymmetric costs).
        return LLMVerdict(
            Decision.ESCALATE, 0.55,
            f"Review {event.source}/{event.event_type} on {event.host}; "
            f"no history to justify suppression.",
            "No strong benign explanation available; erring toward escalation.",
        )


def get_backend(name: str, model: str = "llama3.1:8b") -> LLMBackend:
    if name == "ollama":
        return OllamaBackend(model=model)
    if name == "mock":
        return MockBackend()
    raise ValueError(f"unknown backend: {name}")
