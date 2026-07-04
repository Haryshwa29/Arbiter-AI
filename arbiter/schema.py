"""Data contract between the collection layer and the triage brain.

This is the boundary a future Go agent must honor: collectors emit
`Event` as JSON (one per line / per message); the brain returns `Verdict`.
Keep this module dependency-free and stable — everything else can churn.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ESCALATE = "escalate"
    SUPPRESS = "suppress"
    AMBIGUOUS = "ambiguous"  # internal only: prefilter punts to the LLM tier


class Tier(str, Enum):
    PREFILTER = "prefilter"
    LLM = "llm"


@dataclass
class Event:
    """A normalized security event emitted by any collector.

    `severity` is the *source's* opinion, 0–10 (e.g. mapped from syslog
    priority or a Sigma rule level). Arbiter's own scoring layers on top.
    """

    source: str                      # e.g. "sshd", "auditd", "cloudtrail"
    host: str                        # asset identifier the event occurred on
    event_type: str                  # e.g. "auth_failure", "process_exec"
    message: str                     # raw or lightly normalized log line
    severity: float = 5.0            # 0 (noise) – 10 (critical), per source
    timestamp: str = ""              # ISO-8601; filled at ingest if empty
    id: str = ""                     # filled at ingest if empty
    fields: dict[str, Any] = field(default_factory=dict)  # src_ip, user, ...

    def __post_init__(self) -> None:
        if not self.id:
            self.id = uuid.uuid4().hex[:12]
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        self.severity = max(0.0, min(10.0, float(self.severity)))

    # A stable signature groups "the same alert" across occurrences,
    # which is what historical verdicts are keyed on.
    @property
    def signature(self) -> str:
        return f"{self.source}:{self.event_type}:{self.host}"

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, line: str) -> "Event":
        data = json.loads(line)
        return cls(**data)


@dataclass
class Verdict:
    """Arbiter's decision on one event. Every verdict is auditable:
    escalations carry an evidence summary, suppressions carry a rationale.
    """

    event_id: str
    signature: str
    decision: Decision
    score: float                     # final triage score, 0–10
    tier: Tier                       # which tier decided
    rationale: str                   # why — mandatory for suppressions
    evidence: str = ""               # investigation summary for escalations
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_json(self) -> str:
        d = asdict(self)
        d["decision"] = self.decision.value
        d["tier"] = self.tier.value
        return json.dumps(d)
