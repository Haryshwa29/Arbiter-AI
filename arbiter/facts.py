"""Scoped environment facts — the fact-overreach fix.

The model gauntlet (2026-07-12) showed a 4B model treats a free-text fact
as a host-level benediction: "backups run at 02:00" got applied to a manual
pg_dump written to a personal home directory, and a container-churn fact
bled into a judgment about OAuth token reuse. Both misses share one root
cause: the model has nothing to check a fact's *scope* against.

Per the design stance (detection = code, model = analyst), scope checking
is code, not model behavior. A fact may carry optional constraints —
user, path, process, event_types, time window — and before the LLM sees
it, each constraint is checked against the event:

- any constraint that *violates* -> the fact is rendered with a
  [SCOPE MISMATCH] annotation naming exactly what didn't line up;
- all populated constraints *match* -> [scope verified];
- constraints present but not decidable from the event -> the unverified
  dimensions are named, and judgment stays with the model;
- no constraints -> the fact renders as plain text (legacy behavior).

An out-of-scope fact is never hidden (transparency, invariant #2): the
model should see that someone acted *adjacent* to a maintenance window —
that adjacency is itself signal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .schema import Event

_USER_KEYS = ("user", "username", "account", "uid_name", "actor")
_PROC_KEYS = ("process", "exe", "command", "cmd")
_PATH_RE = re.compile(r"(?:^|[\s'\"=:])((?:/[\w.\-]+)+/?)")
_TIME_RE = re.compile(r"\bat (\d{1,2}):(\d{2})\b")

MATCH, VIOLATE, UNKNOWN = "match", "violate", "unknown"


@dataclass(frozen=True)
class ScopedFact:
    """An admin-curated environment fact plus the scope it actually covers.

    Every constraint is optional; an unconstrained fact behaves exactly
    like the free-text facts it replaces.
    """

    text: str
    host: str = "*"                      # memory-layer scope (host/source/*)
    user: str = ""                       # covers only this acting user
    path: str = ""                       # covers only paths under this prefix
    process: str = ""                    # covers only this tool/process
    event_types: tuple[str, ...] = ()    # covers only these event classes
    window: str = ""                     # covers only "HH:MM-HH:MM" (may wrap)

    @classmethod
    def from_obj(cls, obj: "str | dict | ScopedFact") -> "ScopedFact":
        if isinstance(obj, ScopedFact):
            return obj
        if isinstance(obj, str):
            return cls(text=obj)
        return cls(
            text=obj["text"],
            host=obj.get("host", "*"),
            user=obj.get("user", ""),
            path=obj.get("path", ""),
            process=obj.get("process", ""),
            event_types=tuple(obj.get("event_types", ()) or ()),
            window=obj.get("window", ""),
        )

    @property
    def scoped(self) -> bool:
        return bool(self.user or self.path or self.process
                    or self.event_types or self.window)


@dataclass
class ScopeResult:
    status: str                          # verified | mismatch | partial | unscoped
    violations: list[str] = field(default_factory=list)
    unverified: list[str] = field(default_factory=list)


# --- per-constraint checks (3-state: match / violate / unknown) -------------

def _check_user(fact: ScopedFact, ev: Event) -> tuple[str, str]:
    want = fact.user.lower()
    for key in _USER_KEYS:
        got = str(ev.fields.get(key, "")).strip().lower()
        if got:
            if got == want:
                return MATCH, ""
            return VIOLATE, f"event user '{got}' is not fact user '{fact.user}'"
    # No structured user; fall back to a word-boundary search in the message.
    if re.search(rf"\b{re.escape(want)}\b", ev.message.lower()):
        return MATCH, ""
    return UNKNOWN, "user"


def _check_path(fact: ScopedFact, ev: Event) -> tuple[str, str]:
    prefix = fact.path.rstrip("/")
    seen: list[str] = []
    for v in ev.fields.values():
        if isinstance(v, str) and v.startswith("/"):
            seen.append(v)
    seen += [m.group(1) for m in _PATH_RE.finditer(ev.message)]
    if not seen:
        return UNKNOWN, "path"
    for p in seen:
        if p == prefix or p.startswith(prefix + "/"):
            return MATCH, ""
    return VIOLATE, (f"paths in event ({', '.join(sorted(set(seen))[:3])}) "
                     f"are outside fact scope '{fact.path}'")


def _check_process(fact: ScopedFact, ev: Event) -> tuple[str, str]:
    want = fact.process.lower()
    named = [str(ev.fields.get(k, "")).strip().lower()
             for k in _PROC_KEYS if ev.fields.get(k)]
    if named:
        if any(want in n for n in named):
            return MATCH, ""
        return VIOLATE, (f"event process '{named[0]}' is not fact process "
                         f"'{fact.process}'")
    if want in ev.message.lower():
        return MATCH, ""
    return UNKNOWN, "process"


def _check_event_types(fact: ScopedFact, ev: Event) -> tuple[str, str]:
    # Always decidable: the event declares its own type.
    if ev.event_type in fact.event_types:
        return MATCH, ""
    return VIOLATE, (f"event type '{ev.event_type}' is not covered "
                     f"(fact covers: {', '.join(fact.event_types)})")


def _minutes(hh: str, mm: str) -> int:
    return int(hh) % 24 * 60 + int(mm)


def _event_minutes(ev: Event) -> int | None:
    # Prefer the time the log line itself claims ("at 02:05"); eval events
    # and replayed batches carry ingest timestamps that say nothing about
    # when the activity happened.
    m = _TIME_RE.search(ev.message)
    if m:
        return _minutes(m.group(1), m.group(2))
    m = re.search(r"T(\d{2}):(\d{2})", ev.timestamp)
    if m:
        return _minutes(m.group(1), m.group(2))
    return None


def _check_window(fact: ScopedFact, ev: Event) -> tuple[str, str]:
    m = re.fullmatch(r"(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})", fact.window)
    if not m:
        return UNKNOWN, "window"
    start, end = _minutes(m.group(1), m.group(2)), _minutes(m.group(3), m.group(4))
    at = _event_minutes(ev)
    if at is None:
        return UNKNOWN, "window"
    inside = (start <= at <= end) if start <= end else (at >= start or at <= end)
    if inside:
        return MATCH, ""
    return VIOLATE, (f"event time {at // 60:02d}:{at % 60:02d} is outside "
                     f"fact window {fact.window}")


_CHECKS = (
    ("user", lambda f: f.user, _check_user),
    ("path", lambda f: f.path, _check_path),
    ("process", lambda f: f.process, _check_process),
    ("event_types", lambda f: f.event_types, _check_event_types),
    ("window", lambda f: f.window, _check_window),
)


def scope_check(fact: ScopedFact, event: Event) -> ScopeResult:
    """Check every populated constraint. Any violation wins: a fact that
    demonstrably doesn't cover the event must never read as if it might."""
    if not fact.scoped:
        return ScopeResult("unscoped")
    violations, unverified, matched = [], [], 0
    for _, populated, check in _CHECKS:
        if not populated(fact):
            continue
        state, detail = check(fact, event)
        if state is VIOLATE:
            violations.append(detail)
        elif state is UNKNOWN:
            unverified.append(detail)
        else:
            matched += 1
    if violations:
        return ScopeResult("mismatch", violations=violations)
    if not unverified and matched:
        return ScopeResult("verified")
    return ScopeResult("partial", unverified=unverified)


def render(fact: ScopedFact, event: Event) -> str:
    """The string the LLM sees: the fact plus what the code verified."""
    r = scope_check(fact, event)
    if r.status == "unscoped":
        return fact.text
    if r.status == "mismatch":
        return (f"{fact.text} [SCOPE MISMATCH — this fact does NOT cover "
                f"this event: {'; '.join(r.violations)}. It must not be "
                f"used to justify suppression.]")
    if r.status == "verified":
        return f"{fact.text} [scope verified: this event matches the fact's scope]"
    return (f"{fact.text} [scope not fully verifiable for this event "
            f"(undetermined: {', '.join(r.unverified)}); apply only if the "
            f"specific behavior matches]")


def render_all(facts: list[ScopedFact], event: Event) -> list[str]:
    return [render(f, event) for f in facts]


def texts(facts: list[ScopedFact]) -> list[str]:
    """Raw fact texts, for consumers that match on the admin's wording
    (e.g. guardrail fact_downgrade corroboration)."""
    return [f.text for f in facts]
