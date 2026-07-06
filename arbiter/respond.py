"""Response actuator: turns escalation verdicts into surgical actions.

Response logic stays OUT of the brain, mirroring the collection invariant:
`triage.py` never gains side effects. The CLI (or a future daemon) feeds
(event, verdict) pairs here after triage has decided.

Trust-model extension — blocking requires stronger justification than
alerting, because a false block is costlier than a false alert:

- Actions are always surgical: one IP, one account, one session, one
  process, one host. Never a service-wide switch.
- Actions are TTL-limited and reversible. Nothing is permanent.
- AUTO execution is reserved for deterministic prefilter-tier escalations
  whose catalog entry is marked auto-safe. LLM-tier escalations produce a
  RECOMMEND action for one-click human approval: the model proposes,
  rules dispose.
- Actions that could hurt the service itself (quarantining a confirmed
  crown-jewel host, edge-level DDoS mode) are never auto, regardless of tier.
- Dry-run is the default — the response analog of shadow mode. Every
  planned action lands in a response audit JSONL either way.

Deferred deliberately (agreed with Haryshwa): never-block allowlists
(office NAT / CGNAT protection) and scheduled auto-unlock for account
locks. Command strings are the intent contract a per-host agent will
execute; only dry-run is wired in this slice.
"""

from __future__ import annotations

import json
import subprocess  # noqa: S404 — enforcement path, off by default
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from .schema import Decision, Event, Tier, Verdict


class ActionKind(str, Enum):
    BLOCK_IP = "block_ip"
    KILL_SESSION = "kill_session"
    LOCK_ACCOUNT = "lock_account"
    KILL_PROCESS = "kill_process"
    QUARANTINE_HOST = "quarantine_host"
    ENGAGE_EDGE = "engage_edge"


class ActionMode(str, Enum):
    AUTO = "auto"            # executed without a human (unless dry-run)
    RECOMMEND = "recommend"  # prepared for one-click human approval


@dataclass
class ResponseAction:
    kind: ActionKind
    target: str              # the ONE thing acted on: IP, user, host, binary
    host: str                # where the action applies
    ttl_minutes: int | None  # None = held until human review, never silent-permanent
    command: str             # intent contract for the executing agent
    reason: str
    mode: ActionMode
    event_id: str
    signature: str
    executed: bool = False
    dry_run: bool = True
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_json(self) -> str:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["mode"] = self.mode.value
        return json.dumps(d)


# --- action catalog -------------------------------------------------------
# Each planner returns (kind, target, ttl_minutes, command, reason, auto_safe).
# auto_safe means: surgical, reversible, and cannot take the service down —
# eligible for AUTO only when the *prefilter* (deterministic tier) escalated.

BLOCK_TTL_MIN = 60


def _plan_bruteforce(ev: Event) -> list[tuple]:
    ip = ev.fields.get("src_ip")
    if not ip:
        return []
    return [(
        ActionKind.BLOCK_IP, ip, BLOCK_TTL_MIN,
        f"nft add element inet arbiter blocked {{ {ip} timeout {BLOCK_TTL_MIN}m }}",
        f"brute force from {ip}; drop that source for {BLOCK_TTL_MIN}m",
        True,
    )]


def _plan_geo(ev: Event) -> list[tuple]:
    user, ip = ev.fields.get("user"), ev.fields.get("src_ip")
    actions = []
    if user:
        actions.append((
            ActionKind.KILL_SESSION, user, None,
            f"loginctl terminate-user {user}",
            f"terminate active session for {user} after anomalous geo login",
            True,
        ))
        actions.append((
            ActionKind.LOCK_ACCOUNT, user, None,
            f"usermod --lock {user}",
            f"lock {user} pending re-authentication (held until human review)",
            True,
        ))
    if ip:
        actions.append((
            ActionKind.BLOCK_IP, ip, BLOCK_TTL_MIN,
            f"nft add element inet arbiter blocked {{ {ip} timeout {BLOCK_TTL_MIN}m }}",
            f"block anomalous login source {ip} for {BLOCK_TTL_MIN}m",
            True,
        ))
    return actions


def _plan_ransomware(ev: Event) -> list[tuple]:
    binary = ev.fields.get("binary")
    actions = []
    if binary:
        actions.append((
            ActionKind.KILL_PROCESS, binary, None,
            f"pkill -KILL -f {binary}",
            f"kill mass-rename process {binary} immediately",
            True,
        ))
    actions.append((
        ActionKind.QUARANTINE_HOST, ev.host, BLOCK_TTL_MIN,
        f"arbiter-agent quarantine {ev.host} --ttl {BLOCK_TTL_MIN}m",
        f"isolate {ev.host} from the network while files are inspected",
        True,
    ))
    return actions


def _plan_tampered_binary(ev: Event) -> list[tuple]:
    # Quarantining a crown-jewel host is a self-inflicted outage —
    # never auto, always a human call.
    return [(
        ActionKind.QUARANTINE_HOST, ev.host, None,
        f"arbiter-agent quarantine {ev.host}",
        f"tampered system binary on {ev.host}; isolation is a human call "
        f"(may take production down)",
        False,
    )]


def _plan_flood(ev: Event) -> list[tuple]:
    # The victim host cannot un-fill its own pipe; edge action is
    # customer-opt-in and never auto.
    return [(
        ActionKind.ENGAGE_EDGE, ev.host, None,
        "edge-provider enable under-attack mode",
        "volumetric flood: engage edge protection (rate limit / challenge)",
        False,
    )]


def _plan_conn_exhaustion(ev: Event) -> list[tuple]:
    return [(
        ActionKind.BLOCK_IP, "offending connection sources", BLOCK_TTL_MIN,
        "nft add rule inet arbiter input ct count over 20 counter drop",
        f"cap per-source connections on {ev.host} for {BLOCK_TTL_MIN}m",
        True,
    )]


def _plan_rogue_account(ev: Event) -> list[tuple]:
    user = ev.fields.get("user")
    if not user:
        return []
    return [(
        ActionKind.LOCK_ACCOUNT, user, None,
        f"usermod --lock {user}",
        f"lock suspicious new account {user} (held until human review)",
        True,
    )]


CATALOG = {
    "auth_bruteforce": _plan_bruteforce,
    "geo_impossible_travel": _plan_geo,
    "geo_anomaly_login": _plan_geo,
    "mass_file_rename": _plan_ransomware,
    "file_integrity": _plan_tampered_binary,
    "request_flood": _plan_flood,
    "syn_flood": _plan_flood,
    "conn_exhaustion": _plan_conn_exhaustion,
    "user_created": _plan_rogue_account,
}


def plan(event: Event, verdict: Verdict) -> list[ResponseAction]:
    """Suppressions and unknown event types get no action — alert-only."""
    if verdict.decision is not Decision.ESCALATE:
        return []
    planner = CATALOG.get(event.event_type)
    if planner is None:
        return []

    actions = []
    for kind, target, ttl, command, reason, auto_safe in planner(event):
        mode = (ActionMode.AUTO
                if auto_safe and verdict.tier is Tier.PREFILTER
                else ActionMode.RECOMMEND)
        actions.append(ResponseAction(
            kind=kind, target=str(target), host=event.host,
            ttl_minutes=ttl, command=command, reason=reason, mode=mode,
            event_id=event.id, signature=event.signature,
        ))
    return actions


class Responder:
    """Plans, (optionally) executes, and audits response actions."""

    def __init__(self, audit_path: str | Path = "response_audit.jsonl",
                 dry_run: bool = True) -> None:
        self.audit_path = Path(audit_path)
        self.dry_run = dry_run

    def respond(self, event: Event, verdict: Verdict) -> list[ResponseAction]:
        actions = plan(event, verdict)
        for action in actions:
            action.dry_run = self.dry_run
            if action.mode is ActionMode.AUTO and not self.dry_run:
                action.executed = self._execute(action)
            self._audit(action)
        return actions

    @staticmethod
    def _execute(action: ResponseAction) -> bool:
        result = subprocess.run(  # noqa: S602 — deliberate, opt-in only
            action.command, shell=True, capture_output=True, timeout=30,
        )
        return result.returncode == 0

    def _audit(self, action: ResponseAction) -> None:
        with self.audit_path.open("a", encoding="utf-8") as f:
            f.write(action.to_json() + "\n")
