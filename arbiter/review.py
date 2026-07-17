"""Human feedback loop — the analyst's confirm/overrule pass (roadmap #2).

The realistic-suite eval put the day-one precision floor at ~68%: deploys,
disk failures, and routine ops genuinely look like attacks until the system
is told otherwise. This CLI is the telling. It walks the audit trail's
recent verdicts grouped by signature and records the human's judgment:

- confirm  -> label_verdicts(sig, "confirmed"): suppressions gain the
  history that lets the prefilter absorb the signature without the LLM.
- overrule -> label_verdicts(sig, "overruled"): the prefilter boosts this
  signature's score from now on (trust penalty, +0.3 per overrule, capped).
- overruling an ESCALATION (it was actually benign) offers to create a
  scoped environment fact on the spot — the same fix that took the model
  gauntlet from 83% to 100% recall works in reverse for precision. The
  fact is scoped to the event class it explains (facts.py); over-scoping
  is the admin error the seed comments warn about.

Per invariant #2 there are no silent effects: every label and fact echoes
back exactly what was recorded.

Run: python -m arbiter review [--audit audit.jsonl] [--decision escalate]
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .memory import Memory

CONFIRM, OVERRULE, SKIP, QUIT = "c", "o", "s", "q"


@dataclass
class ReviewItem:
    signature: str
    decision: str                 # escalate | suppress
    tier: str
    count: int                    # occurrences of this signature in the trail
    message: str                  # most recent event message
    host: str
    source: str
    event_type: str
    rationale: str
    shadow: bool = True


def load_audit(path: str | Path) -> list[dict]:
    entries = []
    p = Path(path)
    if not p.exists():
        return entries
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def group_items(entries: list[dict], decision: str = "all") -> list[ReviewItem]:
    """One review item per signature (most recent occurrence wins),
    newest first — the analyst reviews alerts, not duplicates."""
    by_sig: dict[str, ReviewItem] = {}
    for e in entries:                      # audit is append-ordered: oldest first
        ev = e.get("event", {})
        sig = e.get("signature", "")
        if not sig:
            continue
        item = ReviewItem(
            signature=sig, decision=e.get("decision", ""),
            tier=e.get("tier", ""),
            count=(by_sig[sig].count + 1 if sig in by_sig else 1),
            message=ev.get("message", ""), host=ev.get("host", ""),
            source=ev.get("source", ""), event_type=ev.get("type", ""),
            rationale=e.get("rationale", ""), shadow=e.get("shadow", True),
        )
        by_sig[sig] = item
    items = list(by_sig.values())[::-1]    # newest signature first
    if decision != "all":
        items = [i for i in items if i.decision == decision]
    return items


@dataclass
class ReviewStats:
    confirmed: int = 0
    overruled: int = 0
    skipped: int = 0
    facts_added: list[str] = field(default_factory=list)


def apply_feedback(mem: Memory, item: ReviewItem, action: str) -> str:
    """Record one judgment. Returns the label written (or '' for skip)."""
    if action == CONFIRM:
        mem.label_verdicts(item.signature, "confirmed")
        return "confirmed"
    if action == OVERRULE:
        mem.label_verdicts(item.signature, "overruled")
        return "overruled"
    return ""


def _prompt_fact(mem: Memory, item: ReviewItem, input_fn, print_fn) -> str | None:
    """Offer a scoped fact after an escalation is overruled as benign."""
    text = input_fn("  fact text (empty to skip): ").strip()
    if not text:
        return None
    scope = input_fn(f"  scope host [{item.host}]: ").strip() or item.host
    et = input_fn(f"  event types, comma-separated "
                  f"[{item.event_type}]: ").strip() or item.event_type
    event_types = tuple(t.strip() for t in et.split(",") if t.strip())
    user = input_fn("  covers only user (optional): ").strip()
    path = input_fn("  covers only path prefix (optional): ").strip()
    window = input_fn("  covers only window HH:MM-HH:MM (optional): ").strip()
    mem.add_fact(text, scope=scope, user=user, path=path,
                 event_types=event_types, window=window)
    scoped = ", ".join(filter(None, [
        f"event_types={list(event_types)}" if event_types else "",
        f"user={user}" if user else "", f"path={path}" if path else "",
        f"window={window}" if window else ""]))
    print_fn(f"  fact recorded (scope={scope}{', ' + scoped if scoped else ''})")
    return text


def interactive_review(mem: Memory, items: list[ReviewItem],
                       input_fn=input, print_fn=print) -> ReviewStats:
    stats = ReviewStats()
    print_fn(f"{len(items)} signature(s) to review. "
             f"[c]onfirm  [o]verrule  [s]kip  [q]uit\n")
    for i, item in enumerate(items, 1):
        print_fn(f"--- {i}/{len(items)}  {item.decision.upper()} "
                 f"[{item.tier}]  seen {item.count}x")
        print_fn(f"  {item.host}  {item.source}/{item.event_type}")
        print_fn(f"  {item.message}")
        print_fn(f"  why: {item.rationale}")
        while True:
            ans = input_fn("  verdict correct? [c/o/s/q]: ").strip().lower()
            if ans in (CONFIRM, OVERRULE, SKIP, QUIT):
                break
            print_fn("  c = correct, o = wrong (overrule), s = skip, q = quit")
        if ans == QUIT:
            break
        if ans == SKIP:
            stats.skipped += 1
            continue
        label = apply_feedback(mem, item, ans)
        print_fn(f"  -> {label}: all '{item.signature}' verdicts labeled")
        if ans == CONFIRM:
            stats.confirmed += 1
        else:
            stats.overruled += 1
            if item.decision == "escalate":
                # A benign alert we cried wolf on: this is the precision
                # loop — capture WHY it's benign as a scoped fact.
                fact = _prompt_fact(mem, item, input_fn, print_fn)
                if fact:
                    stats.facts_added.append(fact)
            else:
                print_fn("  !! an overruled SUPPRESSION is a missed attack — "
                         "the prefilter will boost this signature from now "
                         "on; consider whether a guardrail should cover it "
                         "(see guardrails.py).")
    print_fn(f"\nreviewed: {stats.confirmed} confirmed, "
             f"{stats.overruled} overruled, {stats.skipped} skipped, "
             f"{len(stats.facts_added)} fact(s) added")
    return stats


def cmd_review(args) -> None:
    entries = load_audit(args.audit)
    if not entries:
        print(f"no audit entries in {args.audit} — run "
              f"`python -m arbiter run <events>` first")
        return
    items = group_items(entries, args.decision)[:args.limit]
    if not items:
        print(f"nothing to review (filter: {args.decision})")
        return
    mem = Memory(args.db)
    try:
        interactive_review(mem, items)
    finally:
        mem.close()
