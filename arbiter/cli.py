"""CLI runner for the triage slice.

  python -m arbiter seed
  python -m arbiter run samples/events.jsonl [--respond]
  python -m arbiter serve
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .eval import evaluate, load_cases, print_variance
from .llm import get_backend
from .memory import Memory
from .respond import ActionMode, Responder
from .schema import Decision, Event
from .triage import TriageEngine

RED, YEL, CYN, DIM, RST = "\033[91m", "\033[93m", "\033[96m", "\033[2m", "\033[0m"


def cmd_seed(args):
    mem = Memory(args.db)
    assets = [("db-prod-01", 2.0, "production postgres", True),
              ("web-prod-01", 1.6, "public web server", True),
              ("ci-runner-01", 0.8, "CI runner", True),
              ("dev-laptop-42", 0.5, "developer laptop", True)]
    for host, crit, role, confirmed in assets:
        mem.upsert_asset(host, crit, role, confirmed)
    mem.add_fact("backups run at 02:00 — nightly IO spike on db-prod-01 is normal", scope="db-prod-01")
    mem.add_fact("ci-runner-01 spawns many short-lived containers; process churn is expected", scope="ci-runner-01")
    print(f"Seeded {len(assets)} assets and 2 environment facts into {args.db}")


def cmd_run(args):
    path = Path(args.events)
    if not path.exists():
        sys.exit(f"no such file: {path}")
    mem = Memory(args.db)
    engine = TriageEngine(memory=mem, llm=get_backend(args.backend, model=args.model),
                          audit_path=args.audit, shadow=not args.live)
    responder = Responder(audit_path=args.respond_audit, dry_run=True) if args.respond else None
    mode = "LIVE" if args.live else "SHADOW"
    print(f"Arbiter triage — backend={args.backend} mode={mode}" + (" respond=DRY-RUN" if responder else "") + "\n")
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        event = Event.from_json(line)
        v = engine.triage(event)
        tag = f"{RED}ESCALATE{RST}" if v.decision is Decision.ESCALATE else f"{YEL}suppress{RST}"
        print(f"{tag}  [{v.tier.value:9}] score={v.score:4.1f}  {event.host:14} {event.source}/{event.event_type}")
        print(f"{DIM}          why: {v.rationale}{RST}")
        if v.evidence:
            print(f"{DIM}     evidence: {v.evidence}{RST}")
        if responder:
            for a in responder.respond(event, v):
                ttl = f" ttl={a.ttl_minutes}m" if a.ttl_minutes else ""
                label = "AUTO (dry-run)" if a.mode is ActionMode.AUTO else "RECOMMEND"
                print(f"{CYN}     respond: [{label}] {a.kind.value} {a.target}{ttl} — {a.reason}{RST}")
    s = engine.stats
    print(f"\n{s.total} events | prefilter decided {s.prefilter_decided}, LLM decided {s.llm_decided} | escalated {s.escalated}, suppressed {s.suppressed}")
    print(f"Audit trail appended to {args.audit}")
    if not args.live:
        print("Shadow mode: verdicts are logged, nothing was actually suppressed.")


def cmd_eval(args):
    path = Path(args.eval_set)
    if not path.exists():
        sys.exit(f"no such file: {path}")
    cases = load_cases(path)
    backend = get_backend(args.backend, model=args.model)
    name = f"{backend.name}:{args.model}" if args.backend == "ollama" else backend.name
    guard = "off" if args.no_guardrails else "on"
    print(f"Evaluating {name} against {len(cases)} labeled cases from {path} "
          f"(guardrails {guard})...")
    reports = []
    for i in range(args.runs):
        if args.runs > 1:
            print(f"--- run {i + 1}/{args.runs} ---")
        report = evaluate(backend, cases, use_guardrails=not args.no_guardrails)
        report.backend_name = name
        reports.append(report)
    reports[-1].print_summary()
    if args.runs > 1:
        print_variance(reports)
    if any(r.missed_attacks for r in reports):
        sys.exit(1)


def cmd_serve(args):
    from .web.server import serve
    serve(host=args.host, port=args.port, store_db=args.store_db,
          iam_db=args.iam_db, mem_db=args.db, events=args.events,
          backend=args.backend, model=args.model, interval=args.interval,
          feed=not args.no_feed)


def main():
    p = argparse.ArgumentParser(prog="arbiter", description="Arbiter triage engine slice")
    p.add_argument("--db", default="arbiter_memory.db", help="memory DB path")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("seed", help="seed demo assets and facts")
    sp.set_defaults(fn=cmd_seed)

    rp = sub.add_parser("run", help="triage a JSONL batch of events")
    rp.add_argument("events")
    rp.add_argument("--backend", choices=["mock", "ollama"], default="mock")
    rp.add_argument("--model", default="llama3.1:8b")
    rp.add_argument("--audit", default="audit.jsonl")
    rp.add_argument("--live", action="store_true")
    rp.add_argument("--respond", action="store_true")
    rp.add_argument("--respond-audit", default="response_audit.jsonl")
    rp.set_defaults(fn=cmd_run)

    ep = sub.add_parser("eval", help="score a backend against labeled cases")
    ep.add_argument("eval_set", nargs="?", default="samples/eval_set.jsonl")
    ep.add_argument("--backend", choices=["mock", "ollama"], default="mock")
    ep.add_argument("--model", default="llama3.1:8b")
    ep.add_argument("--no-guardrails", action="store_true",
                    help="measure the raw model without the security guardrails")
    ep.add_argument("--runs", type=int, default=1,
                    help="repeat the eval N times and report cross-run "
                         "variance (flaky cases are latent misses)")
    ep.set_defaults(fn=cmd_eval)

    wp = sub.add_parser("serve", help="run the self-hosted dashboard")
    wp.add_argument("--host", default="127.0.0.1")
    wp.add_argument("--port", type=int, default=8787)
    wp.add_argument("--store-db", default="arbiter_audit.db")
    wp.add_argument("--iam-db", default="arbiter_iam.db")
    wp.add_argument("--events", default="samples/events.jsonl")
    wp.add_argument("--backend", choices=["mock", "ollama"], default="mock")
    wp.add_argument("--model", default="qwen3.5:4b")
    wp.add_argument("--interval", type=float, default=2.0)
    wp.add_argument("--no-feed", action="store_true")
    wp.set_defaults(fn=cmd_serve)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
