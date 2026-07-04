"""CLI runner for the triage slice.

  python -m arbiter seed                     # demo assets + facts into memory
  python -m arbiter run samples/events.jsonl # triage a batch (mock LLM)
  python -m arbiter run samples/events.jsonl --backend ollama --model llama3.1:8b
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .eval import evaluate, load_cases
from .llm import get_backend
from .memory import Memory
from .schema import Decision, Event
from .triage import TriageEngine

RED, YEL, DIM, RST = "\033[91m", "\033[93m", "\033[2m", "\033[0m"


def cmd_seed(args: argparse.Namespace) -> None:
    mem = Memory(args.db)
    assets = [
        ("db-prod-01", 2.0, "production postgres", True),
        ("web-prod-01", 1.6, "public web server", True),
        ("ci-runner-01", 0.8, "CI runner", True),
        ("dev-laptop-42", 0.5, "developer laptop", True),
    ]
    for host, crit, role, confirmed in assets:
        mem.upsert_asset(host, crit, role, confirmed)
    mem.add_fact("backups run at 02:00 — nightly IO spike on db-prod-01 is normal",
                 scope="db-prod-01")
    mem.add_fact("ci-runner-01 spawns many short-lived containers; process churn is expected",
                 scope="ci-runner-01")
    print(f"Seeded {len(assets)} assets and 2 environment facts into {args.db}")


def cmd_run(args: argparse.Namespace) -> None:
    path = Path(args.events)
    if not path.exists():
        sys.exit(f"no such file: {path}")

    mem = Memory(args.db)
    engine = TriageEngine(
        memory=mem,
        llm=get_backend(args.backend, model=args.model),
        audit_path=args.audit,
        shadow=not args.live,
    )

    mode = "LIVE" if args.live else "SHADOW"
    print(f"Arbiter triage — backend={args.backend} mode={mode}\n")

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        event = Event.from_json(line)
        v = engine.triage(event)
        if v.decision is Decision.ESCALATE:
            tag = f"{RED}ESCALATE{RST}"
        else:
            tag = f"{YEL}suppress{RST}"
        print(f"{tag}  [{v.tier.value:9}] score={v.score:4.1f}  "
              f"{event.host:14} {event.source}/{event.event_type}")
        print(f"{DIM}          why: {v.rationale}{RST}")
        if v.evidence:
            print(f"{DIM}     evidence: {v.evidence}{RST}")

    s = engine.stats
    print(f"\n{s.total} events | prefilter decided {s.prefilter_decided}, "
          f"LLM decided {s.llm_decided} | "
          f"escalated {s.escalated}, suppressed {s.suppressed}")
    print(f"Audit trail appended to {args.audit}")
    if not args.live:
        print("Shadow mode: verdicts are logged, nothing was actually suppressed.")


def cmd_eval(args: argparse.Namespace) -> None:
    path = Path(args.eval_set)
    if not path.exists():
        sys.exit(f"no such file: {path}")

    cases = load_cases(path)
    backend = get_backend(args.backend, model=args.model)
    name = f"{backend.name}:{args.model}" if args.backend == "ollama" else backend.name
    print(f"Evaluating {name} against {len(cases)} labeled cases from {path}...")

    report = evaluate(backend, cases)
    report.backend_name = name
    report.print_summary()

    if report.missed_attacks:
        sys.exit(1)  # fatal per the trust model — fail the run


def main() -> None:
    p = argparse.ArgumentParser(prog="arbiter",
                                description="Arbiter triage engine slice")
    p.add_argument("--db", default="arbiter_memory.db", help="memory DB path")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("seed", help="seed demo assets and facts")
    sp.set_defaults(fn=cmd_seed)

    rp = sub.add_parser("run", help="triage a JSONL batch of events")
    rp.add_argument("events", help="path to events.jsonl")
    rp.add_argument("--backend", choices=["mock", "ollama"], default="mock")
    rp.add_argument("--model", default="llama3.1:8b")
    rp.add_argument("--audit", default="audit.jsonl")
    rp.add_argument("--live", action="store_true",
                    help="disable shadow mode (default: shadow)")
    rp.set_defaults(fn=cmd_run)

    ep = sub.add_parser("eval", help="score a backend against labeled cases")
    ep.add_argument("eval_set", nargs="?", default="samples/eval_set.jsonl",
                    help="path to labeled eval JSONL (default: samples/eval_set.jsonl)")
    ep.add_argument("--backend", choices=["mock", "ollama"], default="mock")
    ep.add_argument("--model", default="llama3.1:8b")
    ep.set_defaults(fn=cmd_eval)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
