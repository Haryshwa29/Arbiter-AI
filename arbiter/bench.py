"""Flood benchmark — triage behavior under attack-rate event volume.

The latency question that matters under a DDoS is not "how fast is one
LLM call" but "does the verdict for the attack arrive instantly, and what
backs up behind it." The pipeline is tiered precisely so that clear
attacks are decided by code (guardrails/prefilter, microseconds) and only
the ambiguous middle waits for the model. This benchmark measures that
claim instead of assuming it:

- synthesizes a flood: DDoS events (one signature, prefilter-clear) mixed
  with routine noise the memory layer should learn, unlearnable noise,
  ambiguous chaff on unknown hosts, and two buried needles — one
  rail-visible, one that only the LLM tier will catch;
- replays it through the real TriageEngine and times every verdict;
- projects real-model latency onto LLM-tier decisions (--llm-latency,
  measured 4.1s for qwen3.5:4b) and simulates a single-server FIFO queue
  at the given arrival rate: utilization, backlog, and — the number that
  answers the question — how long each needle's verdict took to come out;
- projects the same stream with signature-level dedup (one LLM decision
  per signature per window, reused) to show the planned fix.

Run: python -m arbiter bench [--rate 200] [--duration 30] [--backend mock]
"""

from __future__ import annotations

import os
import random
import statistics
import time
from dataclasses import dataclass, field

from .llm import get_backend
from .memory import Memory
from .schema import Decision, Event, Tier
from .triage import TriageEngine

# Stream mix (fractions of total events).
_FLOOD, _IO, _BURST, _AUTH = 0.80, 0.06, 0.05, 0.04
# remainder (~5%): ambiguous chaff on unknown hosts — an attacker mixing
# unique-looking events into the flood to bury the queue.


def _seed_memory(mem: Memory) -> None:
    """Mirror of cmd_seed: known assets + correctly scoped facts."""
    for host, crit, role in (("db-prod-01", 2.0, "production postgres"),
                             ("web-prod-01", 1.6, "public web server"),
                             ("ci-runner-01", 0.8, "CI runner"),
                             ("dev-laptop-42", 0.5, "developer laptop")):
        mem.upsert_asset(host, crit, role, True)
    mem.add_fact("backups run at 02:00 — nightly IO spike on db-prod-01 is normal",
                 scope="db-prod-01", event_types=("io_anomaly",))
    mem.add_fact("ci-runner-01 spawns many short-lived containers; process churn is expected",
                 scope="ci-runner-01",
                 event_types=("process_anomaly", "process_burst", "process_exec"))


def synth_flood(rate: float, duration: float, seed: int = 7) -> list[Event]:
    """Deterministic attack-window event stream, in arrival order."""
    rng = random.Random(seed)
    n = int(rate * duration)
    events: list[Event] = []
    for i in range(n):
        r = rng.random()
        if r < _FLOOD:
            e = Event(source="netflow", host="web-prod-01",
                      event_type="syn_flood",
                      message=f"syn flood: {rng.randint(20000, 90000)} half-open "
                              f"connections from spoofed sources",
                      severity=7.0, fields={"pps": rng.randint(100000, 900000)})
        elif r < _FLOOD + _IO:
            e = Event(source="node_exporter", host="db-prod-01",
                      event_type="io_anomaly",
                      message="nightly disk IO spike on /var/lib/postgresql "
                              "during backups window",
                      severity=2.0, fields={"iops": rng.randint(8000, 9900)})
        elif r < _FLOOD + _IO + _BURST:
            e = Event(source="auditd", host="ci-runner-01",
                      event_type="process_burst",
                      message=f"{rng.randint(150, 400)} short-lived containers "
                              f"spawned in 10m by runner process churn",
                      severity=4.0, fields={})
        elif r < _FLOOD + _IO + _BURST + _AUTH:
            e = Event(source="sshd", host="dev-laptop-42",
                      event_type="auth_failure",
                      message="failed password for jenny (retry then success)",
                      severity=2.5, fields={"user": "jenny"})
        else:
            # Ambiguous chaff: unique host + message → unique signature,
            # no fact, no hot indicator, no rail. Every one is an LLM call.
            e = Event(source="auditd", host=f"ws-{rng.randint(100, 199)}",
                      event_type="process_exec",
                      message=f"unrecognized helper binary restarted with "
                              f"modified config (variant {i})",
                      severity=3.0, fields={})
        events.append(e)

    # Buried needles: real intrusions arriving mid-flood.
    events[int(n * 0.50)] = Event(
        source="auditd", host="web-prod-01", event_type="user_created",
        message="new user backupsvc added with uid 0 during traffic spike",
        severity=3.0, fields={"uid": "0"})            # rail-visible
    events[int(n * 0.60)] = Event(
        source="auditd", host="web-prod-01", event_type="file_change",
        message="authorized_keys for user deploy appended with an "
                "additional key; no matching change ticket",
        severity=3.0, fields={})                       # LLM-tier only
    return events


NEEDLE_TYPES = ("user_created", "file_change")


@dataclass
class BenchRow:
    arrival: float
    signature: str
    tier: Tier
    decision: Decision
    pipeline_s: float     # measured wall time of engine.triage()
    needle: str = ""


def simulate_queue(arrivals: list[float],
                   services: list[float]) -> tuple[list[float], int, float]:
    """Single-server FIFO: per-event time-in-system, max backlog, drain time."""
    finish = 0.0
    finishes: list[float] = []
    for arr, svc in zip(arrivals, services):
        finish = max(arr, finish) + svc
        finishes.append(finish)
    in_system = [f - a for f, a in zip(finishes, arrivals)]
    depth_max, j = 0, 0
    for i, arr in enumerate(arrivals):
        while j < i and finishes[j] <= arr:
            j += 1
        depth_max = max(depth_max, i - j)
    return in_system, depth_max, finishes[-1] if finishes else 0.0


@dataclass
class BenchReport:
    rate: float
    duration: float
    llm_latency: float
    rows: list[BenchRow] = field(default_factory=list)

    def _services(self, dedup_window: float | None) -> list[float]:
        """Per-event service time: measured pipeline + model latency for
        LLM-tier decisions. With a dedup window, a signature already
        LLM-decided inside the window reuses the verdict (pipeline only)."""
        seen: dict[str, float] = {}
        out = []
        for r in self.rows:
            svc = r.pipeline_s
            if r.tier is Tier.LLM:
                last = seen.get(r.signature)
                if dedup_window is None or last is None \
                        or r.arrival - last > dedup_window:
                    svc += self.llm_latency
                    seen[r.signature] = r.arrival
            out.append(svc)
        return out

    def print_summary(self, dedup_window: float) -> None:
        n = len(self.rows)
        by_tier: dict[str, int] = {}
        for r in self.rows:
            key = f"{r.tier.value}:{r.decision.value}"
            by_tier[key] = by_tier.get(key, 0) + 1
        pipe_ms = sorted(r.pipeline_s * 1000 for r in self.rows)
        p = lambda q: pipe_ms[min(n - 1, int(q * n))]

        print(f"\n=== FLOOD BENCH: {n} events @ {self.rate:.0f}/s for "
              f"{self.duration:.0f}s (LLM latency {self.llm_latency:.2f}s"
              f"{' projected' if self.llm_latency else ''}) ===")
        print("tier mix: " + "  ".join(f"{k} {v}"
                                       for k, v in sorted(by_tier.items())))
        print(f"code-path latency per event: p50 {p(.5):.2f}ms  "
              f"p95 {p(.95):.2f}ms  max {pipe_ms[-1]:.2f}ms")

        for label, window in (("AS-IS (no dedup)", None),
                              (f"WITH signature dedup ({dedup_window:.0f}s window)",
                               dedup_window)):
            services = self._services(window)
            llm_calls = sum(1 for r, s in zip(self.rows, services)
                            if r.tier is Tier.LLM
                            and s > r.pipeline_s)
            busy = sum(s - r.pipeline_s for r, s in zip(self.rows, services))
            util = busy / self.duration if self.duration else 0.0
            in_system, depth, drain = simulate_queue(
                [r.arrival for r in self.rows], services)
            print(f"\n--- {label} ---")
            print(f"LLM calls: {llm_calls} ({llm_calls / n:.1%} of events)   "
                  f"model busy {busy:.0f}s over a {self.duration:.0f}s window "
                  f"→ utilization {util:.1f}x "
                  f"{'(SATURATED — queue grows for the whole attack)' if util > 1 else '(keeps up)'}")
            print(f"queue: max backlog {depth} events   worst verdict delay "
                  f"{max(in_system):.1f}s   fully drained {drain:.0f}s "
                  f"after first event")
            for r, t in zip(self.rows, in_system):
                if r.needle:
                    print(f"  needle [{r.needle}] arrived {r.arrival:.1f}s "
                          f"→ verdict {'+' if t >= 0 else ''}{t:.2f}s later "
                          f"({r.tier.value}, {r.decision.value})")
        flood_rows = [ (r, t) for r, t in zip(
            self.rows, simulate_queue([r.arrival for r in self.rows],
                                      self._services(None))[0])
            if r.signature.startswith("netflow:syn_flood")]
        if flood_rows:
            first = flood_rows[0]
            print(f"\nDDoS itself: first syn_flood verdict "
                  f"{first[1]:.3f}s after arrival "
                  f"({first[0].tier.value} — never waits for the model)")


def run_bench(rate: float, duration: float, backend_name: str, model: str,
              llm_latency: float, seed: int = 7) -> BenchReport:
    mem = Memory(":memory:")
    _seed_memory(mem)
    engine = TriageEngine(memory=mem, llm=get_backend(backend_name, model=model),
                          audit_path=os.devnull, shadow=True)
    events = synth_flood(rate, duration, seed)
    report = BenchReport(rate=rate, duration=duration,
                         llm_latency=llm_latency if backend_name == "mock" else 0.0)
    for i, event in enumerate(events):
        t0 = time.monotonic()
        v = engine.triage(event)
        dt = time.monotonic() - t0
        report.rows.append(BenchRow(
            arrival=i / rate, signature=event.signature, tier=v.tier,
            decision=v.decision, pipeline_s=dt,
            needle=(event.event_type
                    if event.event_type in NEEDLE_TYPES else "")))
    mem.close()
    return report


def cmd_bench(args) -> None:
    report = run_bench(args.rate, args.duration, args.backend, args.model,
                       args.llm_latency, args.seed)
    report.print_summary(args.dedup_window)
