#!/usr/bin/env python3
"""Head-to-head local-model comparison for the Arbiter triage engine.

Answers "which local open-weights model is good enough?" with evidence you
can hand to someone else: every run is stamped with the model digest Ollama
actually served, the sha256 of each suite, and the git revision of the code,
then written to a JSON file alongside a readable Markdown table.

The number that matters is the MODEL-ONLY subset. Guardrail-decided cases
say nothing about the model -- they'd score identically with no model at
all -- so the top-line recall/precision flatter every backend equally.

Usage
-----
    # what's actually pulled locally
    ollama list

    python tools/model_compare.py \
        --models qwen3.5:4b,gemma3:12b \
        --suites samples/model_gauntlet.jsonl,samples/redteam_suite.jsonl \
        --runs 3 --out evals/2026-08-22

Notes
-----
* --runs >1 is not optional for a real claim. A sampling model that is right
  once may not be right five times; a flaky ATTACK case is a latent miss.
* Ordering is model-major so a model is loaded into VRAM once, not per suite.
* Nothing here talks to the network beyond localhost:11434 (invariant #3).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.eval import CaseResult, EvalReport, evaluate, load_cases  # noqa: E402
from arbiter.llm import MockBackend, OllamaBackend  # noqa: E402
from arbiter.schema import Decision  # noqa: E402

DEFAULT_SUITES = [
    "samples/model_gauntlet.jsonl",   # rail-invisible: pure model judgment
    "samples/redteam_suite.jsonl",
    "samples/realistic_suite.jsonl",
]


# --------------------------------------------------------------------------
# provenance
# --------------------------------------------------------------------------

def ollama_tags(url: str) -> dict[str, dict]:
    """Map model name -> {digest, size, family, parameter_size, quantization}.

    The digest is what makes this reproducible: "gemma3:12b" is a moving
    tag, the digest is not.
    """
    try:
        with urllib.request.urlopen(f"{url}/api/tags", timeout=10) as resp:
            body = json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit(
            f"Cannot reach Ollama at {url} ({exc}).\n"
            f"Start it first, then re-run. This script never falls back to a "
            f"cloud API -- local inference only."
        )
    out = {}
    for m in body.get("models", []):
        det = m.get("details", {}) or {}
        out[m["name"]] = {
            "digest": (m.get("digest") or "")[:12],
            "size_bytes": m.get("size"),
            "family": det.get("family"),
            "parameter_size": det.get("parameter_size"),
            "quantization": det.get("quantization_level"),
        }
    return out


def _is_cloud(name: str, info: dict) -> bool:
    """Ollama cloud-routed tags run inference off-box (size is null/0)."""
    return name.endswith(":cloud") or not info.get("size_bytes")


def git_rev() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10,
            cwd=Path(__file__).resolve().parent.parent,
        ).stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def sha256_file(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16]


# --------------------------------------------------------------------------
# scoring
# --------------------------------------------------------------------------

def model_only(results: list[CaseResult]) -> list[CaseResult]:
    """Cases the LLM actually decided (no guardrail short-circuit)."""
    return [r for r in results if not r.guardrail]


def subset_scores(results: list[CaseResult]) -> dict:
    atk = [r for r in results if r.case.expected is Decision.ESCALATE]
    ben = [r for r in results if r.case.expected is Decision.SUPPRESS]
    caught = sum(1 for r in atk if r.actual is Decision.ESCALATE)
    false_esc = sum(1 for r in ben if r.actual is Decision.ESCALATE)
    flagged = caught + false_esc
    return {
        "n": len(results),
        "attacks": len(atk),
        "benign": len(ben),
        "caught": caught,
        "missed": len(atk) - caught,
        "false_escalations": false_esc,
        "recall": caught / len(atk) if atk else None,
        "precision": caught / flagged if flagged else None,
        "accuracy": (sum(1 for r in results if r.correct) / len(results)
                     if results else None),
    }


def summarize(reports: list[EvalReport]) -> dict:
    """Collapse N runs of one model x one suite into one record."""
    full = [subset_scores(r.results) for r in reports]
    mo = [subset_scores(model_only(r.results)) for r in reports]

    def spread(records, key):
        vals = [r[key] for r in records if r[key] is not None]
        if not vals:
            return None
        return {"min": min(vals), "max": max(vals),
                "mean": statistics.fmean(vals)}

    # per-case stability across runs
    flaky, latent_misses = [], []
    for row in zip(*(r.results for r in reports)):
        decisions = {x.actual for x in row}
        if len(decisions) > 1:
            c = row[0].case
            esc = sum(1 for x in row if x.actual is Decision.ESCALATE)
            rec = {"category": c.category, "expected": c.expected.value,
                   "escalated_runs": esc, "of_runs": len(row),
                   "notes": c.notes}
            flaky.append(rec)
            if c.expected is Decision.ESCALATE:
                latent_misses.append(rec)

    # a hard miss = missed in EVERY run (not just flaky)
    hard_misses = []
    for row in zip(*(r.results for r in reports)):
        c = row[0].case
        if (c.expected is Decision.ESCALATE
                and all(x.actual is Decision.SUPPRESS for x in row)):
            hard_misses.append({"category": c.category, "notes": c.notes,
                                "host": c.event.host,
                                "event_type": c.event.event_type})

    lat = [r.latency_s for rep in reports for r in rep.results
           if r.latency_s > 0]
    errors = [r.error for rep in reports for r in rep.results if r.error]

    return {
        "runs": len(reports),
        "full": {k: spread(full, k) for k in ("recall", "precision", "accuracy")},
        "full_counts": full[0],
        "model_only": {k: spread(mo, k)
                       for k in ("recall", "precision", "accuracy")},
        "model_only_counts": mo[0],
        "guardrail_decided": full[0]["n"] - mo[0]["n"],
        "hard_misses": hard_misses,
        "flaky": flaky,
        "latent_misses": latent_misses,
        "gate": "PASS" if not hard_misses and not latent_misses else "FAIL",
        "avg_latency_s": statistics.fmean(lat) if lat else 0.0,
        "backend_errors": len(errors),
        "error_samples": errors[:3],
    }


def disagreements(per_model: dict[str, list[EvalReport]]) -> list[dict]:
    """Cases where the models decided differently -- the actual evidence.

    Aggregate scores can tie while the models fail on completely different
    cases; this is the section a skeptic reads.
    """
    names = list(per_model)
    if len(names) < 2:
        return []
    out = []
    n_cases = len(per_model[names[0]][0].results)
    for i in range(n_cases):
        majority = {}
        for name in names:
            votes = Counter(rep.results[i].actual.value
                            for rep in per_model[name])
            majority[name] = votes.most_common(1)[0][0]
        if len(set(majority.values())) > 1:
            case = per_model[names[0]][0].results[i].case
            out.append({
                "category": case.category,
                "expected": case.expected.value,
                "event_type": case.event.event_type,
                "host": case.event.host,
                "message": case.event.message[:110],
                "notes": case.notes,
                "decisions": majority,
                "correct": {k: (v == case.expected.value)
                            for k, v in majority.items()},
            })
    return out


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def pct(v):
    return "--" if v is None else f"{v:.0%}"


def band(sp):
    if sp is None:
        return "--"
    if abs(sp["max"] - sp["min"]) < 1e-9:
        return f"{sp['mean']:.0%}"
    return f"{sp['mean']:.0%} ({sp['min']:.0%}-{sp['max']:.0%})"


def render_markdown(payload: dict) -> str:
    L = []
    meta = payload["meta"]
    L.append("# Local model comparison — Arbiter triage")
    L.append("")
    L.append(f"Run {meta['timestamp']} on {meta['host']} "
             f"({meta['platform']}), arbiter @ `{meta['git_rev']}`, "
             f"{meta['runs']} run(s) per suite, "
             f"guardrails **{'on' if meta['guardrails'] else 'off'}**.")
    L.append("")
    L.append("## Models served")
    L.append("")
    L.append("| model | digest | params | quant | size |")
    L.append("|---|---|---|---|---|")
    for name, d in meta["models"].items():
        gb = f"{d['size_bytes'] / 1e9:.1f} GB" if d.get("size_bytes") else "--"
        L.append(f"| `{name}` | `{d.get('digest', '?')}` | "
                 f"{d.get('parameter_size') or '?'} | "
                 f"{d.get('quantization') or '?'} | {gb} |")
    L.append("")
    L.append("## Suites")
    L.append("")
    L.append("| suite | cases | sha256 |")
    L.append("|---|---|---|")
    for s in meta["suites"]:
        L.append(f"| `{s['path']}` | {s['cases']} | `{s['sha256']}` |")
    L.append("")

    L.append("## Model-only subset — the comparison that counts")
    L.append("")
    L.append("Guardrail-decided cases are excluded: they escalate without the "
             "model and would score identically with no model at all.")
    L.append("")
    L.append("| suite | model | recall | precision | missed | flaky | "
             "gate | s/case |")
    L.append("|---|---|---|---|---|---|---|---|")
    for suite, by_model in payload["results"].items():
        for model, s in by_model.items():
            L.append(
                f"| `{Path(suite).stem}` | `{model}` | "
                f"{band(s['model_only']['recall'])} | "
                f"{band(s['model_only']['precision'])} | "
                f"{len(s['hard_misses'])} hard / "
                f"{len(s['latent_misses'])} latent | "
                f"{len(s['flaky'])} | {s['gate']} | "
                f"{s['avg_latency_s']:.2f} |"
            )
    L.append("")

    L.append("## Full suite (guardrails included)")
    L.append("")
    L.append("| suite | model | recall | precision | accuracy | rail-decided |")
    L.append("|---|---|---|---|---|---|")
    for suite, by_model in payload["results"].items():
        for model, s in by_model.items():
            L.append(f"| `{Path(suite).stem}` | `{model}` | "
                     f"{band(s['full']['recall'])} | "
                     f"{band(s['full']['precision'])} | "
                     f"{band(s['full']['accuracy'])} | "
                     f"{s['guardrail_decided']} |")
    L.append("")

    for suite, cases in payload["disagreements"].items():
        L.append(f"## Where they disagree — `{Path(suite).stem}`")
        L.append("")
        if not cases:
            L.append("_No disagreements: identical decisions on every case. "
                     "Any score gap here is noise, not capability._")
            L.append("")
            continue
        L.append(f"{len(cases)} case(s) decided differently. A model that "
                 "wins on aggregate but loses here is not clearly better.")
        L.append("")
        models = list(next(iter(cases))["decisions"])
        L.append("| category | expected | " +
                 " | ".join(f"`{m}`" for m in models) + " | event |")
        L.append("|---|---|" + "---|" * len(models) + "---|")
        for c in cases:
            cells = []
            for m in models:
                mark = "OK" if c["correct"][m] else "WRONG"
                cells.append(f"{c['decisions'][m]} ({mark})")
            L.append(f"| {c['category']} | {c['expected']} | "
                     + " | ".join(cells) +
                     f" | {c['event_type']} on {c['host']} |")
        L.append("")

    L.append("## Hard misses by model")
    L.append("")
    L.append("Missed in every run. Per invariant #1 these are the only "
             "failures that are actually expensive.")
    L.append("")
    any_miss = False
    for suite, by_model in payload["results"].items():
        for model, s in by_model.items():
            for m in s["hard_misses"]:
                any_miss = True
                L.append(f"- `{model}` / `{Path(suite).stem}` — "
                         f"**{m['category']}** ({m['event_type']} on "
                         f"{m['host']}): {m['notes']}")
    if not any_miss:
        L.append("_None._")
    L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--models",
                   help="comma-separated ollama tags, e.g. qwen3.5:4b,gemma3:12b")
    p.add_argument("--match",
                   help="instead of --models, auto-select every locally "
                        "pulled tag whose name contains one of these "
                        "comma-separated substrings, e.g. qwen,gemma")
    p.add_argument("--suites", default=",".join(DEFAULT_SUITES),
                   help="comma-separated paths to labeled JSONL suites")
    p.add_argument("--runs", type=int, default=3,
                   help="repeats per model per suite (default 3; 1 proves "
                        "nothing about a sampling model)")
    p.add_argument("--out", default="evals/latest",
                   help="output directory for results.json + comparison.md")
    p.add_argument("--url", default="http://localhost:11434")
    p.add_argument("--no-guardrails", action="store_true",
                   help="isolate raw model judgment on every case")
    p.add_argument("--self-test", action="store_true",
                   help="validate the harness with MockBackend instead of "
                        "Ollama (no GPU, no inference). Proves the plumbing, "
                        "never a model claim.")
    args = p.parse_args()

    if not args.models and not args.match:
        raise SystemExit("Pass --models or --match (see --help).")

    suites = [s.strip() for s in args.suites.split(",") if s.strip()]
    use_rails = not args.no_guardrails

    # preflight: fail loudly before spending an hour of inference
    if args.self_test:
        models = [m.strip() for m in (args.models or "").split(",") if m.strip()]
        tags = {m: {"digest": "self-test", "parameter_size": "n/a",
                    "quantization": "n/a", "size_bytes": None,
                    "family": "mock"} for m in models}
    else:
        tags = ollama_tags(args.url)
        if args.match:
            want = [s.strip().lower() for s in args.match.split(",") if s.strip()]
            models = sorted(t for t in tags
                            if any(w in t.lower() for w in want)
                            and not _is_cloud(t, tags[t]))
            if not models:
                raise SystemExit(
                    "No pulled model matches " + "/".join(want) + ".\n"
                    "Available: " + ", ".join(sorted(tags))
                )
            print("auto-selected: " + ", ".join(models) + "\n")
        else:
            models = [m.strip() for m in args.models.split(",") if m.strip()]
        # Invariant #3: nothing leaves the customer's network. An Ollama
        # cloud-routed tag would ship every event off-box.
        cloud = [m for m in models if m in tags and _is_cloud(m, tags[m])]
        if cloud:
            raise SystemExit(
                "Refusing to evaluate cloud-routed model(s): "
                + ", ".join(cloud) + "\n"
                "Arbiter's design invariant #3 is that no event leaves the "
                "customer's network. Benchmarking a cloud endpoint would "
                "produce a number the product can never ship."
            )
        missing = [m for m in models if m not in tags]
        if missing:
            raise SystemExit(
                "Not pulled locally: " + ", ".join(missing) + "\n"
                "Available: " + ", ".join(sorted(tags)) + "\n"
                "Run `ollama pull <model>` first. The tag must match exactly "
                "-- there is no gemma:8b; Gemma ships 1b/4b/12b/27b (Gemma 3) "
                "and 2b/9b/27b (Gemma 2)."
            )
    for s in suites:
        if not Path(s).exists():
            raise SystemExit(f"No such suite: {s}")

    suite_cases = {s: load_cases(s) for s in suites}
    meta = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": platform.node(),
        "platform": f"{platform.system()} {platform.release()}",
        "python": sys.version.split()[0],
        "git_rev": git_rev(),
        "runs": args.runs,
        "guardrails": use_rails,
        "models": {m: tags[m] for m in models},
        "suites": [{"path": s, "cases": len(suite_cases[s]),
                    "sha256": sha256_file(s)} for s in suites],
    }

    results: dict[str, dict[str, dict]] = {s: {} for s in suites}
    raw: dict[str, dict[str, list[EvalReport]]] = {s: {} for s in suites}

    total = len(models) * len(suites) * args.runs
    done = 0
    t0 = time.monotonic()
    # model-major: keeps one model resident in VRAM instead of thrashing
    for model in models:
        backend = (MockBackend() if args.self_test
                   else OllamaBackend(model=model, url=args.url))
        for suite in suites:
            reports = []
            for i in range(args.runs):
                done += 1
                print(f"[{done}/{total}] {model} x {Path(suite).stem} "
                      f"run {i + 1}/{args.runs} "
                      f"({len(suite_cases[suite])} cases)...", flush=True)
                reports.append(evaluate(backend, suite_cases[suite], use_rails))
            raw[suite][model] = reports
            results[suite][model] = summarize(reports)

    payload = {
        "meta": meta,
        "results": results,
        "disagreements": {s: disagreements(raw[s]) for s in suites},
        "elapsed_s": round(time.monotonic() - t0, 1),
    }

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(payload, indent=2),
                                      encoding="utf-8")
    md = render_markdown(payload)
    (out / "comparison.md").write_text(md, encoding="utf-8")

    print(md)
    print(f"\nWrote {out / 'results.json'} and {out / 'comparison.md'} "
          f"({payload['elapsed_s']}s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
