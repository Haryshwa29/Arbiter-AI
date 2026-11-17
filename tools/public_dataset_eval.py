"""Reproducible, local-only cold-start triage evaluation on AIT-ADS.

Dataset preparation downloads public data. Evaluation itself only contacts
loopback Ollama and never opens a response actuator or customer database.
No changes to the production adapters, model prompt, or detection policy.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import heapq
import io
import csv
import json
import math
import ipaddress
import copy
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from arbiter.ingestion.normalization import normalize
from arbiter.llm import OllamaBackend, RulesOnlyBackend
from arbiter.memory import Memory
from arbiter.triage import TriageEngine

REVISION = "ce927ddaeaa674f6909e1de676fa7dc293e393bd"
DATA_URL = "https://zenodo.org/records/8263181/files/ait_ads.zip?download=1"
LABEL_URL = f"https://raw.githubusercontent.com/ait-aecid/alert-data-set/{REVISION}/alerts_csv/alerts_csv.zip"
DATA_MD5 = "43db6b1f0996e0024befd617706c50e9"
SCENARIOS = ("fox", "harrison", "russellmitchell", "santos", "shaw", "wardbeck", "wheeler", "wilson")


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def download(url, path):
    if path.exists():
        return
    temporary = path.with_suffix(".part")
    with urllib.request.urlopen(url, timeout=90) as src, temporary.open("wb") as dst:
        while block := src.read(1024 * 1024):
            dst.write(block)
    temporary.replace(path)


def label_rows(archive, scenario):
    with archive.open(f"alerts_csv/{scenario}_alerts.txt") as f:
        yield from csv.DictReader(io.TextIOWrapper(f, encoding="utf-8"))


def check_match(raw, row):
    description = raw["rule"]["description"]
    name = description if description.startswith("Suricata: ") else "Wazuh: " + description
    if row["name"] != name or row["ip"] != raw["agent"]["ip"]:
        raise ValueError("Raw alert and published event label do not align")


def event_from_raw(raw):
    # Elastic export calls this @timestamp; native manager input calls it
    # timestamp. Retain original native fields, rule severity, host and text.
    # Ground truth, CSV host aliases, attack categories and time_label are
    # deliberately unavailable here and never enter the event or model prompt.
    data = copy.deepcopy(raw)
    data["timestamp"] = data.get("timestamp") or data["@timestamp"]
    # AIT's older Wazuh decoder sometimes stores IPv4:port in srcip/dstip.
    # Split this unambiguously into the current adapter's separate fields;
    # original full_log remains present. Never infer absent network evidence.
    detail = data.get("data", {})
    for prefix in ("src", "dst"):
        value = detail.get(prefix + "ip", "")
        if isinstance(value, str) and value.count(":") == 1:
            address, port = value.rsplit(":", 1)
            if port.isdigit() and 0 <= int(port) <= 65535:
                ipaddress.IPv4Address(address)
                detail[prefix + "ip"] = address
                detail.setdefault(prefix + "port", int(port))
    return normalize(data, "wazuh").to_event()


def prepare(args):
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    if (out / "sample.jsonl").exists():
        raise SystemExit("Use a new output directory to freeze a new sample")
    cache = args.cache
    cache.mkdir(parents=True, exist_ok=True)
    download(DATA_URL, cache / "ait_ads.zip")
    download(LABEL_URL, cache / "alerts_csv.zip")
    with (cache / "ait_ads.zip").open("rb") as f:
        if hashlib.file_digest(f, "md5").hexdigest() != DATA_MD5:
            raise ValueError("Zenodo checksum mismatch")
    populations = Counter()
    heaps = defaultdict(list)
    excluded_aminer = Counter()
    excluded = defaultdict(set)
    if args.exclude_sample:
        for line in args.exclude_sample.read_text(encoding="utf-8").splitlines():
            item = json.loads(line)
            excluded[item["scenario"]].add(item["label_row"] - 2)
    # Deterministic bottom-k hash sample per scenario and event-label stratum.
    # Rare attack categories are sampled explicitly rather than drowned out
    # by repeated web-scanning alerts. These are NOT natural-prevalence rates.
    with zipfile.ZipFile(cache / "alerts_csv.zip") as labels:
        for scenario in SCENARIOS:
            for index, row in enumerate(label_rows(labels, scenario)):
                if not row["name"].startswith(("Wazuh: ", "Suricata: ")):
                    excluded_aminer[scenario] += 1
                    continue
                key = (scenario, row["event_label"])
                populations[key] += 1
                if index in excluded[scenario]:
                    continue
                k = args.negative_per_scenario if key[1] == "-" else args.attack_per_category
                score = int(hashlib.sha256(f"{args.seed}:{scenario}:{index}".encode()).hexdigest(), 16)
                item = (-score, index, row)
                heapq.heappush(heaps[key], item)
                if len(heaps[key]) > k:
                    heapq.heappop(heaps[key])
    chosen = defaultdict(dict)
    for (scenario, label), items in heaps.items():
        for _, index, row in items:
            chosen[scenario][index] = row
    sample = []
    alignment = {}
    with zipfile.ZipFile(cache / "ait_ads.zip") as rawzip, zipfile.ZipFile(cache / "alerts_csv.zip") as labels:
        for scenario in SCENARIOS:
            rows = iter(label_rows(labels, scenario))
            count = 0
            skipped = 0
            with rawzip.open(f"{scenario}_wazuh.json") as f:
                for line_number, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    # Same exclusion as the publisher's analyze.py, which
                    # emitted the label CSV in raw-alert order, then AMiner.
                    if b"The average number" in line:
                        skipped += 1
                        continue
                    raw = json.loads(line)
                    row = next(rows)
                    check_match(raw, row)
                    if count in chosen[scenario]:
                        assert chosen[scenario][count] == row
                        event = event_from_raw(raw)
                        sample.append({"sample_id": f"{scenario}:{line_number}", "scenario": scenario,
                            "raw_line": line_number, "label_row": count + 2,
                            "label": row["event_label"], "expected_attack": row["event_label"] != "-",
                            "population_stratum": populations[(scenario, row["event_label"])],
                            "event": json.loads(event.to_json())})
                    count += 1
            remaining = list(rows)
            if any(r["name"].startswith(("Wazuh: ", "Suricata: ")) for r in remaining):
                raise ValueError("Unmatched labels remain")
            if len(remaining) != excluded_aminer[scenario]:
                raise ValueError("AMiner exclusion count mismatch")
            alignment[scenario] = {"matched_supported_alerts": count, "excluded_average_alerts": skipped,
                "excluded_aminer": len(remaining), "sampled": len(chosen[scenario])}
            print("Aligned", scenario, alignment[scenario], flush=True)
    sample.sort(key=lambda r: (r["scenario"], r["event"]["timestamp"], r["raw_line"]))
    with (out / "sample.jsonl").open("w", encoding="utf-8") as f:
        for item in sample:
            f.write(json.dumps(item, allow_nan=False) + "\n")
    manifest = {"dataset": "AIT Alert Data Set (AIT-ADS)", "doi": "10.5281/zenodo.8263181",
        "dataset_url": DATA_URL, "dataset_sha256": digest(cache / "ait_ads.zip"),
        "dataset_md5": DATA_MD5, "labels_url": LABEL_URL, "labels_revision": REVISION,
        "labels_sha256": digest(cache / "alerts_csv.zip"), "sample_sha256": digest(out / "sample.jsonl"),
        "seed": args.seed, "sampling": "bottom-k SHA256 within each scenario/event_label stratum",
        "excluded_sample_sha256": digest(args.exclude_sample) if args.exclude_sample else None,
        "excluded_sample_rows": sum(len(v) for v in excluded.values()),
        "attack_per_category": args.attack_per_category, "negative_per_scenario": args.negative_per_scenario,
        "sample_size": len(sample), "alignment": alignment,
        "strata": [{"scenario": k[0], "label": k[1], "population": v, "sampled": len(heaps[k])}
                   for k, v in sorted(populations.items())],
        "protocol": "cold-start independent alerts; no facts, labels, feedback or prior verdict history; default asset criticality; shadow mode; Wazuh adapter and TriageEngine; no temporal correlation, collector or response evaluation",
        "format_adaptations": ["Elastic @timestamp copied to native timestamp", "IPv4:port in srcip/dstip split into separate IP and port fields when present"],
        "label_caveat": "event_label '-' means no attack annotation in the publisher's mapping, not independently certified benign; event labels rather than time windows are used",
        "frozen_at_utc": datetime.now(timezone.utc).isoformat()}
    save(out / "manifest.json", manifest)
    print("Frozen sample:", len(sample), "alerts; SHA256", manifest["sample_sha256"], flush=True)


def rate(numerator, denominator):
    return numerator / denominator if denominator else None


def wilson(successes, total):
    if not total:
        return None
    z = 1.959963984540054
    p = successes / total
    d = 1 + z*z/total
    centre = (p + z*z/(2*total))/d
    half = z*math.sqrt(p*(1-p)/total + z*z/(4*total*total))/d
    return [max(0, centre-half), min(1, centre+half)]


def metrics(rows):
    tp = sum(r["expected_attack"] and r["decision"] == "escalate" for r in rows)
    fn = sum(r["expected_attack"] and r["decision"] == "suppress" for r in rows)
    fp = sum(not r["expected_attack"] and r["decision"] == "escalate" for r in rows)
    tn = sum(not r["expected_attack"] and r["decision"] == "suppress" for r in rows)
    return {"n": len(rows), "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "attack_label_recall": rate(tp, tp+fn), "negative_label_suppression": rate(tn, tn+fp),
        "false_escalation_rate": rate(fp, fp+tn), "sample_precision": rate(tp, tp+fp),
        "sample_accuracy": rate(tp+tn, len(rows)), "sample_f1": rate(2*tp, 2*tp+fp+fn),
        "suppression_fraction": rate(tn+fn, len(rows)),
        "recall_wilson95_descriptive": wilson(tp, tp+fn),
        "negative_suppression_wilson95_descriptive": wilson(tn, tn+fp)}


def ollama_json(path):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open("http://127.0.0.1:11434" + path, timeout=10) as r:
        return json.load(r)


def run(args):
    from arbiter.schema import Event
    out = args.out
    manifest = json.loads((out / "manifest.json").read_text())
    if digest(out / "sample.jsonl") != manifest["sample_sha256"]:
        raise ValueError("Frozen sample checksum mismatch")
    sample = [json.loads(line) for line in (out / "sample.jsonl").read_text().splitlines()]
    run_dir = out / args.name
    run_dir.mkdir(exist_ok=True)
    if (run_dir / "predictions.jsonl").exists():
        raise SystemExit("Refusing to overwrite an evaluation; use a new --name")
    backend = OllamaBackend(args.model, url="http://127.0.0.1:11434") if args.backend == "ollama" else RulesOnlyBackend()
    tags = ollama_json("/api/tags") if args.backend == "ollama" else {}
    model = next((m for m in tags.get("models", []) if m["name"] == args.model), None)
    if args.backend == "ollama" and (not model or model.get("remote_host") or model.get("remote_model")):
        raise ValueError("A verified local model must be available")
    code = {str(p.relative_to(ROOT)).replace("\\", "/"): digest(p) for p in sorted((ROOT / "arbiter").rglob("*.py"))}
    meta = {"backend": args.backend, "model": model, "sample_sha256": manifest["sample_sha256"],
        "git_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "python": platform.python_version(), "os": platform.platform(), "processor": platform.processor(),
        "code_sha256": code, "runner_sha256": digest(__file__),
        "started_utc": datetime.now(timezone.utc).isoformat(), "repeat_count": 1,
        "inference_options": {"temperature": 0.1, "think": False, "format": "json"},
        "local_server_version": ollama_json("/api/version") if model else None}
    save(run_dir / "run.json", meta)
    results = []
    started = time.perf_counter()
    with (run_dir / "predictions.jsonl").open("w", encoding="utf-8") as output:
        for i, item in enumerate(sample, 1):
            # New in-memory database per alert prevents sampled events from
            # becoming an invented deployment history or leaking labels.
            memory = Memory(":memory:")
            engine = TriageEngine(memory, backend, audit_path=run_dir / "audit.jsonl", shadow=True)
            t0 = time.perf_counter()
            try:
                verdict = engine.triage(Event(**item["event"]))
            finally:
                latency = time.perf_counter() - t0
                memory.close()
            row = {k: v for k, v in item.items() if k != "event"}
            row.update(json.loads(verdict.to_json()))
            row["latency_s"] = latency
            row["policy_fallback"] = verdict.rationale.startswith("LLM tier failed (")
            results.append(row)
            output.write(json.dumps(row, allow_nan=False) + "\n")
            output.flush()
            print(f"{args.name} {i}/{len(sample)} {item['scenario']} label={item['label']} -> {verdict.decision.value} [{verdict.tier.value}] {latency:.2f}s elapsed={time.perf_counter()-started:.0f}s", flush=True)
    save(run_dir / "summary.json", summarize(results, time.perf_counter()-started))
    print(json.dumps(summarize(results, time.perf_counter()-started), indent=2), flush=True)


def summarize(rows, elapsed):
    result = metrics(rows)
    result["backend_errors_escalated_by_policy"] = sum(r.get("policy_fallback", False) for r in rows)
    result["tiers"] = dict(Counter(r["tier"] for r in rows))
    result["by_scenario"] = {s: metrics([r for r in rows if r["scenario"] == s]) for s in SCENARIOS}
    result["by_label"] = {s: metrics([r for r in rows if r["label"] == s]) for s in sorted({r["label"] for r in rows})}
    result["model_decided_subset"] = metrics([r for r in rows if r["tier"] == "llm" and not r.get("policy_fallback")])
    timings = sorted(r["latency_s"] for r in rows)
    result["latency_s"] = {"p50": statistics.median(timings), "p95_nearest_rank": timings[math.ceil(.95*len(timings))-1],
        "mean": statistics.mean(timings), "max": max(timings), "total_wall_s": elapsed,
        "sequential_alerts_per_second": len(rows)/elapsed}
    result["always_escalate_baseline"] = metrics([{**r, "decision": "escalate"} for r in rows])
    result["interval_caveat"] = "Wilson intervals are descriptive only: alerts are stratified and correlated within scenarios; not deployment or independent attack confidence bounds"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--cache", type=Path, default=ROOT / "output/public-eval/ait-ads")
    p.add_argument("--seed", type=int, default=20261117)
    p.add_argument("--attack-per-category", type=int, default=2)
    p.add_argument("--negative-per-scenario", type=int, default=16)
    p.add_argument("--exclude-sample", type=Path, help="Exclude previously evaluated label-row identities before sampling")
    p = sub.add_parser("run")
    p.add_argument("--backend", choices=["ollama", "rules-only"], default="ollama")
    p.add_argument("--model", default="qwen3.5:4b")
    p.add_argument("--name", required=True)
    args = parser.parse_args()
    if args.command == "prepare" and (args.attack_per_category < 1 or args.negative_per_scenario < 1):
        parser.error("Stratum sample sizes must be positive")
    (prepare if args.command == "prepare" else run)(args)


if __name__ == "__main__":
    main()
