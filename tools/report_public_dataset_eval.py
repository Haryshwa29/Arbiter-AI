"""Build a publication pack from completed, frozen public-data runs."""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import html
import json
from pathlib import Path
import statistics
import zipfile


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def percent(value):
    return "undefined" if value is None else f"{100*value:.1f}%"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--run", default="qwen3.5-4b-run1")
    args = parser.parse_args()
    out = args.directory
    manifest = read(out / "manifest.json")
    summary = read(out / args.run / "summary.json")
    baseline = read(out / "rules-only/summary.json")
    meta = read(out / args.run / "run.json")
    hardware = read(out / "hardware.json")
    sample = [json.loads(line) for line in (out / "sample.jsonl").read_text().splitlines()]
    rows = [json.loads(line) for line in (out / args.run / "predictions.jsonl").read_text().splitlines()]
    assert len(rows) == len(sample) == manifest["sample_size"]
    assert len({r["sample_id"] for r in rows}) == len(sample)
    assert [r["sample_id"] for r in rows] == [r["sample_id"] for r in sample]
    assert all(r["label"] == s["label"] for r, s in zip(rows, sample))
    # Independently cross-tabulate saved decisions, rather than trust report
    # percentages or count backend outages as successful model predictions.
    matrix = Counter((r["expected_attack"], r["decision"]) for r in rows)
    for key, pair in {"tp": (True, "escalate"), "fn": (True, "suppress"),
                      "fp": (False, "escalate"), "tn": (False, "suppress")}.items():
        assert summary[key] == matrix[pair], (key, summary[key], matrix[pair])
    assert sum(matrix.values()) == len(rows)
    assert hashlib.sha256((out / "sample.jsonl").read_bytes()).hexdigest() == manifest["sample_sha256"]
    assert meta["sample_sha256"] == manifest["sample_sha256"]
    n = len(rows)
    pos = summary["tp"] + summary["fn"]
    neg = summary["fp"] + summary["tn"]
    model = meta["model"]
    elapsed = summary["latency_s"]["total_wall_s"]
    categories = sorted({s["label"] for s in sample} - {"-"})
    fields = ["sample_id", "scenario", "label", "expected_attack", "decision", "tier", "score", "latency_s", "policy_fallback", "rationale", "evidence"]
    with (out / "results.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    source_counts = Counter("Suricata via Wazuh" if s["event"]["message"].startswith("Suricata:") else "Wazuh" for s in sample)
    lines = [
        "# Arbiter AI: AIT-ADS public-data pilot", "",
        "**Measured local execution on 17 November 2026. This is a small, stratified cold-start alert-triage pilot on public simulated attacks, not a production detection-rate claim.**", "",
        f"Arbiter escalated **{summary['tp']}/{pos} attack-annotated alerts ({percent(summary['attack_label_recall'])})**, suppressed **{summary['tn']}/{neg} alerts without attack annotations ({percent(summary['negative_label_suppression'])})**, and suppressed **{summary['fn']} attack-annotated alerts**. The model generated {summary['backend_errors_escalated_by_policy']} policy-fallback errors. Every verdict and rationale is included.", "",
        "## Results", "",
        "The comparison uses the identical frozen sample. Escalating every alert is an intentionally conservative baseline; high recall by itself does not demonstrate useful triage.", "",
        "| Metric | Arbiter + local Qwen | Arbiter rules-only |",
        "|---|---:|---:|",
        f"| Alerts evaluated | {n} | {baseline['n']} |",
        f"| Attack-annotated alerts escalated | {summary['tp']}/{pos} ({percent(summary['attack_label_recall'])}) | {baseline['tp']}/{pos} ({percent(baseline['attack_label_recall'])}) |",
        f"| Attack-annotated alerts suppressed | {summary['fn']} | {baseline['fn']} |",
        f"| Negative-label alerts suppressed | {summary['tn']}/{neg} ({percent(summary['negative_label_suppression'])}) | {baseline['tn']}/{neg} ({percent(baseline['negative_label_suppression'])}) |",
        f"| Negative-label alerts escalated | {summary['fp']}/{neg} ({percent(summary['false_escalation_rate'])}) | {baseline['fp']}/{neg} ({percent(baseline['false_escalation_rate'])}) |",
        f"| Precision on this stratified sample | {percent(summary['sample_precision'])} | {percent(baseline['sample_precision'])} |",
        f"| Accuracy on this stratified sample | {percent(summary['sample_accuracy'])} | {percent(baseline['sample_accuracy'])} |",
        f"| F1 on this stratified sample | {summary['sample_f1']:.3f} | {baseline['sample_f1']:.3f} |", "",
        "Confusion matrix: TP = attack label + escalate, FN = attack label + suppress, FP = no attack annotation + escalate, TN = no attack annotation + suppress. These are benchmark label comparisons, not independent confirmation of real compromise or harmlessness.", "",
        "### Attack annotation breakdown", "",
        "| Published event label | Evaluated | Escalated | Suppressed | Escalation rate |", "|---|---:|---:|---:|---:|",
    ]
    for label in categories:
        m = summary["by_label"][label]
        lines.append(f"| {label} | {m['n']} | {m['tp']} | {m['fn']} | {percent(m['attack_label_recall'])} |")
    lines += ["", "### Scenario breakdown", "",
        "| Scenario | Attack labels escalated | Negative labels suppressed |", "|---|---:|---:|"]
    for scenario, m in summary["by_scenario"].items():
        lines.append(f"| {scenario} | {m['tp']}/{m['tp']+m['fn']} | {m['tn']}/{m['tn']+m['fp']} |")
    model_m = summary["model_decided_subset"]
    lines += ["", "### Measured execution", "",
        f"- Backend: local Ollama {meta['local_server_version']['version']}; `{model['name']}`, {model['details']['parameter_size']}, {model['details']['quantization_level']}.",
        f"- Hardware: {hardware['cpu']}; {hardware['ram_bytes']/1024**3:.1f} GiB usable RAM; {hardware['gpu']} (16 GiB VRAM). Windows; Python {meta['python']}.",
        f"- End-to-end `TriageEngine.triage()` latency: median **{summary['latency_s']['p50']:.2f} s**, p95 **{summary['latency_s']['p95_nearest_rank']:.2f} s**, mean {summary['latency_s']['mean']:.2f} s, max {summary['latency_s']['max']:.2f} s.",
        f"- Sequential measured wall time: **{elapsed/60:.2f} minutes**; {summary['latency_s']['sequential_alerts_per_second']:.3f} alerts/s. Per-alert engine timing includes local-model metadata checks, inference, verdict memory writes and shadow JSONL audit; it excludes creation of the fresh per-alert database, which is included in total wall time. Neither measure includes downloading, sample preparation or live queue delay. This is not collector throughput, incident detection latency, or a projected capacity figure.",
        f"- Decision tiers: {json.dumps(summary['tiers'], sort_keys=True)}. Successful model-decided subset: {model_m['n']} alerts, {model_m['tp']}/{model_m['tp']+model_m['fn']} attack labels escalated and {model_m['tn']}/{model_m['tn']+model_m['fp']} negative labels suppressed. Deterministic guardrails/prefilter decisions are not credited to model intelligence.",
        "- Model temperature 0.1, JSON output, reasoning mode disabled, production prompt unchanged. One pass only; no repeatability or cross-model claim. Normal desktop load was not controlled.", "",
        "Cold-start here means empty Arbiter memory/context for each alert. The local model was already loaded and a separate synthetic maintenance-event availability probe ran before evaluation; these timings do not measure a deliberate cold model load.", "",
        "## Dataset and frozen protocol", "",
        "Source: [AIT Alert Data Set, version 1](https://zenodo.org/records/8263181), DOI **10.5281/zenodo.8263181**, by **Max Landauer, Florian Skopik and Markus Wurzenberger, AIT Austrian Institute of Technology**. Dataset license: **Creative Commons Attribution 4.0 International (CC BY 4.0)**. Cite the authors' 2024 paper, *Introducing a New Alert Data Set for Multi-Step Attack Analysis*, and the 2023 paper, *Maintainable Log Datasets for Evaluation of Intrusion Detection Systems*. The publishers describe these as synthetic alerts from simulated multi-step attacks and normal user behavior, not customer breach records.", "",
        f"Event-level labels come from the publishers' [analysis CSV archive at revision {manifest['labels_revision'][:12]}]({manifest['labels_url']}). We use **event_label**, not **time_label**. Being in an attack time window does not make every alert malicious. The publishers' analysis repository also contains GPL-3.0 code; no publisher code was incorporated into Arbiter.", "",
        f"1. Download the original 96.2 MB alert archive and verify the publisher's MD5, then record SHA-256 hashes. Align all **2,600,263** supported Wazuh/Suricata alert rows with the publishers' event-label rows in original order, checking rule descriptions and sensor IPs. AMiner's **55,558** alerts are excluded because Arbiter has no AMiner adapter. These are preparation/coverage counts: the local model evaluated **{n}**, not 2.6 million alerts.",
        f"2. Freeze a bottom-k SHA-256 sample with seed **{manifest['seed']}**: up to two attack alerts per scenario/event-label category and sixteen negative-label alerts per scenario. This yielded **{pos} attack labels and {neg} negative labels**, seven attack annotation categories and all eight scenarios. Source mix: {source_counts['Wazuh']} Wazuh and {source_counts['Suricata via Wazuh']} Suricata alerts carried by Wazuh.",
        "3. Apply only two format compatibility steps: copy Elasticsearch `@timestamp` into native `timestamp`; split explicitly recorded IPv4:port values into separate IP/port fields. Use the existing Wazuh normalizer, its source rule levels, and `TriageEngine`. No ground-truth label/category metadata, time-window labels, CSV host aliases, inferred severities or curated benign facts are added to model input. Original detection descriptions and recorded attack-related strings remain valid evidence.",
        "4. Start with fresh in-memory context for every alert: no customer databases, prior verdicts, feedback or test-label-derived facts. Use default asset criticality, shadow mode and the unchanged production model prompt/policies. Run the same sample through rules-only policy. No responder, containment, firewall or installed-service state is touched.",
        "5. Preserve every verdict, rationale, measured latency, policy-fallback flag, data hash, model digest and engine source-file hash. Recompute the confusion matrix independently from the saved predictions when producing this report.", "",
        "## Limits on publishable claims", "",
        "- **Pilot scope:** one local model, one pass, 214 selected alerts from one public testbed collection. No claim about live breach prevention, whole-network coverage, ransomware prevention, autonomous response, or production accuracy.",
        "- **Negative labels:** `-` means no attack annotation in the publisher's mapping. Treating these as benchmark negatives follows that mapping; it does not certify that every negative alert is benign. The reported negative-label escalation rate should not be presented as a verified operational false-positive rate.",
        "- **Sampling:** attack categories and scenarios are deliberately balanced, rare classes are oversampled, and many dataset alerts repeat the same activity. Precision, accuracy, F1 and suppression percentages apply to this sample; they are not natural-prevalence full-dataset or customer estimates. Individual alerts are not independent attacks.",
        "- **Coverage:** no AMiner input, Windows telemetry, temporal correlation, collector behavior, continuous replay, analyst feedback or response actions were evaluated. Some published attack behaviors, including webshell-command annotations found only in excluded AMiner input, are absent from this supported-input sample. Do not claim coverage of all dataset attacks.",
        "- **Uncertainty:** descriptive Wilson intervals are retained in summary.json; scenario clustering and stratification prevent interpreting them as deployment confidence bounds. There was no untouched private holdout or check for pretraining exposure to this public dataset. No policy or prompt was tuned using the resulting predictions.",
        "- **Timing:** measurements reflect this PC, shared local inference service, the stated model and this input sample. No vendor comparisons or estimated cloud savings were measured.", "",
        "- **Explanations:** label agreement does not score factual accuracy of the generated rationale. A spot check found that the explanation for `santos:42300` described private address `10.229.255.254` as external without supplied network-boundary context. Saved model explanations remain unverified advice; no numerical grounding score is claimed.", "",
        "## Reproduce", "",
        "From the repository root, using Python 3.11+ and the stated local Ollama model:", "",
        "```powershell",
        "python tools/public_dataset_eval.py --out evals/ait-ads-reproduction prepare",
        "python tools/public_dataset_eval.py --out evals/ait-ads-reproduction run --backend rules-only --name rules-only",
        "python tools/public_dataset_eval.py --out evals/ait-ads-reproduction run --backend ollama --model qwen3.5:4b --name qwen3.5-4b-run1",
        "```", "",
        "For an exact-input replay use the included frozen sample and manifest. Sampling seed and pinned data can reproduce input selection; local-model outputs and timing may vary. Obtain the matching model digest rather than relying on a moving tag.", "",
        f"- Engine git revision: `{meta['git_revision']}`. Source-file hashes are in `{args.run}/run.json`; the evaluation tool and tests were new, uncommitted additions when the run started.",
        f"- Model digest: `{model['digest']}`.",
        f"- Sample SHA-256: `{manifest['sample_sha256']}`.",
        f"- Dataset SHA-256: `{manifest['dataset_sha256']}`.",
        f"- Event-label archive SHA-256: `{manifest['labels_sha256']}`.", "",
        "Repository validation for this work: **438 passed, 2 skipped, 25 subtests passed**; the required seed-and-run CLI smoke check also passed in isolated output files. The smoke check uses the mock backend and is not included in the public-data model results.", "",
        "## Files", "",
        "`results.csv` contains every prediction. `sample.jsonl` contains the exact model input events with separately stored scoring labels. `manifest.json` records population coverage and sampling. Each run directory contains machine-readable summary, provenance and shadow audit. `error-analysis.md` lists every disagreement with the published labels. `publication-copy.md` is a short, qualified public statement. `SHA256SUMS.txt` verifies the pack.", "",
    ]
    (out / "README.md").write_text("\n".join(lines), encoding="utf-8")
    errors = ["# Disagreements with published event labels", "",
        "Attack-annotation suppressions are listed first. No annotation does not independently establish harmlessness; negative-label escalations may still be defensible precautionary reviews.", ""]
    event_map = {s["sample_id"]: s["event"] for s in sample}
    for kind, selected in [
        ("Attack-annotated alerts suppressed", [r for r in rows if r["expected_attack"] and r["decision"] == "suppress"]),
        ("Alerts without attack annotations escalated", [r for r in rows if not r["expected_attack"] and r["decision"] == "escalate"]),
    ]:
        errors += [f"## {kind} ({len(selected)})", ""]
        for r in selected:
            e = event_map[r["sample_id"]]
            errors += [f"### {r['sample_id']} — {r['label']}", "",
                f"Source message: {e['message']}", "", f"Decision: **{r['decision']}**, tier `{r['tier']}`, source severity {e['severity']:.2f}.",
                "", f"Rationale: {r['rationale']}", "", f"Evidence: {r['evidence'] or '(none)'}", ""]
    (out / "error-analysis.md").write_text("\n".join(errors), encoding="utf-8")
    copy = (f"On 17 November 2026, we ran Arbiter AI with a fully local Qwen3.5 model on a frozen, stratified sample of {n} public AIT-ADS alerts spanning eight simulated company networks. "
        f"Arbiter escalated {summary['tp']} of {pos} attack-annotated alerts ({percent(summary['attack_label_recall'])}), suppressed {summary['fn']} attack-annotated alerts, and suppressed {summary['tn']} of {neg} alerts without attack annotations ({percent(summary['negative_label_suppression'])}). "
        f"Median triage latency was {summary['latency_s']['p50']:.2f} seconds on an RTX 4060 Ti desktop. "
        "These are single-pass cold-start pilot results on simulated attacks, not production detection or verified false-positive rates. Full inputs, methods, limitations, errors and results accompany the report. "
        "Dataset: Landauer, Skopik and Wurzenberger, AIT Alert Data Set, DOI 10.5281/zenodo.8263181 (CC BY 4.0).\n")
    (out / "publication-copy.md").write_text(copy, encoding="utf-8")
    # A static, self-contained HTML export is directly publishable; all text
    # is escaped and it requests no fonts, scripts or other runtime assets.
    body = html.escape(copy)
    page = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Arbiter AI — public-data pilot</title><style>body{{font:18px/1.6 system-ui,sans-serif;max-width:850px;margin:60px auto;padding:24px;background:#111315;color:#e8e9eb}}h1{{line-height:1.2}}table{{border-collapse:collapse;width:100%}}td,th{{padding:12px;text-align:left;border-bottom:1px solid #41464c}}a{{color:#a8c7ff}}.note{{color:#b9bec5}}</style><h1>Arbiter AI: public-data pilot</h1><p>{body}</p><table><tr><th>Measured outcome</th><th>Result</th></tr><tr><td>Attack-annotated alerts escalated</td><td>{summary['tp']}/{pos} ({percent(summary['attack_label_recall'])})</td></tr><tr><td>Attack-annotated alerts suppressed</td><td>{summary['fn']}</td></tr><tr><td>Negative-label alerts suppressed</td><td>{summary['tn']}/{neg} ({percent(summary['negative_label_suppression'])})</td></tr><tr><td>Median / p95 triage latency</td><td>{summary['latency_s']['p50']:.2f} s / {summary['latency_s']['p95_nearest_rank']:.2f} s</td></tr></table><p class="note">Sample-specific results. Negative labels mean no publisher attack annotation; they do not certify harmlessness. The rules-only baseline escalated every alert. Seven attack annotation categories were sampled; AMiner and temporal correlation were excluded.</p><p><a href="README.md">Full methods and limitations</a> · <a href="results.csv">Every result (CSV)</a> · <a href="error-analysis.md">Every label disagreement</a> · <a href="https://zenodo.org/records/8263181">Dataset and attribution</a></p></html>'''
    (out / "index.html").write_text(page, encoding="utf-8")
    files = sorted(p for p in out.rglob("*") if p.is_file() and p.name != "SHA256SUMS.txt")
    checksums = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out).as_posix()}" for p in files]
    (out / "SHA256SUMS.txt").write_text("\n".join(checksums) + "\n", encoding="utf-8")
    destination = out.parent / (out.name + "-publication-pack.zip")
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in sorted(out.rglob("*")):
            if p.is_file():
                z.write(p, out.name + "/" + p.relative_to(out).as_posix())
    print("Verified", n, "predictions; report and pack:", destination)


if __name__ == "__main__":
    main()
