# Arbiter AI: AIT-ADS public-data pilot

**Measured local execution on 17 November 2026. This is a small, stratified cold-start alert-triage pilot on public simulated attacks, not a production detection-rate claim.**

Arbiter escalated **72/86 attack-annotated alerts (83.7%)**, suppressed **5/128 alerts without attack annotations (3.9%)**, and suppressed **14 attack-annotated alerts**. The model generated 0 policy-fallback errors. Every verdict and rationale is included.

## Results

The comparison uses the identical frozen sample. Escalating every alert is an intentionally conservative baseline; high recall by itself does not demonstrate useful triage.

| Metric | Arbiter + local Qwen | Arbiter rules-only |
|---|---:|---:|
| Alerts evaluated | 214 | 214 |
| Attack-annotated alerts escalated | 72/86 (83.7%) | 86/86 (100.0%) |
| Attack-annotated alerts suppressed | 14 | 0 |
| Negative-label alerts suppressed | 5/128 (3.9%) | 0/128 (0.0%) |
| Negative-label alerts escalated | 123/128 (96.1%) | 128/128 (100.0%) |
| Precision on this stratified sample | 36.9% | 40.2% |
| Accuracy on this stratified sample | 36.0% | 40.2% |
| F1 on this stratified sample | 0.512 | 0.573 |

Confusion matrix: TP = attack label + escalate, FN = attack label + suppress, FP = no attack annotation + escalate, TN = no attack annotation + suppress. These are benchmark label comparisons, not independent confirmation of real compromise or harmlessness.

### Attack annotation breakdown

| Published event label | Evaluated | Escalated | Suppressed | Escalation rate |
|---|---:|---:|---:|---:|
| attacker_change_user | 16 | 16 | 0 | 100.0% |
| dirb | 16 | 2 | 14 | 12.5% |
| dnsteal | 4 | 4 | 0 | 100.0% |
| escalated_sudo_command | 16 | 16 | 0 | 100.0% |
| online_cracking | 4 | 4 | 0 | 100.0% |
| service_scan | 14 | 14 | 0 | 100.0% |
| wpscan | 16 | 16 | 0 | 100.0% |

### Scenario breakdown

| Scenario | Attack labels escalated | Negative labels suppressed |
|---|---:|---:|
| fox | 10/12 | 0/16 |
| harrison | 10/12 | 0/16 |
| russellmitchell | 9/10 | 0/16 |
| santos | 12/14 | 1/16 |
| shaw | 6/8 | 2/16 |
| wardbeck | 9/10 | 0/16 |
| wheeler | 8/10 | 2/16 |
| wilson | 8/10 | 0/16 |

### Measured execution

- Backend: local Ollama 0.40.3; `qwen3.5:4b`, 4.7B, Q4_K_M.
- Hardware: 13th Gen Intel(R) Core(TM) i7-13700F; 31.8 GiB usable RAM; NVIDIA GeForce RTX 4060 Ti (16 GiB VRAM). Windows; Python 3.14.5.
- End-to-end `TriageEngine.triage()` latency: median **3.85 s**, p95 **6.89 s**, mean 4.26 s, max 7.66 s.
- Sequential measured wall time: **15.21 minutes**; 0.235 alerts/s. Per-alert engine timing includes local-model metadata checks, inference, verdict memory writes and shadow JSONL audit; it excludes creation of the fresh per-alert database, which is included in total wall time. Neither measure includes downloading, sample preparation or live queue delay. This is not collector throughput, incident detection latency, or a projected capacity figure.
- Decision tiers: {"guardrail": 3, "llm": 206, "prefilter": 5}. Successful model-decided subset: 206 alerts, 67/81 attack labels escalated and 5/125 negative labels suppressed. Deterministic guardrails/prefilter decisions are not credited to model intelligence.
- Model temperature 0.1, JSON output, reasoning mode disabled, production prompt unchanged. One pass only; no repeatability or cross-model claim. Normal desktop load was not controlled.

Cold-start here means empty Arbiter memory/context for each alert. The local model was already loaded and a separate synthetic maintenance-event availability probe ran before evaluation; these timings do not measure a deliberate cold model load.

## Dataset and frozen protocol

Source: [AIT Alert Data Set, version 1](https://zenodo.org/records/8263181), DOI **10.5281/zenodo.8263181**, by **Max Landauer, Florian Skopik and Markus Wurzenberger, AIT Austrian Institute of Technology**. Dataset license: **Creative Commons Attribution 4.0 International (CC BY 4.0)**. Cite the authors' 2024 paper, *Introducing a New Alert Data Set for Multi-Step Attack Analysis*, and the 2023 paper, *Maintainable Log Datasets for Evaluation of Intrusion Detection Systems*. The publishers describe these as synthetic alerts from simulated multi-step attacks and normal user behavior, not customer breach records.

Event-level labels come from the publishers' [analysis CSV archive at revision ce927ddaeaa6](https://raw.githubusercontent.com/ait-aecid/alert-data-set/ce927ddaeaa674f6909e1de676fa7dc293e393bd/alerts_csv/alerts_csv.zip). We use **event_label**, not **time_label**. Being in an attack time window does not make every alert malicious. The publishers' analysis repository also contains GPL-3.0 code; no publisher code was incorporated into Arbiter.

1. Download the original 96.2 MB alert archive and verify the publisher's MD5, then record SHA-256 hashes. Align all **2,600,263** supported Wazuh/Suricata alert rows with the publishers' event-label rows in original order, checking rule descriptions and sensor IPs. AMiner's **55,558** alerts are excluded because Arbiter has no AMiner adapter. These are preparation/coverage counts: the local model evaluated **214**, not 2.6 million alerts.
2. Freeze a bottom-k SHA-256 sample with seed **20261117**: up to two attack alerts per scenario/event-label category and sixteen negative-label alerts per scenario. This yielded **86 attack labels and 128 negative labels**, seven attack annotation categories and all eight scenarios. Source mix: 154 Wazuh and 60 Suricata alerts carried by Wazuh.
3. Apply only two format compatibility steps: copy Elasticsearch `@timestamp` into native `timestamp`; split explicitly recorded IPv4:port values into separate IP/port fields. Use the existing Wazuh normalizer, its source rule levels, and `TriageEngine`. No ground-truth label/category metadata, time-window labels, CSV host aliases, inferred severities or curated benign facts are added to model input. Original detection descriptions and recorded attack-related strings remain valid evidence.
4. Start with fresh in-memory context for every alert: no customer databases, prior verdicts, feedback or test-label-derived facts. Use default asset criticality, shadow mode and the unchanged production model prompt/policies. Run the same sample through rules-only policy. No responder, containment, firewall or installed-service state is touched.
5. Preserve every verdict, rationale, measured latency, policy-fallback flag, data hash, model digest and engine source-file hash. Recompute the confusion matrix independently from the saved predictions when producing this report.

## Limits on publishable claims

- **Pilot scope:** one local model, one pass, 214 selected alerts from one public testbed collection. No claim about live breach prevention, whole-network coverage, ransomware prevention, autonomous response, or production accuracy.
- **Negative labels:** `-` means no attack annotation in the publisher's mapping. Treating these as benchmark negatives follows that mapping; it does not certify that every negative alert is benign. The reported negative-label escalation rate should not be presented as a verified operational false-positive rate.
- **Sampling:** attack categories and scenarios are deliberately balanced, rare classes are oversampled, and many dataset alerts repeat the same activity. Precision, accuracy, F1 and suppression percentages apply to this sample; they are not natural-prevalence full-dataset or customer estimates. Individual alerts are not independent attacks.
- **Coverage:** no AMiner input, Windows telemetry, temporal correlation, collector behavior, continuous replay, analyst feedback or response actions were evaluated. Some published attack behaviors, including webshell-command annotations found only in excluded AMiner input, are absent from this supported-input sample. Do not claim coverage of all dataset attacks.
- **Uncertainty:** descriptive Wilson intervals are retained in summary.json; scenario clustering and stratification prevent interpreting them as deployment confidence bounds. There was no untouched private holdout or check for pretraining exposure to this public dataset. No policy or prompt was tuned using the resulting predictions.
- **Timing:** measurements reflect this PC, shared local inference service, the stated model and this input sample. No vendor comparisons or estimated cloud savings were measured.

- **Explanations:** label agreement does not score factual accuracy of the generated rationale. A spot check found that the explanation for `santos:42300` described private address `10.229.255.254` as external without supplied network-boundary context. Saved model explanations remain unverified advice; no numerical grounding score is claimed.

## Reproduce

From the repository root, using Python 3.11+ and the stated local Ollama model:

```powershell
python tools/public_dataset_eval.py --out evals/ait-ads-reproduction prepare
python tools/public_dataset_eval.py --out evals/ait-ads-reproduction run --backend rules-only --name rules-only
python tools/public_dataset_eval.py --out evals/ait-ads-reproduction run --backend ollama --model qwen3.5:4b --name qwen3.5-4b-run1
```

For an exact-input replay use the included frozen sample and manifest. Sampling seed and pinned data can reproduce input selection; local-model outputs and timing may vary. Obtain the matching model digest rather than relying on a moving tag.

- Engine git revision: `f6da2692d0c3b03951f878242c74f14aeeb20cfe`. Source-file hashes are in `qwen3.5-4b-run1/run.json`; the evaluation tool and tests were new, uncommitted additions when the run started.
- Model digest: `2a654d98e6fba55d452b7043684e9b57a947e393bbffa62485a7aac05ee4eefd`.
- Sample SHA-256: `b4944d82837a53b6a5d3ad7e33cff0c72512e969aeac835e942eacdcff54ca6d`.
- Dataset SHA-256: `9f0595c4ebe56ac9223763881f55369dd4f249a8108064e4ae108eb3309aeeb9`.
- Event-label archive SHA-256: `2bf1a81527a3fe15d92079a7834c9d77c5305546e15569657d2097d6294825c3`.

Repository validation for this work: **438 passed, 2 skipped, 25 subtests passed**; the required seed-and-run CLI smoke check also passed in isolated output files. The smoke check uses the mock backend and is not included in the public-data model results.

## Files

`results.csv` contains every prediction. `sample.jsonl` contains the exact model input events with separately stored scoring labels. `manifest.json` records population coverage and sampling. Each run directory contains machine-readable summary, provenance and shadow audit. `error-analysis.md` lists every disagreement with the published labels. `publication-copy.md` is a short, qualified public statement. `SHA256SUMS.txt` verifies the pack.
