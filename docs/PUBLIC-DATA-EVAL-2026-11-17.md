# AIT-ADS evaluation: Qwen3.5 triage failures and deterministic hardening

The later [Qwen L1 / Gemma L2 report](TWO-BRAIN-PUBLIC-EVAL.md) separately measures
the second model's final alert decisions. The single-brain results below remain
the historical baseline.

**Start with [the findings in plain English](FINDINGS-IN-PLAIN-ENGLISH.md)**
for the dataset, failures, improvements and planned next tests. This page keeps
the detailed measurements and methods for readers who want to check the evidence.

Measured on 17 November 2026. These are one-pass, stratified **alert-label** comparisons on simulated public attacks. They are not production breach-detection or verified operational false-positive rates.

## Model and public dataset

All three local-model runs used **`qwen3.5:4b`**, served by local Ollama: **4.7B parameters, Q4_K_M**, RTX 4060 Ti 16 GiB, i7-13700F, 31.8 GiB usable RAM, Windows, Python 3.14.5. The tag says 4b; its metadata reports 4.7B parameters. No cloud inference, mock predictions, response actions or customer databases were used in these evaluations.

Exact model digest: `2a654d98e6fba55d452b7043684e9b57a947e393bbffa62485a7aac05ee4eefd`. Model weights, system prompt, temperature (0.1), JSON response format and disabled reasoning mode were unchanged. The revision changes source normalization and deterministic policies; it does not make the underlying model smarter.

Public dataset: **AIT Alert Data Set (AIT-ADS), version 1**, by **Max Landauer, Florian Skopik and Markus Wurzenberger**, AIT Austrian Institute of Technology. [Zenodo record / DOI 10.5281/zenodo.8263181](https://zenodo.org/records/8263181), **CC BY 4.0**. Cite *Introducing a New Alert Data Set for Multi-Step Attack Analysis* (2024) and *Maintainable Log Datasets for Evaluation of Intrusion Detection Systems* (2023). The authors describe synthetic alerts generated from realistic simulated user activity and multi-step attacks across eight company networks.

The evaluation uses native Wazuh and Suricata-via-Wazuh alerts, with the publishers' **event_label** annotations, not broad attack time windows. AMiner's 55,558 alerts are excluded because Arbiter has no AMiner adapter. Preparation aligned all 2,600,263 supported alert rows; this is not the number evaluated by the model.

## Before and after

| Measured outcome | Original | Same-alert retest | Disjoint-alert holdout |
|---|---:|---:|---:|
| Alerts evaluated | 214 | 214 | 202 |
| Attack annotations escalated / total | 72/86 (83.7%) | 86/86 (100.0%) | 74/74 (100.0%) |
| Attack annotations suppressed | 14 | 0 | 0 |
| Negative-label alerts suppressed / total | 5/128 (3.9%) | 47/128 (36.7%) | 51/128 (39.8%) |
| Negative-label alerts escalated / total | 123/128 (96.1%) | 81/128 (63.3%) | 77/128 (60.2%) |
| Precision on this stratified sample | 36.9% | 51.5% | 49.0% |
| Accuracy on this stratified sample | 36.0% | 62.1% | 61.9% |
| F1 on this stratified sample | 0.512 | 0.680 | 0.658 |
| Alerts sent to the model | 206/214 (96.3%) | 103/214 (48.1%) | 100/202 (49.5%) |
| Median / p95 engine latency | 3.85 s / 6.89 s | 0.50 ms / 6.90 s | 0.70 ms / 6.94 s |
| Median engine latency for LLM-tier alerts | 3.93 s | 4.13 s | 4.38 s |
| Sequential run time | 15.21 min | 8.24 min | 8.28 min |
| Backend errors escalated by policy | 0 | 0 | 0 |

The original rules-only policy escalated every alert: 100% attack-label recall with 0% negative-label suppression. It was a conservative baseline, not useful noise reduction. The hardened rules-only baseline is also saved for each new sample; deterministic improvements must not be credited to Qwen's reasoning.

## Which layer failed?

In the original run, **all 14 attack-annotation suppressions were decided by the LLM**. The prefilter made **zero suppressions**. Its five decisions were escalations; three compared against negative labels. The guardrails escalated three attack-annotated alerts. There were no model outages, JSON parse failures or policy-fallback errors.

| Run / deciding tier | Decisions | Attack labels escalated | Attack labels suppressed | Negative labels escalated | Negative labels suppressed |
|---|---:|---:|---:|---:|---:|
| Original: guardrail | 3 | 3 | 0 | 0 | 0 |
| Original: prefilter | 5 | 2 | 0 | 3 | 0 |
| Original: llm | 206 | 67 | 14 | 120 | 5 |
| Same-alert retest: guardrail | 64 | 64 | 0 | 0 | 0 |
| Same-alert retest: prefilter | 47 | 0 | 0 | 3 | 44 |
| Same-alert retest: llm | 103 | 22 | 0 | 78 | 3 |
| Disjoint-alert holdout: guardrail | 57 | 57 | 0 | 0 | 0 |
| Disjoint-alert holdout: prefilter | 45 | 0 | 0 | 0 | 45 |
| Disjoint-alert holdout: llm | 100 | 17 | 0 | 77 | 6 |

**Attribution:** the direct wrong suppression was an LLM classification failure. The surrounding deterministic policy also had a coverage gap: it deferred low/moderate-severity application alerts to the model, and no pre/post-model rule prevented those dismissals. This was not a prefilter suppression bug or an agent execution failure.

### 1. Directory enumeration was dismissed as an ordinary 404

All 14 original suppressed attack annotations were `dirb` directory-enumeration alerts. Only 2/16 of that category were escalated (12.5%). Recorded requests probed application paths and returned 404; the model repeatedly concluded that a missing resource meant benign activity. An unsuccessful request does not establish a harmless requester. Conversely, an isolated 404 also does not prove a successful exploit.

Wazuh's decoded rule carried `web`, `accesslog` and `attack` groups, but those semantic groups were not preserved as bounded typed observations at the brain boundary. The generic low/moderate source score was insufficient for automatic escalation, so the LLM could confidently suppress it. The new guardrail requires review of a **detector-classified web attack/recon alert**, including 4xx responses. This is a review floor, not a diagnosis or an authorization to block.

The new rule deliberately avoids matching dataset hosts, private attacker IPs, WordPress paths, or literal `dirb` labels. An ordinary 404 lacking an upstream attack/recon classification does not trigger this floor. A source that overlabels routine missing pages as attacks can still create extra reviews; that precision tradeoff needs additional validation.

### 2. Routine TLS mail logins were escalated

All 43 original Dovecot-success alerts in the negative-label sample were escalated by the LLM. Some explanations treated `method=PLAIN` as proof of an unencrypted connection even though the same log explicitly recorded TLS. Others treated absent historical context as suspicious behavior. The old routine-telemetry prefilter did not cover Wazuh's Dovecot observations.

The new shortcut requires native Dovecot authentication-success provenance, the matching decoder/program, a recorded non-privileged user, explicit TLS, equal peer/server addresses in RFC1918 or loopback space, low source severity, consistent structured fields, no correlated finding and no prior human-overruled suppression. These observations remain retained for correlation. This is deliberately narrower than suppressing every successful login, private-IP login, or TLS event.

PAM/su/sudo sessions are excluded from that mail shortcut. New source-grounded privilege guardrails require review of root sudo operations and supported service-account identity transitions. A successful PAM login does not establish that the action is benign.

### 3. Wrapped detector evidence was flattened

The old Wazuh adapter treated embedded Suricata alerts as generic findings, used only the Wazuh wrapper's level, and missed EVE `src_ip`/`dest_ip` aliases. Thus an underlying priority-1 scan alert could arrive as severity 2 with absent normalized endpoints. That did not cause the 14 directory-scan suppressions, but it was a separate coverage/context defect.

The revised adapter preserves embedded priority and endpoints, uses a `network_alert` event class, and applies the existing high-priority finding review floor to priority-1 embedded alerts. Bounded native observations, rather than test labels or invented risk, reach the rules and model. A separate narrow prefilter recognizes a source-confirmed FreshClam update-start event; it does not declare an update completed or malware absent.

### 4. Context and explanation quality remain limitations

The pilot starts with empty Arbiter memory for every alert. A model seeing one request cannot reconstruct a whole scan campaign. The new bounded correlation rule detects at least ten distinct error paths for the same host, peer and agent within five minutes; it excludes future events, different agents/peers and repeated retries of one path. This rule is covered by owned synthetic regressions, **not by these independent-alert public-data runs**.

A manual explanation spot check also found a private RFC1918 address described as external without network-boundary evidence. Label agreement is not an explanation-grounding score. The source normalization changes improve available evidence but do not demonstrate that this model's explanations are always accurate.

## Attack-label breakdown

| Event label | Original escalated/total | Retest escalated/total | Holdout escalated/total |
|---|---:|---:|---:|
| attacker_change_user | 16/16 (100.0%) | 16/16 (100.0%) | 6/6 (100.0%) |
| dirb | 2/16 (12.5%) | 16/16 (100.0%) | 16/16 (100.0%) |
| dnsteal | 4/4 (100.0%) | 4/4 (100.0%) | 4/4 (100.0%) |
| escalated_sudo_command | 16/16 (100.0%) | 16/16 (100.0%) | 16/16 (100.0%) |
| online_cracking | 4/4 (100.0%) | 4/4 (100.0%) | 2/2 (100.0%) |
| service_scan | 14/14 (100.0%) | 14/14 (100.0%) | 14/14 (100.0%) |
| wpscan | 16/16 (100.0%) | 16/16 (100.0%) | 16/16 (100.0%) |

## Experimental limits and what to improve next

1. **Reduce remaining review noise with verified context.** Inspect the remaining generic IDS/TLS/decode anomalies against asset/service baselines and nearby independent detections. Do not silence all TLS errors: this dataset includes attack-annotated protocol anomalies too. A private address, TLS, or a high model confidence is not sufficient evidence of harmlessness.
2. **Validate review-floor precision.** The conservative source-attack-group review floor fixes the observed dismissals, but source groups can be broad. Collect independently labeled benign broken-link/application-error alerts, authorized scans and legitimate administrative sudo/su activity. Test scoped, expiring analyst-approved exceptions and actual temporal patterns before relaxing the floors.
3. **Evaluate complete chronological sequences.** Replay full scenarios through collection, bounded queues and correlation; measure scenario/incident detection, time to first review and overload behavior. These alert-isolation experiments cannot establish correlation efficacy, collection coverage or real response effectiveness.
4. **Test generalization and model stability.** Freeze new scenarios/datasets, run repeated model passes, score explanation grounding, and compare local model sizes on the model-decided subset. The disjoint alerts here come from the same eight testbed scenarios; they are not independent new campaigns. Public-data pretraining exposure was not audited.
5. **Maintain provenance and feedback boundaries.** Preserve native identities, decoder fields and underlying tool priorities; keep exact suppression scope, human overrides and audit reasons. No detector change here authorizes containment. New runtime dependencies: none.

The old sample was inspected to develop the fix. Its retest is a regression result and must not be presented as an untouched test. The second sample uses seed 20261118 and excludes every original selected raw alert, but related/duplicated behavior from the same scenarios can remain. Both new samples were frozen before their model runs and their code hashes match. No post-result threshold/prompt adjustment was made during these runs.

All percentages are unweighted, deliberately stratified sample values. Rare attack categories are oversampled. `-` means no publisher attack annotation, not independently certified benign behavior. Therefore the negative-label escalation rate is a proxy under this mapping, not a verified customer false-positive rate. The reported 100%-style observed rates, if any, are finite-sample counts rather than guarantees.

Timing is measured `TriageEngine.triage()` duration, including local metadata checks, inference, verdict memory writes and shadow audit. The model was loaded; cold-start refers to empty Arbiter context, not a cold model load. It excludes live queue delay, collection and dataset preparation. Total wall time includes per-alert in-memory database creation. Improved overall latency can arise from skipping inference and must not be advertised as improved model generation speed.

## Reproduction and artifacts

Evidence files: [original report](../evals/2026-11-17-ait-ads/README.md), [original predictions](../evals/2026-11-17-ait-ads/qwen3.5-4b-run1/predictions.jsonl), [retest CSV](../evals/2026-11-17-ait-ads-hardening/retest/results.csv), [holdout CSV](../evals/2026-11-17-ait-ads-hardening/holdout/results.csv), [retest provenance](../evals/2026-11-17-ait-ads-hardening/retest/qwen3.5-4b-run1/run.json), [holdout provenance](../evals/2026-11-17-ait-ads-hardening/holdout/qwen3.5-4b-run1/run.json), and [machine-readable comparison](../evals/2026-11-17-ait-ads-hardening/comparison.json). Each sample directory includes its frozen inputs, manifest, per-alert predictions, summary and shadow audit.

Validation of the final code: **459 tests passed, 2 skipped, 25 subtests passed**, including 21 focused source-policy cases; the required isolated seed-and-run CLI smoke check passed. A preliminary retest was stopped to harden TLS-field parsing against usernames/multiline marker placement. Both frozen final samples were then revalidated against the final normalizer before complete model runs. Preliminary predictions are not included in the published results.

The original normalized inputs are immutable. The retest uses the same raw alert identities and labels, re-normalized through the revised source adapter, so its normalized-input hash intentionally differs. The disjoint sample excludes original label-row identities before deterministic bottom-k selection. Format preparation copies Elasticsearch `@timestamp` to native `timestamp` and splits older IPv4:port decoder values; all transformations are recorded.

```powershell
python tools/public_dataset_eval.py --out evals/reproduction/retest prepare
python tools/public_dataset_eval.py --out evals/reproduction/holdout prepare --seed 20261118 --exclude-sample evals/2026-11-17-ait-ads/sample.jsonl
python tools/public_dataset_eval.py --out evals/reproduction/retest run --backend ollama --model qwen3.5:4b --name qwen3.5-4b-run1
python tools/public_dataset_eval.py --out evals/reproduction/holdout run --backend ollama --model qwen3.5:4b --name qwen3.5-4b-run1
```

Those commands create separate replication outputs under `evals/reproduction`. `python tools/report_triage_hardening.py` verifies and regenerates the report from the included, frozen evidence directories (`evals/2026-11-17-ait-ads` and `evals/2026-11-17-ait-ads-hardening`); it does not silently replace them with the separate replication outputs.

The report generator verifies paired identities, disjointness, model digest, every saved confusion-matrix cell, exact input hashes and equal post-change engine hashes. Model outputs and timing can vary on repeat runs. Obtain the matching model digest rather than relying only on a moving tag.

The new runs were measured with working-tree changes on base commit `f6da2692d0c3b03951f878242c74f14aeeb20cfe` before publication. Consequently the run metadata's git revision identifies that parent, while `code_sha256` identifies every exact evaluated engine file. The published change includes the evaluated source, with cross-checkout line-ending verification described below; checking out only the parent would reproduce the old policies.

Frozen evaluation files are excluded from Git line-ending conversion so their input/result checksums remain valid on GitHub. Engine sources follow the repository's LF convention; two measured Windows source files had CRLF endings. `source-provenance.json` records both measured raw-byte hashes and canonical-LF hashes for the old and new engine files. Canonical hashing changes only CRLF to LF and leaves all other source bytes intact; it supports verification across checkouts without changing the measured results.

| Run | Frozen input SHA-256 |
|---|---|
| Original | `b4944d82837a53b6a5d3ad7e33cff0c72512e969aeac835e942eacdcff54ca6d` |
| Same-alert retest | `aec4c56dc009e35531cb088ee8a0b09cba0d1c19a392ec11d35c4d8530764949` |
| Disjoint-alert holdout | `5485da312eae0023c4aa1d4241b61114bc9c0d86a73ac1f86abba18b1486c2bc` |

Primary supporting sources: [AIT-ADS](https://zenodo.org/records/8263181); [publishers' event-label archive](https://github.com/ait-aecid/alert-data-set/tree/ce927ddaeaa674f6909e1de676fa7dc293e393bd/alerts_csv); [Wazuh ClamAV rule semantics](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/clam-av-logs-collection.html). Existing and new tests use isolated fixtures and databases; live customer installs were not upgraded.
