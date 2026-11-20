# Qwen L1 and Gemma L2: public attack-data results

**Architecture correction:** this historical run did not include the requested
separate L2 noise-oriented pre-filter and complete shared final exit. The
[independent L2 follow-up](L2-INDEPENDENT-REVIEW.md) documents that correction and
a different frozen sample. The original measurements below remain unchanged.

**Qwen decides what to escalate. Gemma receives only those escalations and may keep the warning or suppress it with a written reason. No device action was authorized or executed.**

**Measured result:** after both stages, 74/74 attack-annotated records remained flagged (100.0%), and 48/128 records without attack annotations were quieted (37.5%). Gemma removed 0 Qwen warnings, including 0 attack-annotated records.

**L2 did not reduce the warning count in this run.** It completed its reviews but added substantial processing time.

## What we built, in everyday terms

**Qwen (`qwen3.5:4b`) is L1, the first reviewer.** Existing quick rules handle clear cases. Qwen reads the unclear ones and either keeps them quiet or escalates them.

**Gemma (`gemma4:12b`) is L2, the second reviewer.** It never receives the raw incoming stream directly. It receives only alerts successfully escalated by Qwen. It assesses the facts, then a separate Gemma call challenges that assessment. This is two passes by the same second model, not an independent third model.

**Gemma can suppress a Qwen alert**, but only when it proposes suppression, describes the record as routine-looking, reports confidence of at least 0.9, supplies checked facts and a written reason, and passes the challenge. Otherwise the warning stays flagged. Errors also retain it. Mandatory safety-rule warnings stay flagged outside this model-review route.

Both models run locally. Their metadata reports 4.7B parameters for Qwen and 11.9B for Gemma; B means billion. Both use compressed Q4_K_M weights. Confidence is a model self-report, not a measured probability of correctness.

The [ready-to-run terminal version](TWO-BRAIN-SETUP.md) implements this mode. Its event list shows the final decision alongside Qwen's original review; `l2-cases` stores the second review. Original audit totals retain first-stage decisions. The installed/portable dashboard application was not replaced, and this test does not establish dashboard integration or live queue performance.

## What public dataset did we use?

**AIT Alert Data Set (AIT-ADS), version 1**, by Max Landauer, Florian Skopik and Markus Wurzenberger, AIT Austrian Institute of Technology. [Original dataset / DOI 10.5281/zenodo.8263181](https://zenodo.org/records/8263181), licensed **CC BY 4.0**. The publisher requests citation of *Introducing a New Alert Data Set for Multi-Step Attack Analysis* (2024) and *Maintainable Log Datasets for Evaluation of Intrusion Detection Systems* (2023).

Think of it as security-tool reports from eight simulated company networks. It mixes staged scanning, web exploitation, password attacks, privilege changes, command execution and data theft with routine logins and software activity. We use Wazuh and Suricata-via-Wazuh reports; unsupported AMiner reports are excluded.

This run uses **202 frozen records: 74 with publisher attack annotations and 128 without attack annotations**. It reruns the same additional-sample cases from the previous comparison, not all 2.6 million supported records. The scoring uses the publisher's per-record `event_label`, not a broad attack time window. The model prompts do not receive these scoring labels.

**A record without an attack annotation is not certified harmless.** These selected cases come from the same known public scenarios; they are not an independent new-campaign test or a production detection-rate estimate.

## What were the actual numbers?

| Outcome on the same records | After L1 rules + Qwen | After Gemma L2 |
|---|---:|---:|
| Attack-annotated records flagged | 74/74 (100.0%) | 74/74 (100.0%) |
| Attack-annotated records wrongly quieted | 0/74 (0.0%) | 0/74 (0.0%) |
| Records without attack annotations quieted | 48/128 (37.5%) | 48/128 (37.5%) |
| Records without attack annotations still flagged | 80/128 (62.5%) | 80/128 (62.5%) |
| All visible warnings | 154/202 | 154/202 |

Gemma quieted **0 of the 97 Qwen escalations (0.0%)**: 0 records without attack annotations and 0 attack-annotated records. This measures the added effect of L2 on this run; it must not be credited to a new prefilter.

## Which layer succeeded or failed?

| Stage | What the test found |
|---|---|
| Quick prefilter | Quieted 45 unannotated records and 0 attack-annotated records. |
| Mandatory guardrails | Flagged 57 attack-annotated records before Qwen/Gemma. These are rule coverage, not Gemma successes. |
| Qwen L1 | Sent 97 alerts to Gemma, including 17 attack-annotated records; 0 model-failure policy fallbacks. |
| Gemma L2 decisions | Wrongly suppressed 0 of its 17 attack-annotated inputs (0.0%). |
| Gemma response reliability | 97/97 reviews passed structure/fact checks (100.0%); 0/97 failed (0.0%). |
| Challenge pass | Accepted 97 assessments; challenged 0. A challenge retains the warning. |
| Device response | Zero commands, network blocks or other containment actions. |

Passed checks means the reply had the required format and exact copied fields/citation IDs. It does not certify every conclusion or sentence. A model-generated ordinary explanation can still be wrong. Neither confidence nor a second pass by the same model is a guarantee.

### What failed and why

Gemma proposed keeping all 97 warnings; there were **zero suppression proposals** and zero suppression proposals overturned by the software. Thus the lack of reduction was its decision behavior under these frozen prompts and cold-start evidence, rather than the confidence gate rejecting attempted suppressions. This run does not isolate which prompt, model or context change would improve that behavior.

The code's suppression branch is covered by controlled-response regression tests. This public run did not exercise suppression by the real model, because Gemma made no suppression proposals.

The inspected examples exposed explanation problems even when a final flag matched its label. In `fox:12977`, Gemma treated a high-numbered network port as a listening service; the source instead shows traffic from port 443 to port 41262, which could be a client receiving a reply. The standalone fields omit the source port for this older wrapper, although the original message retains it. This needs both better field extraction and a more careful model interpretation.

In `fox:447150`, Gemma retained an attack-annotated session record but overstated what an administrator-level system process proved about privilege escalation. Its own challenge accepted both explanations. These selected examples are qualitative findings, not a measured error percentage for all explanations. A useful counterexample is `harrison:12719`, where Gemma found a concrete file-name-like clue inside a long DNS query; the quoted query was verified against the record.

Gemma did not suppress an attack-annotated record in this run. That is a result on its selected inputs, not proof that it cannot miss attacks.

## What improved, and what still needs work?

The earlier hardening added rules for web reconnaissance, retained important source-tool details and narrowly recognized routine mail/update observations. This iteration adds the requested L1-to-L2 handoff, final L2 decisions with written reasons, a separate challenge, strict fact checks, event-bound decisions and retention of warnings on errors. It does not retrain either model or make quieting infallible.

1. **Inspect the advice and any wrong suppressions.** Check invented causes, mistaken attribution and ordinary explanations that the actual record does not support. A formal independently scored explanation-quality study is still needed.
2. **Test whether L2 can distinguish ordinary activity from attacks.** Use development pairs with a concrete ordinary explanation and a similar-looking attack. Improve missing source fields and surrounding context, then freeze fresh evaluation cases. Keep response checks and retain failures; do not tune on the scored answers or retry them until they pass.
3. **Test complete sequences and the live queue.** Measure time to the first useful warning, time to L2, backlog, repeated-event handling and restarts. The terminal scheduler coalesces related cases; this isolated replay reviews individual alerts and does not validate that scheduling behavior under load.
4. **Test unfamiliar scenarios and repeat runs.** Compare Qwen alone with the cascade, including missed attacks, remaining warnings, reliable completion and speed. This sample has already been used in earlier development comparisons.
5. **Finish the operational integration.** Test dashboard presentation and clearly separated L1/L2 counts. L2 decisions currently live in terminal cases; L1 audit and learned history are preserved. Decide how human-confirmed L2 corrections should update learning before allowing repeated automatic quieting.
6. **Keep alert classification separate from device actions.** Suppressing an alert does not grant permission to block traffic, kill processes or run commands.

## How long did it take?

Hardware: 13th Gen Intel(R) Core(TM) i7-13700F, 31.8 GiB usable RAM, NVIDIA GeForce RTX 4060 Ti with 16,380 MiB GPU memory. Local Python 3.14.5 on Windows.

- Qwen/rule stage: 7.52 minutes of measured work across 202 records.
- Half of Gemma reviews finished within 31.58 seconds; 95% within 37.80 seconds; longest 41.03 seconds.
- Total Gemma work: 50.51 minutes across 97 inputs, including failures.
- This is staged: all fresh Qwen decisions first, then every eligible Gemma review. It is not a live arrival-rate, queue-delay or breach-detection-time measurement.
- Gemma uses two bounded calls, JSON-schema response formats, temperature 0.1, internal thinking off, an 8,192-token context request and a 1,536-token generation cap per call. Overall budget: 180 seconds; each inference request retains a 90-second cap. Explicit assessment and challenge text is saved; hidden thinking is not.
- Compatibility probes used one previously seen public record. A thinking-enabled probe timed out; later probes exposed fact-field and prompt compatibility problems. Those fixes and settings were frozen before this scored run. An advice-only pilot was stopped after five reviews when the owner clarified that L2 should make final decisions. None of those pilot reviews count here.

## Inspect or reproduce the result

```text
python tools/two_brain_eval.py --out evals/your-qwen-gemma-run
python tools/report_two_brain_eval.py evals/your-qwen-gemma-run
```

Input SHA-256: `5485da312eae0023c4aa1d4241b61114bc9c0d86a73ac1f86abba18b1486c2bc`. The run records both model digests, raw and canonical-LF source hashes, options and the runner hash. Source was evaluated in a working tree on parent `e6c52f0af4e338ea5b2465e70fe11f6b2723d490`; those hashes identify its exact state.

`sample.jsonl` is the frozen input. `input-provenance.json` preserves the sampling method, archive hashes and publisher-label revision. `primary.jsonl` preserves each L1 decision; `secondary-inputs.jsonl` holds label-free evidence packets; `secondary.jsonl` retains L2 results/errors; `final.jsonl` holds all final decisions. `summary.json` contains percentages and timings; CSV exports make the outcomes easier to inspect. Hardware and source-agent setup checks are recorded separately. `SHA256SUMS.txt` protects artifact bytes.

[Read the inspected examples and explanation limits](../evals/2026-11-17-qwen-gemma-final-review/case-review.md).

## Efficiency review

The local model runner reported 2944.63 seconds of loading, prompt processing and generation, about 97.2% of measured Gemma review time. This accounting comparison points to inference as the main cost; it is not an operating-system profile or a live-load benchmark. Rewriting small Python helpers would not address that cost.

The existing scheduler, local transport and validators were reused. No runtime package or extra service was added, and the evaluated source was kept unchanged. A faster configuration needs a separate measured test of speed and missed attacks.

[Read the efficiency measurements and review scope](../evals/2026-11-17-qwen-gemma-final-review/efficiency-review.md).
