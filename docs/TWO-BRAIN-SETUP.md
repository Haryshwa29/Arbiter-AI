# Qwen L1, Gemma L2: confirm or suppress escalated alerts

**Qwen3.5:4b is L1. Gemma4:12b is L2.** Gemma receives only alerts successfully
escalated by Qwen, then decides whether to keep the alert or suppress it with a
written reason. It never receives the incoming stream directly. Both models are
installed on the evaluation PC and run locally.

## Start the source-agent preset

From the repository root on Windows:

```powershell
.\tools\Start-TwoBrainAgent.ps1
```

Equivalent command, also usable with an appropriate state path on Linux:

```text
python -m arbiter agent --state-dir work/qwen-gemma-final-agent --backend ollama --model qwen3.5:4b --l2-model gemma4:12b --l2-final-review --l2-review-seconds 180 --l2-policy samples/two-brain-final-review.policy.json
```

The launcher has its own state directory. It starts the terminal agent's normal
permitted local collection; do not point two agents at the same state directory.
Enter `status`, `events`, `l2-cases`, or `l2-notices` to inspect the setup and
`quit` to stop. No containment flags are included.

The preset does not replace an installed or portable application. The dashboard
can enable the same pipeline with `serve --l2-model gemma4:12b`; see
[dashboard configuration](FIVE-WORKER-PIPELINE.md#local-dashboard). In the terminal,
`events` shows the final classification while
preserving `first_stage` and `second_stage`. The durable `l2-cases` records hold
L2 decisions and reasons. Original ingestion/audit totals remain L1 evidence;
`status` reports L2 classifications separately. Nothing rewrites the original
Qwen verdict. A pending or failed review keeps the warning visible.

## How the handoff works

The terminal final-review preset now has [five bounded worker stages](FIVE-WORKER-PIPELINE.md):
gateway, L1, L2 prefilter, L2, and final guardrail. L1 can continue while L2
investigates another event. The current source also has a separate sixth CPU
report worker; decisions finish before longer template reports. `status` exposes
decision workers, waiting lines and report-worker state. The
[latest public checkpoint](PROGRESS-2026-11-20.md) measured five-worker operation;
the newer compact-reply/report update awaits a real-model retest. Installed
dashboard updates require a new build and explicit L2 configuration.

1. Existing rules handle clear cases. Mandatory safety warnings remain flagged;
   they do not enter Gemma's queue. Quiet observations also do not enter it.
2. Qwen reviews unclear events. Only its successful local-model escalations go
   to Gemma. A failed Qwen call remains flagged by policy and bypasses L2.
3. An independent **L2 pre-filter** runs first. In the five-worker terminal
   preset it quiets only supported routine cases; unresolved warnings pass to
   Gemma even when useful context is missing. Known risk remains protected by
   the final guardrail after model review. Exact, human-corrected process history can resolve a
   routine case: at least five explicit corrections, no unresolved risk, and the
   same process hash, command, user, parent and environment. Broad host history
   and the model's own previous opinions cannot authorize this shortcut.
   A narrow native Wazuh resolved-CVE notification can also be quieted with
   checked rule/status/package/version evidence. This does not certify the asset
   safe. The old sequential evaluation's context-required bypass remains a
   historical routing limitation; it is not the upgraded terminal behavior.
4. When a model review is useful, Gemma receives bounded original facts **without
   Qwen's rationale or conclusion text**. Benchmark scoring labels are excluded.
   It considers ordinary and malicious explanations and proposes one final
   `escalate` or `suppress` decision, with a written reason. The older duplicate
   `outlook` judgment is derived for display rather than requested independently.
5. A separate Gemma call challenges a proposed suppression. Retain-only decisions
   can skip it. This is a second pass by the same model, not a third brain.
6. A **shared final guardrail** checks L1 and L2 decisions, including shortcuts.
   Model suppression needs an accepted challenge, validated supplied evidence and
   confidence of at least 0.9. Uncertainty, low confidence,
   malformed answers, known-risk vetoes or errors retain the warning. Model confidence is not a
   measured probability of correctness, and exact citations do not certify prose.
7. Every completed decision is tied to its exact event. A newer event cannot
   inherit an older event's suppression. Rejecting L2's case retains the alert.

This classification mode cannot authorize a network block, kill a process or run
a command. Suppressing an alert does not change the monitored device. The older
native-response L2 mode remains separate, with its stricter fresh native evidence
and independent executor gates. Its defaults were not relaxed for public data.

## Local inference settings

The separate [L2 security-context upgrade](L2-CONTEXT.md) preserves native CVE,
technique and conversation details and adds bounded matching login history and
an offline CISA reference. Its guards keep unknown applicability and unexplained
protocol anomalies visible. This upgrade is not applied to the already-running
stopped public replay. [Scoped repeat memory](LEARNED-PATTERNS.md) is a subsequent
upgrade and is also excluded from those frozen measurements.

The selected L2 route requests an 8,192-token context, at most 1,536 generated
tokens per call, temperature 0.1 and internal thinking off. Assessment and challenge
remain required, and their explicit explanations are saved. The overall review
budget is 180 seconds; individual requests retain a 90-second cap. These limits
are not speed guarantees.

Initial compatibility probes on one previously seen public record found a timeout
with thinking enabled and response-format/prompt compatibility problems. Those
checks are development probes, not successful scored evaluations. The previous
advice-only pilot stopped after five reviews when the owner clarified that L2
should make the final alert decision; those pilot results do not count in the
new final-review evaluation.

## Run the public-data evaluation

For all 2,600,263 supported records with resumable overnight processing, see
[the full public-data run guide](FULL-PUBLIC-RUN.md). The commands below are
the smaller comparison workflow.

```text
python tools/two_brain_eval.py --sample evals/2026-11-17-l2-evidence-gated/sample.jsonl --out evals/your-qwen-gemma-run
python tools/report_l2_independent_eval.py evals/your-qwen-gemma-run
```

The command above uses the corrected route's frozen 192-record AIT-ADS sample.
Without --sample, the runner defaults to the older 202-record comparison sample.
Qwen runs fresh with independent memory for each record, then every
eligible Qwen escalation is reviewed by Gemma. All first decisions, L2 outcomes,
errors, final classifications and durations are saved. Completed failures are
counted, not retried until they pass.

The latest published follow-up reused saved L1 decisions and ran L2 again after
adding the missing-DNS-question guardrail. It cleared 2 of 85 warnings without
attack annotations; 92 of 94 L2 cases retained without Gemma. No attack-annotated
record reached Gemma. This is a modest policy retest, not a new detection-rate
claim. See [the full results and limits](L2-INDEPENDENT-REVIEW.md).

The evaluation is staged: all Qwen decisions first, then L2 reviews. It does not
start live collection or a response actuator. Historical timestamps stay
historical. Measured inference time is not live queue delay or breach-detection
time. The terminal scheduler coalesces related cases; isolated-record evaluation
does not validate its behavior under production load.

To resume an interrupted identical scored run:

```text
python tools/two_brain_eval.py --out evals/your-qwen-gemma-run --resume
```

Resume checks input, model identities, source hashes and settings. Use a new
output directory for a changed model, prompt, policy or code version.
