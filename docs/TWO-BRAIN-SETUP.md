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

The preset does not replace an installed or portable application, or enable L2
in the dashboard. In the terminal, `events` shows the final classification while
preserving `first_stage` and `second_stage`. The durable `l2-cases` records hold
L2 decisions and reasons. Original ingestion/audit totals remain L1 evidence;
`status` reports L2 classifications separately. Nothing rewrites the original
Qwen verdict. A pending or failed review keeps the warning visible.

## How the handoff works

1. Existing rules handle clear cases. Mandatory safety warnings remain flagged;
   they do not enter Gemma's queue. Quiet observations also do not enter it.
2. Qwen reviews unclear events. Only its successful local-model escalations go
   to Gemma. A failed Qwen call remains flagged by policy and bypasses L2.
3. An independent **L2 pre-filter and safety check** runs first. It retains known
   risky evidence without inference. It also retains isolated protocol/login
   warnings that lack the context needed to settle them, avoiding a paid repeat
   of the same evidence. Exact, human-corrected process history can resolve a
   routine case: at least five explicit corrections, no unresolved risk, and the
   same process hash, command, user, parent and environment. Broad host history
   and the model's own previous opinions cannot authorize this shortcut.
4. When a model review is useful, Gemma receives bounded original facts **without
   Qwen's rationale or conclusion text**. Benchmark scoring labels are excluded.
   It considers ordinary and malicious explanations and proposes one final
   `escalate` or `suppress` decision, with a written reason. The older duplicate
   `outlook` judgment is derived for display rather than requested independently.
5. A separate Gemma call challenges that decision. This is a second pass by the
   same model, not an independent third model.
6. A **shared final guardrail** checks L1 and L2 decisions, including shortcuts.
   Model suppression needs an accepted challenge, exact copied facts and
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

```text
python tools/two_brain_eval.py --out evals/your-qwen-gemma-run
python tools/report_two_brain_eval.py evals/your-qwen-gemma-run
```

The default input is the same frozen 202-record AIT-ADS sample used in the prior
comparison. Qwen runs fresh with independent memory for each record, then every
eligible Qwen escalation is reviewed by Gemma. All first decisions, L2 outcomes,
errors, final classifications and durations are saved. Completed failures are
counted, not retried until they pass.

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
