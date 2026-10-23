# Optional L2 incident review and bounded response

The terminal agent supports an independent L2 investigation engine and a
separately selected local Ollama model.
It is off by default. No model is downloaded automatically. Choose and provision
a larger model appropriate to the customer's hardware. L2 verifies local model
metadata reports more than 4B parameters and rejects the same model name as an
Ollama L1 configuration. Model size does not establish quality. Existing triage
and the side-effect-free triage engine remain unchanged.

## Run

Advice only, using an already installed model:

```text
python -m arbiter agent --state-dir ./agent-state --l2-model YOUR_INSTALLED_MODEL
```

Inference uses loopback Ollama and the existing model metadata checks that reject
cloud aliases. Customer-controlled remote inference is not implemented in this
release. No runtime dependencies were added.

L2 has its own transport, evidence prefilter, investigation orchestration and
recommendation guardrails (`l2_transport.py`, `l2_evidence.py`, `l2.py`,
`l2_guardrails.py`). It does not invoke L1's model engine or verdict parser.
It shares the durable telemetry store, narrow action catalog and native firewall
adapters. L1 escalation is the handoff trigger; L1 prose and correlations are
not accepted as proof for L2's action authorization.

The L2 evidence prefilter independently rebuilds same-host/account/peer failure
sequences or native Defender/Sysmon exact-path support. It rejects untrusted
origins, duplicate identities, replay tags, future/stale data and cross-host
evidence. It uses a bounded, read-only local dossier of up to 64 records, with
code-assigned fact IDs and a digest. It executes no model-selected queries.

The general investigation route uses two separate model calls: evidence-based
analysis and a challenge of the recommendation against benign explanations,
contradictions and service impact. Both use the chosen larger model; a second
pass is not an independent model or proof of correctness. Explicit reasoning is
enabled, with a 16K context request and bounded generation. Concise assessments
are retained; raw internal model thinking is not stored.

The analysis must include both malicious and benign hypotheses, each identifying
supporting and opposing evidence IDs. Assertions must reference known fact IDs
and exact field values. Blocking needs
citations for every independently required support record, a matching target,
and a challenge with no objections and complete support citations. Unsupported
assertions fail closed. The executor rebuilds supporting evidence again before
action. This validates citations and policy constraints, not every semantic
claim in model-written prose; real-model evaluation remains necessary.

For a native Defender finding matched to exact-path Sysmon network activity,
L2 has a code-validated critical fast path. The scheduler runs this path without
waiting behind inference. Only the existing explicit policy, scope, freshness
and deadline conditions can authorize containment. Deeper model investigation
is queued afterward; its conclusions are retained as follow-up notices. A
contradictory follow-up stops a still-pending recommendation and alerts a human
if containment already happened. Model unavailability does not revoke an
independently supported fast-path decision. Revert remains available.

L2 supplies a structured brief: assessment, evidence, gaps, recommendation,
alternatives, recovery, urgency and confidence. It can recommend only human
review or the exact supported IP-block proposal. It cannot suppress a verdict,
execute shell commands, change scope, or enroll its own automatic actions.

For pre-authorized unattended response, create a local JSON policy:

```json
{
  "automatic": true,
  "rules": ["repeated_login_failures", "malware_process_network"],
  "windows": {"critical": 60, "high": 300, "medium": 1800}
}
```

Pass `--l2-policy PATH` together with `--l2-model`, `--enable-containment`, and
explicit `--allow-network` and `--protect-network` values for the deployment.
The existing protections for management, service and local addresses apply.
Protect the configuration and state directory using the customer's OS access
controls. This CLI assumes its operator is the authorized local administrator.

Severity comes from normalized severity and L2's own independent evidence
assessment, not L1 correlation prose or model-written urgency:
critical >=9, high >=7, medium >=4, otherwise
low. Policy may shorten the default windows, including immediate critical action,
but cannot increase them or make higher severity wait longer than lower severity.
Low severity never automatically acts. Response deadline and five-minute firewall
expiry are separate timers.

The scheduler requires all of the following before execution:

- Automatic response explicitly enabled and the deterministic rule enrolled.
- For malware/network correlations, verified tool-source evidence.
- A validated L2 block recommendation with confidence >=0.95 and matching peer.
- A still-eligible local collector proposal with evidence no older than 30 seconds.
- A permitted peer, remaining action capacity, and successful native rule checks.

CPU/path/network heuristics alone are not enrolled for unattended action. An old
finding, protected address, unavailable model, uncertain recommendation or failed
native operation escalates to human review instead of broadening authority.
Repeated observations do not reset deadlines. Increasing severity shortens the
deadline and invalidates an older lower-severity L2 review. Incident identity
includes process creation identity where available.

## Operator commands

```text
l2-cases
l2-notices
l2-notices LAST_NOTICE_ID
l2-ack CASE_ID
l2-defer CASE_ID reason for review
l2-reject CASE_ID reason for rejection
l2-revert CASE_ID
l2-stop
l2-resume
```

Acknowledgment or deferral grants at most one bounded extension, limited to one
severity window. Repeated acknowledgments cannot keep extending it. Reject and
defer require reasons. Revert uses the existing verified native undo operation;
it cannot restore an interrupted session or undo every downstream consequence.
The stop switch persists across restart and stops unattended actions, not existing
blocks; use revert for immediate release. Existing blocks retain OS-owned expiry.

Notices are persisted in SQLite and the audit trail, and emitted as JSON on the
running CLI's stdout. They include action outcome, expiry and the revert command.
`l2-notices` supports a durable consumer cursor. This release has no email, pager,
dashboard controls or delivery acknowledgments; terminal output is not a guarantee
that a person received a notification. Wire a customer-owned local alert consumer
before relying on unattended operation in production.

Cases, deadlines, review decisions, stop state and notices survive restart. An
interrupted executing case requires inspection and is never blindly retried.
Completed/rejected/reverted cases are not automatically rearmed by repeated
telemetry for the same incident identity; subsequent activity needs human review.

## Validation and limits

Model inference runs separately from the scheduler, with priority-ordered jobs.
`--l2-review-seconds` sets the reasoning/challenge budget (10–180 seconds,
default 90); it does not change response policy timers. A pending review does not
delay deadline notices, but no action is authorized until a valid review exists.
Model failure preserves the human escalation. This is not an emergency response
guarantee when inference, telemetry, OS permissions or the agent are unavailable.
Shutdown stops the scheduler; OS expiry remains independent.

The CLI scheduler drains unseen escalations in priority-ordered batches of 100
and refreshes pending cases. Backlog progress persists across restarts; queue
delay must still be monitored before fleet deployment. There is no
arbitrary evidence-request executor, account disabling, file deletion, process
termination or broad host isolation.

Tests cover deadlines, severity upgrades, stale evidence, invalid model output,
policy denial, acknowledgement limits, rejection, emergency stop persistence,
interrupted execution, failed actions and revert. The packaged Linux namespace
test (`tools/smoke_agent_linux.py --l2`) uses synthetic authentication records
and fixture responses passed through the real independent L2 engine and
guardrails with real nftables enforcement. It verifies
blocked traffic, preserved management traffic, notice persistence and restored
connectivity after revert. Tests also cover fabricated citations, changed targets,
cross-host/account/peer records, replay, cloud aliases, redirects, undersized
models, challenge disagreement and the critical scheduler bypassing a blocked
model. These do not establish larger-model accuracy or Windows native enforcement.
Initial local 36B and 11.9B synthetic reviews timed out at the earlier 30-second
per-call limit and failed closed. An 8B synthetic review also timed out with a
90-second budget. Installed model metadata alone is not a successful reasoning
result; model-serving performance on this host needs resolution before deploying
the general investigation route. No claim of higher accuracy or lower inference
latency than L1 is established. No THM data is used for this work.
