# Arbiter AI: follow an event through the system

**A picture of what happens at each stage, with plain-English explanations.**

Read from top to bottom: gather security reports, keep the evidence, decide what
needs attention, and explain the next step to a person. Separate approval and
safety checks control any supported device action. The moving dots show the
route through the software; they are not live traffic or measured speed.

**Qwen3.5:4b is L1, the first reviewer. Gemma4:12b is L2, the final reviewer of
alerts Qwen escalates. Both can be replaced with compatible local models.**
Gemma never receives the incoming stream directly. Separate L2 guardrails and a
pre-filter settle clear cases or avoid a repeat model review when needed context
is missing. Gemma reads original facts without Qwen's opinion text and can keep
or suppress an alert with a written reason. Pending, uncertain or failed reviews keep the
warning visible. Neither model can authorize a device change in this preset.

**Prefer no motion? [Read the identical still-diagram edition](architecture/STILL.md).**
The explanations below also provide a complete text equivalent. The GIF and SVG
assets live in this repository; no external diagram service or runtime script is
needed to view this document on GitHub.

For the public-data results, read [what failed, what improved and what we plan
to test next](FINDINGS-IN-PLAIN-ENGLISH.md).

## The complete flow: intake and triage together

![Collection, evidence and rules lead to Qwen L1; only Qwen's escalations reach Gemma L2. Gemma confirms or suppresses them after a separate challenge, with written reasons and both reviews preserved. Mandatory safety warnings bypass L2; failed or uncertain reviews retain the alert.](architecture/arbiter-flow.gif)

Read downward along the center when an event is unclear. Follow the side arrows
when the rules can decide sooner. **Blue** gathers and organizes information;
**gold** marks a question; **purple** is the local AI; **green** keeps a quiet
observation; **red** asks a person to review. Both outcomes keep a written record.

## What each numbered stage means

| Stage | What is happening | Why it matters |
|---|---|---|
| 01 — Read security reports | Read logs and alerts from sources you enabled. | Arbiter starts with recorded observations, not a story invented by AI. |
| 02 — Organize and check | Put computer, user, time and network details in a common format. | Important information should survive the handoff; broken records are rejected. |
| 03 — Save a waiting line | Save events while they wait to be examined. | A restart can recover waiting work, and overload is visible. The line has a limit. |
| 04 — Connect clues | Look at nearby events, the computer's role, previous decisions and approved facts. | One event can be misleading. A fact about a different account or action should not excuse it. |
| 05 — Apply safety rules | Ask whether a recorded risky signal requires review. | The AI cannot simply dismiss a protected finding. A warning does not prove a breach succeeded. |
| 06 — Use quick sorting rules | Decide clear cases without asking the AI. | Routine observations can stay quiet; clearly risky events can be flagged promptly. |
| 07 — Ask Qwen3.5:4b | Have the first local model read an unclear alert and explain its recommendation. | Another compatible local model can replace it but needs its own evaluation. |
| 08 — Check the AI answer | Check its format, confidence and consistency with the safety rules. | An AI failure or a recommendation that is too uncertain goes to human review. These checks do not guarantee a correct judgment. |
| 09 — Save the decision | Keep the reason, evidence, history and which rule or model decided. | A person can inspect the decision and correct it later. |
| 10 — Explain the next step | Show what happened, where it came from, what is unknown and what to check. | Advice helps a person investigate; it does not authorize changes to a computer. |
| 11 — Apply separate L2 rules | Check only Qwen's escalations for known risk, exact human-corrected context and missing investigation context. | Resolve supported cases without inference; retain unresolved protocol/login warnings without paying for a repeat opinion. |
| 12 — Ask Gemma4:12b when useful | Read original facts independently, then challenge the proposed decision. | A model suppression needs a written reason, checked facts, confidence of at least 0.9 and an accepted challenge. |
| 13 — Apply shared final guardrails | The same suppression veto protects L1 and L2 exits, including shortcuts. | A known risk overrides quieting. Preserve which layer proposed and decided; no device action rights. |

The shared policy runs at each stage's exit. L1 shortcuts do not wait for Gemma;
the diagram joins the routes to show that they use the same final-check code.

Mandatory safety-rule warnings remain visible and do not enter Gemma directly.
Quiet observations and Qwen-failure policy alerts also bypass L2. The original
single-brain evaluation remains a baseline; the two-brain replay records fresh
Qwen decisions, Gemma's final decisions, missed attack annotations, remaining
warnings, challenges, failures and timing. The source terminal view preserves
both reviews; original ingestion/audit totals remain first-stage evidence.

## Qwen3.5, replacement models, and Ollama

**Qwen3.5 is the model that reads and reasons about the alert. Ollama is the
software currently used to run that model locally. They are different parts.**
The diagram names the models, rather than presenting their runner as the AI itself.
Gemma4:12b is the selected second model. The two-brain source-agent preset is
documented in [the second-brain setup guide](TWO-BRAIN-SETUP.md).

You can replace Qwen3.5 with another compatible local language model. It must
accept the evidence and return the decision format Arbiter expects. A different
model-serving system can be connected through a compatible backend adapter;
that is separate from selecting a different model. The current implementation
does not make every model or server work automatically. Each replacement needs
quality, speed and hardware testing. Customer inference stays local, and the
same safety and approval checks remain in place.

The following sections keep the implementation details for readers who want to
check the diagram against the code.

## 1. Intake: preserve the evidence

### Sources produce observations, not verdicts

Host tools and collectors read Windows event logs, Sysmon, Defender findings,
osquery, supported network logs, device attachments, and local process context.
Optional AWS readers retrieve configured CloudTrail or GuardDuty sources through
the optional SDK. These integrations have different permissions, coverage and
delivery guarantees; listing a source does not imply that it is enabled or that
its transport has been validated in every environment.

Collection is outside the triage engine. A collector does not ask the model to
classify an event, run a response, or grant itself trust. The registry tracks
enabled sources and checkpoints. Local discovery respects explicitly disabled
sources. [Connector reference](CONNECTORS.md) · [tool integration](SECURITY_TOOL_INTEGRATIONS.md).

### Normalize once, retain the original

Adapters produce `SecurityEvent` v1.0: event identity, source, UTC timestamps,
host, account, severity, network/process/file fields and bounded metadata.
Validation rejects unsupported schema versions, invalid values and events above
256 KiB. The original payload remains available for inspection.

Source provenance matters. Imported data cannot make itself a trusted native
security finding by supplying a convincing-looking field. Event text and model
output are evidence to inspect, never instructions to execute.

### Queue durably, select cheaply

The SQLite ingestion store uses WAL, identity deduplication and persistent
checkpoints. Its pending/processing capacity defaults to 10,000 records. Queue
pressure is visible: supported checkpointed collectors retry and HTTP ingestion
can return 429. UDP syslog can lose packets; it has no reliable retry guarantee.

One analysis worker claims events. Urgency normally wins; one in 100 claims uses
FIFO ordering so older work can progress. Indexed ID selection loads only the
chosen event's large payload. This reduces time spent holding the shared database
lock; it does **not** make the queue unlimited or eliminate inference backlogs.

On restart, interrupted processing returns to pending. A recorded audit verdict
can be reused. Delivery is at least once: a crash between history and audit writes
can duplicate memory history. Arbitrary failed events are not silently retried.

### Add context before entering the brain

The worker updates observed assets, correlates a bounded recent event window,
and supplies related-event IDs. It adapts the normalized record to the stable
`Event` contract in `arbiter/schema.py`. Observed inventory is different from
curated business criticality or an administrator-approved environment fact.

**Code:** [collectors](../arbiter/ingestion/collectors),
[normalization](../arbiter/ingestion/schema.py),
[queue](../arbiter/ingestion/store.py),
[worker](../arbiter/ingestion/pipeline.py),
[correlation](../arbiter/ingestion/correlation.py).

## 2. Triage: decide with evidence

In the combined diagram above, stages 05–08 expand the decision path. The
outside shortcut arrows show direct decisions: a guardrail escalation skips the
prefilter and model; a decisive prefilter skips the model and its answer check.

### Guardrails establish the review floor

Before model inference, code checks recognized classes such as credential access,
privilege expansion, download-and-execute, integrity changes, exfiltration,
dangerous system-tool use, ransomware patterns and trusted high-priority findings.
A match normally returns a guardrail escalation immediately, with a reason code.

There is a narrow implemented exception: a standing environment fact explicitly
naming the host and dangerous marker can route certain guardrail matches to
model review. It cannot suppress the event by itself or send it to cheap
prefilter suppression. Other guardrails still apply.

### Spend inference only on ambiguity

The prefilter combines severity, asset criticality and verdict history. Trusted
routine profiles can be handled cheaply; strong suspicious signals escalate
without a model call. An unfamiliar or ambiguous event goes to local reasoning.
Low severity alone is insufficient justification for suppression.

The model receives bounded context and scope-checked facts. A fact about one
process, account or time window must not explain unrelated activity. Learning
is stored context and reviewed history; Arbiter does not fine-tune model weights.

### Validate the answer rather than trusting fluent prose

Qwen3.5, or another compatible local model, returns a proposed decision, confidence, rationale, evidence and
optional bounded investigation steps. The parser validates the decision and
finite confidence. The engine rechecks guardrails. Suppression confidence below
0.7 becomes an escalation; model failure also escalates by policy.

The model cannot invoke a shell or authorize a device response. A plausible
explanation is not proof. Larger models and code-checked citations still need
evaluation against real operating conditions.

### Store an auditable decision

An escalation carries evidence; a suppression carries a written rationale.
Decisions update memory history and the JSONL trail; the worker persists a
queryable audit row and telemetry analysis. Tier and available backend/model
provenance distinguish rule decisions, real inference, test heuristics and
policy fallbacks. Shadow-mode output is recorded as such.

**Code:** [engine](../arbiter/triage.py),
[guardrails](../arbiter/guardrails.py),
[prefilter](../arbiter/prefilter.py), [facts](../arbiter/facts.py),
[local model adapter](../arbiter/llm.py), [memory](../arbiter/memory.py),
[audit store](../arbiter/store.py).

## 3. Review: explain before asking for action

![Vertical operator flow: authenticated API, alert explanation, review, independent deadlines, explicit approval and evidence checks, typed firewall response, verification and undo.](architecture/03-review-response.gif)

### The dashboard reads through an API

The React dashboard uses one API client. Operational APIs require a session;
state-changing requests use double-submit CSRF protection. Privileged controls
check the administrator role. The explicitly configured local-owner mode is
restricted to loopback and local Host/Origin checks. SSE publishes new audit
verdicts, while event views query the durable read model.

The frontend never invokes the triage engine directly. Static assets, fonts and
scripts are self-hosted. There is no runtime CDN, analytics or telemetry service
in the customer dashboard.

### An alert must answer four questions

1. **What triggered?** The recorded decision and, for the system-tool guardrail,
   the binary and command markers actually found in the event text.
2. **Where did it originate?** Executable, parent executable, account, command
   and parent command when recorded; missing values are explicit.
3. **What remains unknown?** Initiating application, authorization, provenance,
   signature verification or other evidence gaps.
4. **What should I do?** Bounded manual investigation steps, labelled as model
   advice or policy guidance rather than executable authority.

For example, a `conhost.exe` event whose parent PowerShell command contains
Arbiter's inventory script can explain that `-nop` matched inside `-NoProfile`.
The matching script is a benign-origin clue; it does not prove who launched it
or automatically bypass security checks. Historical telemetry receives this
read-only explanation without rewriting the stored verdict.

### Review is separate from classification and execution

Acknowledgement records who reviewed an audit row. It does not mark it benign,
kill a process, or remove a rule. Confirm/overrule feedback affects matching
history; signature-wide feedback can cover more than the individual row.
Recommended steps are advisory prose and are never parsed into shell commands.

### Deadlines do not create authority

An independent L1 scheduler persists review cases. Default windows are critical
60 seconds, high five minutes, medium 30 minutes, and low with no automatic
deadline. Severity comes from source severity and deterministic findings, not
model confidence. Default expiry marks a case overdue without changing a device.

An administrator can explicitly approve a supported temporary response or enroll
one eligible incident for a timed peer block. Timed execution requires fresh,
independently supported evidence, an unchanged exact target, permitted scope,
protected management/service networks, capacity and native checks. Stale evidence
or a failed check requires human review. The recommendation never authorizes
itself. Deferral, rejection and emergency stop are persisted separately.

### Execute narrowly, then verify

Supported native peer blocks use a fixed typed operation with a five-minute,
OS-owned expiry. Native rule checks and removal checks are recorded. Windows
firewall and Linux nftables support differ by runtime and scope; a verified rule
does not establish that every attacker flow was stopped.

Undo removes the relevant rule where supported; it cannot restore interrupted
connections or reverse downstream effects. Expiry due and verified cleanup are
different states. No general-purpose remote shell is exposed by the model.

**Code:** [API](../arbiter/api/server.py), [IAM](../arbiter/iam.py),
[alert explanation](../arbiter/ingestion/recommendations.py),
[event drawer](../frontend/src/components/EventPanel.tsx),
[response workflow](../arbiter/ingestion/response_workflow.py),
[native protection](../arbiter/ingestion/protection.py),
[scope](../arbiter/ingestion/containment.py).

## 4. Boundaries: keep reasoning and authority separate

![Vertical optional L2 flow: agent escalation, independently rebuilt dossier, separate local investigation and challenge, policy gate; separate customer/public deployment boxes and a clearly planned remote controller/edge target.](architecture/04-boundaries.gif)

### Optional L2 belongs to the terminal agent

The selected Qwen/Gemma preset uses **independent final alert review**. Only successful Qwen
escalations enter the separate L2 pre-filter. Known risk stays flagged. Exact
human corrections can settle routine process activity; broad history and the
model's own earlier answers cannot. Isolated protocol/login records without
useful extra context stay flagged without a model repeat. Cases needing model
judgment reach Gemma without Qwen's opinion text. Separate local transport requests a fixed response
format; code then validates copied fact values, citation IDs and the proposed
decision. Gemma assesses and challenges it. It returns one classification; the
compatibility outlook is derived. Suppression needs confidence of at least 0.9,
an accepted challenge and the shared final veto to pass. Internal thinking
is off; written hypotheses and challenge remain visible. An uncertain, invalid or
unavailable review retains the warning. These checks do not certify conclusions.
Each completed decision belongs to its exact event, so a newer event cannot
inherit an older event's suppression.

The stricter native response mode described below remains separate. Historical
Wazuh/public replay records are not accepted as fresh native containment evidence.

L2 is off by default and explicitly configured with a distinct local model.
Metadata must report more than four billion parameters; no model is downloaded
automatically. It has independent inference transport, evidence selection,
investigation, challenge and recommendation validation. It does not reuse L1's
model engine or accept L1 prose as action proof.

The bounded dossier uses up to 64 local records and code-assigned fact IDs.
Evidence checks reject stale, untrusted, duplicate, replayed and cross-host action
support. L2 returns assessment, evidence, gaps, recommendation, alternatives,
recovery and urgency. Its action vocabulary is human review or the supported
exact peer block. Advice-only is the default.

Unattended action needs explicit local policy and containment scope. A supported
critical deterministic fast path can bypass inference queues while preserving
the policy and executor gates; deeper review follows. A contradictory follow-up
is recorded and can stop a pending recommendation. This is a separate agent
workflow, not an automatically enabled second dashboard model.

### Customer installation and public demonstration are separate

| Boundary | Implemented behavior |
|---|---|
| Customer inference | Qwen3.5 or another compatible local model. The current runner is Ollama; cloud model aliases are rejected. No external inference calls. |
| Optional AWS acquisition | Explicit source integration; contacts configured AWS APIs to retrieve telemetry. This is different from cloud inference. |
| Local Demo & Replay | Isolated state and simulated responses; no native actuator. |
| Public site simulator | Separately authorized cloud-AI exception with consent for uploaded samples; server-only credentials and simulated response controls. |
| Public landing | Static copy; no customer verdicts, hosts, counts or authenticated API calls. Off by default in customer installs. |
| Packaging | Readable Python zipapp + bundled dashboard; boot service owns lifecycle and preserves databases on upgrade. |

### Planned remote architecture is not a shipped channel

The [controller + trusted edge design](BREACH_CONTAINMENT_ARCHITECTURE.md)
describes authenticated remote telemetry, signed typed action requests and
edge enforcement. It is a target architecture. The current local agent and its
native adapters do not establish that the distributed controller/edge channel
or fleet-wide containment has shipped or been validated.

**Code:** [terminal agent](../arbiter/agent.py), [L2 engine](../arbiter/l2.py),
[L2 pre-filter](../arbiter/l2_prefilter.py), [independent final review](../arbiter/l2_final_review.py),
[shared final guardrail](../arbiter/guardrails.py),
[dossier](../arbiter/l2_evidence.py), [L2 policy](../arbiter/l2_workflow.py),
[L2 validation](../arbiter/l2_guardrails.py),
[public demo backend](../arbiter/site_cloud.py), [installer](../arbiter/install).

## State ownership at a glance

| State | Owner | Why it is separate |
|---|---|---|
| Raw/normalized events, checkpoints, queue, observed assets | Ingestion SQLite store | Collection and recovery do not depend on the model. |
| Assets, scoped facts, verdict history, feedback | Memory SQLite store | Context can be inspected; no weight training is hidden. |
| Verdicts, reviewer identity, IAM/action audit records | Audit SQLite store + JSONL trails | Decisions and operator changes remain attributable. |
| Accounts, roles, sessions and persisted signing secret | IAM store + local secret | Authentication survives restart without exposing data publicly. |
| Review cases, deadlines, stop state, action records | Response workflow tables in local state | Inference delays do not own authority or erase deadlines. |
| Demo state | Isolated local stores or browser simulation | Demonstrations cannot act on the monitored device. |

## What the diagrams do not promise

This is a pre-release implementation map, not a capacity or security certification.
One worker and bounded queues can accumulate backlog; UDP is lossy; correlation
windows can miss late signals. Native rule verification is narrower than proof
of breach containment. Real-model quality, production-scale delivery and remote
fleet enforcement require their own validation. See
[ingestion limits](INGESTION_ARCHITECTURE.md), [L1 response](L1-RESPONSE.md),
[L2 response](L2-RESPONSE.md), and [validation notes](AGENT-LIVE-VALIDATION.md).

## Maintain this walkthrough

The combined diagram is generated by
[`tools/render_unified_architecture.py`](../tools/render_unified_architecture.py).
The supplementary review and boundary diagrams use
[`tools/render_architecture.py`](../tools/render_architecture.py). Run either with
Python and Pillow installed locally to rebuild the repository-owned GIF, PNG
and SVG assets. Pillow is a documentation build tool, not an Arbiter runtime
dependency. The renderer downloads nothing. Update the explanations and still
edition alongside the diagrams when an implementation boundary changes.
