# Arbiter AI: follow an event through the current system

**Qwen3.5:4b is L1. Gemma4:12b is L2. Five decision workers are joined by a
separate CPU report worker.** Only Qwen's successful model escalations enter
L2. Gemma can keep or quiet them; it never receives the incoming stream directly.

This diagram describes the published November 20 source update. The measured
20K checkpoint used the five decision workers; compact replies and the separate
report worker were added afterward and await a real-model retest.

The implementation is on
[`codex/ait-ads-triage-hardening`](https://github.com/Haryshwa29/Arbiter-AI/tree/codex/ait-ads-triage-hardening).
Older releases and the application code on `main` can predate this design.

[Latest results in plain English](https://github.com/Haryshwa29/Arbiter-AI/blob/90798fe744d1b96ddfaa0fcab3f1412b7fcbf9c6/docs/PROGRESS-2026-11-20.md) ·
[Full report and raw data](https://github.com/Haryshwa29/Arbiter-AI/blob/90798fe744d1b96ddfaa0fcab3f1412b7fcbf9c6/evals/2026-11-20-20k-checkpoint/README.md) ·
[Static diagram](https://github.com/Haryshwa29/Arbiter-AI/blob/90798fe744d1b96ddfaa0fcab3f1412b7fcbf9c6/docs/architecture/STILL.md) · [Technical component map](https://github.com/Haryshwa29/Arbiter-AI/blob/90798fe744d1b96ddfaa0fcab3f1412b7fcbf9c6/docs/ARCHITECTURE.md)

## The complete flow

![Current flow: source evidence and saved queue, gateway, L1 rules and Qwen, L2 pre-filter, independent Gemma, shared final checks, saved decision, separate CPU reports and authenticated dashboard. Side routes skip unnecessary model work; scoped memory supports eligible live repeats.](https://raw.githubusercontent.com/Haryshwa29/Arbiter-AI/90798fe744d1b96ddfaa0fcab3f1412b7fcbf9c6/docs/architecture/arbiter-flow.gif)

The moving dots illustrate software routes. They do not show live activity,
speed or how often a route is taken. **Blue** organizes evidence and rules,
**purple** marks AI review, **gold** marks checks/report work and **green** marks
supported quieting or bounded repeat memory. Both final outcomes keep a record.

## 1. Intake: preserve the evidence

Enabled collectors read security logs and keep the original source details.
Uploaded practice records use isolated demo/replay state. Events are checked,
normalized and saved in a durable SQLite waiting line before review. An event
is an observation; it is not automatically an alert.

The gateway worker selects an event, links nearby clues and adds relevant
local facts. It distinguishes recorded evidence from approved business context.
A fact about a different user, process or time window cannot explain this event.

Pending work can recover after restart. The queue has a limit; overload must be
visible. Checkpointed collectors and HTTP ingestion have their own retry/error
behavior. UDP can lose packets. See [ingestion limits](https://github.com/Haryshwa29/Arbiter-AI/blob/90798fe744d1b96ddfaa0fcab3f1412b7fcbf9c6/docs/INGESTION_ARCHITECTURE.md).

## 2. Triage: decide with evidence

| Worker | What happens | What can leave this stage |
|---|---|---|
| **1 — Gateway** | Load a saved record and connect relevant clues. | A prepared event for L1. |
| **2 — L1 rules + Qwen3.5:4b** | Safety rules flag protected risks; quick rules settle supported clear cases. Qwen reviews unclear events locally. | Only a successful Qwen model escalation enters L2. Other results go to final checks. |
| **3 — L2 pre-filter** | Independently check whether Qwen's warning has a supported routine explanation. | An eligible suppression goes to final checks. Unresolved cases, including missing context, go to Gemma. |
| **4 — Gemma4:12b** | Read original facts without Qwen's opinion text. Return a short decision, competing explanations, gaps and supplied evidence IDs. | Keep the warning, or propose suppression with a separate checking call and at least 90% stated confidence. |
| **5 — Shared final guardrail** | Check L1 and L2 exits, including pre-filter shortcuts and human rejection. | Keep visible for investigation or quiet with a recorded reason; save the outcome and queue report work. |
| **6 — CPU report worker** | Format saved facts and reasons using six local templates, with no AI call. | A saved explanation, independent of decision completion. |

Mandatory safety-rule warnings do not enter Gemma's queue. A failed Qwen call
stays flagged and bypasses L2. L1 warnings remain visible while L2 is pending.
Gemma's checking call is a second pass by the same model; retain-only decisions
can skip it. It is not an independent third brain.

**The corrected L2 route matters:** the early sequential replay could retain
context-poor warnings before Gemma read them. In the current five-worker route,
the L2 pre-filter suppresses a supported routine case or passes an unresolved
escalation to Gemma. Protected risk is still enforced at the final exit.

Security checks run before and after model decisions. A narrow standing fact
can route certain safety-rule matches to model review, but it cannot suppress
them by itself. Known-risk vetoes, invalid evidence, insufficient confidence
and failed reviews keep warnings visible. Model confidence and valid citations
do not establish a correct judgement: the latest checkpoint still missed one
attacker-associated session. See [the findings](https://github.com/Haryshwa29/Arbiter-AI/blob/90798fe744d1b96ddfaa0fcab3f1412b7fcbf9c6/docs/PROGRESS-2026-11-20.md).

### Decisions finish before reports

L1 and L2 save their actual input context and decision receipts. Gemma's new
compact reply uses IDs selected from supplied facts, reducing the need to retype
field names and values. It still explains ordinary and suspicious interpretations.

After the final decision is saved, a durable job goes to the separate CPU worker.
Six templates cover authentication, web, network, software/update, process and
generic events. Templates combine recorded evidence, saved reasons, uncertainty
and clearly labelled manual checks. They do not fill gaps with invented facts.

The dashboard can show partial facts during review, then a completed decision
while its report is pending, then the final report. Slow or failed report writing
does not change that decision. Jobs recover after restart; a report from an older
revision cannot replace a human's newer correction. See
[implementation and tests](https://github.com/Haryshwa29/Arbiter-AI/blob/90798fe744d1b96ddfaa0fcab3f1412b7fcbf9c6/docs/DECISION-REPORT-WORKER.md).

### Remember routine repeats, within limits

Qualifying live Qwen suppressions teach L1's pre-filter. Qualifying live Gemma
suppressions teach L2's pre-filter after the checking pass and final gates.
A later exact match can avoid the corresponding model call, recording the
original model, event, reason and template rather than claiming a fresh review.

Matches are scoped to host/source identity, event content, model and environment.
They expire after **one hour or 25 matches**, cannot renew themselves and can be
revoked. Native process cases retain stricter history requirements. No broad
host allowlist is created. File/API/demo/replay records cannot teach or use
these live shortcuts. The latest measured checkpoint had zero learned hits;
benefit on that run was not demonstrated. See [pattern memory](https://github.com/Haryshwa29/Arbiter-AI/blob/90798fe744d1b96ddfaa0fcab3f1412b7fcbf9c6/docs/LEARNED-PATTERNS.md).

## 3. Review: explain before asking for action

The authenticated dashboard reads through the API; it never invokes the brain
directly. Event details show source evidence, L1's original decision, L2's review,
the final classification and report status. Data Sources exposes worker health,
waiting lines, errors and learned-pattern counts. Existing L1 audit totals and
final L2 outcomes remain distinct.

An administrator can reject an L2 suppression and keep the warning visible.
That rejection wins over a later model reply and revokes its matching shortcut.
Marking a record reviewed is separate from declaring it benign or executing a
response. Reports should explain what happened, where, what is unknown and what
manual checks are useful.

This final-review preset cannot authorize commands or device changes. Supported
native response modes use separate permission, fresh-evidence, exact-target,
expiry and verification gates. Recommended prose is never executable authority.
See [L1 response](https://github.com/Haryshwa29/Arbiter-AI/blob/90798fe744d1b96ddfaa0fcab3f1412b7fcbf9c6/docs/L1-RESPONSE.md), [L2 response](https://github.com/Haryshwa29/Arbiter-AI/blob/90798fe744d1b96ddfaa0fcab3f1412b7fcbf9c6/docs/L2-RESPONSE.md) and
[monitoring and demo boundaries](https://github.com/Haryshwa29/Arbiter-AI/blob/90798fe744d1b96ddfaa0fcab3f1412b7fcbf9c6/docs/DEVICE_MONITORING_AND_DEMO.md).

## 4. Boundaries: keep reasoning and authority separate

### Qwen3.5, replacement models and Ollama

**Qwen3.5:4b** and **Gemma4:12b** are model names. **Ollama** is the current local
runner that loads their weights and serves requests. Either brain can use a
compatible local replacement meeting its role's checks; the two roles require
distinct models, and replacement quality must be evaluated again. Another
serving system needs a compatible adapter. L2 is explicitly configured, not
automatically enabled by publishing a source update.

### Local, integrated and planned systems

| Boundary | What it means |
|---|---|
| Customer inference | Local models and local saved evidence; no cloud inference. |
| Customer dashboard | Self-hosted assets, authenticated operational APIs, CSRF/role checks and no analytics or runtime CDN. |
| Optional AWS acquisition | Enabled readers contact configured AWS APIs to fetch telemetry. This does not enable cloud reasoning. |
| Local Demo & Replay | Isolated practice state and simulated responses; no device actuator. |
| Separately authorized public simulator | Its own consent/cloud boundary; cannot change a customer's device. |
| Public landing | Static copy, zero authenticated API calls, off by default on customer installs. |
| Planned controller/edge design | Future authenticated remote telemetry and typed response channel; not a shipped fleet-protection claim. |

## Work distribution and what remains to test

Five decision workers overlap different records; the CPU report worker runs
independently. These are worker threads, not five copies of the models. A full
L2 waiting line eventually slows upstream work, and both models share local
inference resources. The gateway and ordinary single-brain mode have different
worker arrangements. See [queue limits and recovery](https://github.com/Haryshwa29/Arbiter-AI/blob/90798fe744d1b96ddfaa0fcab3f1412b7fcbf9c6/docs/FIVE-WORKER-PIPELINE.md).

The measured checkpoint processed **41.83 records/min overall**, including quick
rule decisions. Its valid L2 model reviews averaged roughly **34s**, while the
L2-routed ingestion-to-final path averaged **36m 09s** because of waiting.
The compact-decision/report update needs a fresh real-model test to establish
its effect on queue delay, quality and GPU stability. No new latency result is
implied by the diagram.

## Maintain this walkthrough

The [local renderer](https://github.com/Haryshwa29/Arbiter-AI/blob/90798fe744d1b96ddfaa0fcab3f1412b7fcbf9c6/tools/render_unified_architecture.py) builds the SVG,
PNG and animated GIF using installed Pillow and local fonts. It downloads
nothing; Pillow is a documentation tool, not an Arbiter runtime dependency.
Update this explanation, [the still edition](https://github.com/Haryshwa29/Arbiter-AI/blob/90798fe744d1b96ddfaa0fcab3f1412b7fcbf9c6/docs/architecture/STILL.md) and the
[architecture map](https://github.com/Haryshwa29/Arbiter-AI/blob/90798fe744d1b96ddfaa0fcab3f1412b7fcbf9c6/docs/ARCHITECTURE.md) when the implemented route changes.
