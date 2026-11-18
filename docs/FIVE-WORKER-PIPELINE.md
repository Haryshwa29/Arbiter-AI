# Five workers: keep each stage moving

The terminal agent's `--l2-final-review` preset now uses five worker threads.
They work on different events at the same time. **Qwen3.5:4b remains L1;
Gemma4:12b remains L2. Only Qwen's successful model escalations enter L2.**
Both models can be replaced by compatible local models and must remain distinct.

This is separate development work. It was not installed into the ongoing
26,000-record checkpoint, nor into the installed/portable dashboard. That
checkpoint still measures one sequential replay worker.

```mermaid
flowchart TD
    Q[Durable waiting line: already normalized source records]
    G[Worker 1 - Gateway: load the next record and connect nearby clues]
    A[Worker 2 - L1: quick rules, Qwen3.5:4b when needed, and L1 safety checks]
    P[Worker 3 - L2 prefilter: check risk and whether enough context exists]
    B[Worker 4 - L2: Gemma4:12b assesses and challenges its decision]
    F[Worker 5 - Final guardrail: check the proposed outcome and preserve both stages]
    V[Show the result: retain uncertainty for review, or quiet a supported ordinary case]
    Q --> G --> A
    A -->|Successful Qwen escalation only| P
    A -->|Quiet, mandatory rule, or failed Qwen| F
    P -->|Model review is useful| B
    P -->|Supported routine suppression only| F
    B --> F --> V
```

| Worker | What it does in everyday terms |
|---|---|
| Gateway | Chooses the next saved event, prepares its evidence and keeps review deadlines visible. |
| L1 | Handles clear cases with rules; asks Qwen about unclear ones. It can continue while Gemma investigates another event. |
| L2 prefilter | Independently quiets a supported routine case; passes unresolved L1 escalations, including missing context, to Gemma. |
| L2 | Gives Gemma the original evidence and bounded security context, without Qwen's written opinion; requires a separate challenge pass. |
| Final guardrail | Checks L1-only exits and L2 outcomes. Unsupported or failed L2 decisions leave the original warning visible. Saves exact event bindings. |

The old replay's `L2_CONTEXT_REQUIRED` shortcut retained warnings before Gemma
could read them. That was a routing mismatch with the requested L1/L2 operation.
This terminal pipeline corrects it: the L2 prefilter either suppresses with a
supported reason or passes the escalation to Gemma. Protected risk is still
enforced by the final guardrail after that review. A risky model suppression
cannot override the veto. Legacy sequential comparison tools retain the old
routing explicitly; do not use their numbers as the upgraded pipeline's score.

The independent prefilter keeps the exact five-human-corrections process rule.
It also recognizes a narrow source-confirmed resolution notification: native
Wazuh rule 23502, `Solved`, one named CVE/package/version, low severity, and no
conflicting risk or correlation. It quiets that notification only; it does not
declare the computer safe or rule out prior exploitation. Active, incomplete,
high-risk and unverified lookalikes are not suppressed. Source semantics:
[Wazuh vulnerability events](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html),
[versioned Wazuh rule definitions](https://github.com/wazuh/wazuh/blob/v4.14.10/ruleset/rules/0520-vulnerability-detector_rules.xml).
These rules do not guarantee that most alerts in the current dataset can be
quieted safely; no suppression quota is used. Richer context is evidence to
check, not permission to invent an ordinary explanation.

This means five **stages**, not five copies of either model. Collectors and
other application duties can have additional threads. Ordinary single-brain,
advice-only and native-response modes retain their existing workers. No new
service, runtime dependency or device-action permission is introduced.

## Waiting lines and visible progress

The gateway reads from the existing durable SQLite buffer (10,000 unfinished
records by default). Only one event waits immediately ahead of L1, keeping
urgent selection close to inference. Each later stage has at most 32 queued
jobs. A full line slows the producer instead of discarding events or growing
memory without a limit. A busy Gemma queue can eventually apply backpressure;
separation is not a promise that L1 can run indefinitely without it.

Enter `status` in the source terminal. `pipeline_workers` lists all five names,
whether each is alive/busy, queued jobs, queue capacity, completed jobs, stage
errors, accumulated queue waiting and occupied milliseconds. Occupied time
includes downstream backpressure; it is not pure model compute time. A record
may bypass stages, so completed counts need not be equal. Existing queue totals
include unfinished records; first-stage audit totals and L2 classifications
remain distinct.

L1 warnings stay visible while L2 is pending. A human rejection wins even if a
model reply arrives later. Each case is tied to one event. A restart recovers
unfinished records and reuses a completed durable L1 verdict instead of asking
Qwen twice. A saved L2 answer is checked again against the current final policy
before reuse. Shutdown waits for active workers before closing their stores;
it can wait for the bounded outstanding model call. No model request grants
permission for a network block, process termination or command.

## What we verified, and what to measure next

Controlled model replies with real queues and temporary stores demonstrated
that L1 progresses while L2 is blocked. Tests also cover final safety vetoes,
model/prefilter/finalizer failures, rejection during inference, pending review
deadlines, model changes, shutdown and restart recovery. These are software
checks, not a public-data accuracy result or a real-GPU speed benchmark.

Five workers do not guarantee a fivefold speedup. Qwen and Gemma share a GPU;
the local inference server may serialize work or reload model weights. Richer
L2 context can increase review time or route more cases to Gemma. Measure the
same frozen records sequentially and through this pipeline, record model
loading, queue delay, per-stage median/95th-percentile latency and throughput,
and check decision quality alongside speed. Then test attack-containing
timelines, ordinary lookalikes and bursts with persistent scoped history.

Start commands: [two-brain setup](TWO-BRAIN-SETUP.md). Context boundaries:
[L2 security context](L2-CONTEXT.md). Historical results stay separate.
