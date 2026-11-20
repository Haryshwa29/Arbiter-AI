# Arbiter AI

**Two local AI reviewers. Fewer unnecessary warnings. A reason saved for every decision.**

Arbiter helps a small team sort security events into **keep visible for investigation**
or **quiet with a recorded reason**. Qwen3.5:4b is the first reviewer (**L1**).
Gemma4:12b is the second reviewer (**L2**) and sees only alerts Qwen escalates.
Quick rules handle clear cases, safety checks protect the final decision, and
customer inference stays local.

**Latest publication — 20 November 2026:**
[Plain-English progress tables](docs/PROGRESS-2026-11-20.md) ·
[Full report and raw results](evals/2026-11-20-20k-checkpoint/README.md) ·
[GitHub findings](https://github.com/Haryshwa29/Arbiter-AI/issues/13) ·
[Current architecture](docs/ARCHITECTURE.md)

**Available on [`main`](https://github.com/Haryshwa29/Arbiter-AI/tree/main):**
the code, reports and architecture described here are merged together. Existing
releases and installed builds may predate this update.

## What changed, and why it matters

| What a reader wants to know | Initial published run | Latest measured checkpoint | Practical impact |
|---|---:|---:|---|
| How much was tested? | 26,002 records | **20,002 saved decisions** | The new run completed 76.93% of its planned 26,000 records. |
| Were attack-labelled records included? | None | **17,305** | The new checkpoint tests labelled attacks alongside unannotated activity. |
| How many attack records stayed flagged? | Not measured | **17,304 / 17,305 — 99.994%** | One attack-labelled account/session record was wrongly quieted. |
| How much unannotated activity was quieted? | **57.52%** | **89.95%** | About **575 → 900 per 1,000** unannotated records stayed quiet. |
| How many of Qwen's unannotated warnings did L2 remove? | **0.35%** | **64.67%** | L2 removed **496 of 767** such warnings in the new checkpoint. |
| How quickly did the whole replay progress? | **29.84 records/min** | **41.83 records/min** | The observed overall rate was **40.20% higher**, including quick rule decisions. |
| How long did each saved checkpoint take? | **14h 31m 28s** | **7h 58m 09s** | These are the actual elapsed times for the record counts above. |

**In everyday terms:** L2 now does useful filtering. It quieted almost two-thirds
of the unannotated warnings passed up by L1, while the full pipeline kept
17,304 attack-labelled records visible. **Unannotated** means the dataset publisher
did not attach an attack label; it does not independently prove the activity benign.

### Which attacks were correctly flagged?

The public source is the [AIT Alert Data Set v1](https://zenodo.org/records/8263181),
using the Fox scenario. It contains alerts and logs from a simulated organization,
including ordinary activity and publisher-labelled attack activity. This checkpoint
contains web scans, password guessing, attacker-associated account/session activity
and privileged attack-phase commands.

| Attack type | Correctly flagged / tested | Correctly flagged |
|---|---:|---:|
| Web directory scanning | 17,293 / 17,293 | **100%** |
| Online password guessing | 2 / 2 | **100%** |
| Attacker-associated account/session activity | 2 / 3 | **66.67%** |
| Privileged attack-phase commands | 7 / 7 | **100%** |
| **Full pipeline** | **17,304 / 17,305** | **99.994%** |

Most attacks were repeated web scans. Rules retained **17,300** attack records;
**five reached the models and four stayed flagged**. The headline percentage
describes the whole system; the small account/session sample shows where the
next reasoning tests matter most.

### What still needs work?

| Finding | What happened | Next step |
|---|---|---|
| One attack was quieted | Qwen flagged an attacker-associated session; Gemma accepted an ordinary explanation, and its checking pass and final rules did not stop it. | Test authorized and malicious session lookalikes with stronger supporting context. |
| Some model replies failed | **13 processing failures** left the affected alerts visible. Three consecutive failures stopped the run at 20,002 records. | Retest the new evidence-ID reply format and investigate GPU memory headroom. |
| L2 built a backlog | The L2-routed path averaged **36m 09s** from ingestion to final decision, including waiting; maximum **40m 59.55s**. | Measure queue delay alongside model time after the compact-decision update. |
| Repeat shortcuts did not help this run | **Zero L2 pre-filter suppressions and zero learned-pattern hits.** | Investigate eligible matches and test safely scoped repeat avoidance. |

Arbiter's policy is to **keep suspicious activity visible when there is not enough
evidence to quiet it safely**. A missed attack is a false negative. More context
should reduce unnecessary warnings without weakening that policy.

## The current project design

**Five decision workers + one separate CPU report worker.** Different stages can
work on different records at the same time. This is one L1 model and one L2 model,
with bounded waiting lines between stages.

[![Current Arbiter design: saved events pass through gateway, L1 rules and Qwen3.5:4b. Only successful Qwen escalations enter the L2 pre-filter and, when unresolved, Gemma4:12b. All exits pass shared final checks. A separate CPU worker prepares reports from saved decisions.](docs/architecture/arbiter-flow.svg)](docs/ARCHITECTURE-WALKTHROUGH.md)

| Stage | What happens in plain English | Why it helps |
|---|---|---|
| **1. Gateway** | Selects a saved event, organizes its evidence and connects nearby clues. | Review starts from recorded evidence; pending work can recover after restart. |
| **2. L1: rules + Qwen3.5:4b** | Quick rules handle clear cases. Qwen reviews unclear activity and can quiet it or raise a warning. | Expensive AI work is reserved for cases that need it. |
| **3. L2 pre-filter** | Checks Qwen's escalations for a supported routine explanation. It quiets an eligible case or sends it to Gemma. | L2 has its own rules; missing context alone does not prevent Gemma from reading an escalation. |
| **4. L2: Gemma4:12b** | Reviews original facts independently and proposes keeping or quieting the alert. A proposed suppression requires a separate checking call. | Gemma can overrule Qwen, with evidence and safeguards. |
| **5. Shared final guardrail** | Checks both L1 and L2 exits, including shortcuts, and saves the final result. | Failed reviews and protected risks keep the warning visible. |
| **6. CPU report worker** | Uses saved facts and six local templates to prepare the longer explanation. It makes **no AI call**. | Report writing can finish after the decision; it does not hold Gemma's decision queue. |

**Gemma never receives the incoming stream directly.** Only successful Qwen
model escalations enter L2. Rule-mandated warnings, failed Qwen calls and quiet
L1 decisions bypass Gemma and still pass final checks. Warnings remain visible
while L2 is working. A proposed Gemma suppression needs at least **90% stated
confidence**, an accepted checking pass and the final rules; confidence is not
a verified probability of correctness.

**Models are replaceable.** Qwen3.5:4b and Gemma4:12b are the evaluated pairing.
Either can be swapped for a compatible local model that meets its role's checks
and is evaluated again. **Ollama is the current runner**, the software that loads
the models. Another serving system needs a compatible adapter.

**Memory avoids eligible repeat work.** Each brain can teach its own pre-filter
an exact, safely suppressed live pattern. Matches are tied to the host, source,
content, model and environment, expire after **one hour or 25 matches**, and can
be revoked. A changed event needs normal review. Uploaded/demo/replay records
cannot teach or use these live shortcuts. This is saved local memory, not model
retraining or a blanket exemption for a host.

[Architecture and component map](docs/ARCHITECTURE.md) ·
[Illustrated walkthrough](docs/ARCHITECTURE-WALKTHROUGH.md) ·
[Worker queues](docs/FIVE-WORKER-PIPELINE.md) ·
[Pattern memory](docs/LEARNED-PATTERNS.md) ·
[Decision/report separation](docs/DECISION-REPORT-WORKER.md)

## Available now and what we test next

**Status: pre-release.** The measured 20K checkpoint used the five decision
workers. The newer compact Gemma replies, saved context receipts, six report
templates and separate CPU report worker are implemented in the published source.
They passed **649 tests and 25 subtests**, frontend builds and **17 frontend checks**.
Their real-model speed and accuracy retest is still next; they are not the cause
of the already measured results above.

The updated dashboard shows partial event facts during review, saved reports
afterward, both reviewers' decisions, queues and worker status. The installed
dashboard and benchmark remain stopped; publishing source does not deploy it.

Next: retest the missed account/session case and evidence failures, replay with
real Qwen/Gemma, measure typical and slowest-case queue/model/report times, then
run the separately planned ten-hour endurance test. The **18–23s L2 model-review
target** versus the measured roughly **34s** is a planning target, not a new result.
Broader attack coverage and sustained GPU stability remain validation work.

## Use Arbiter locally

### From a checkout

Python 3.10+ is required. The core and mock backend need no third-party Python
dependencies. These commands use sample events and do not enable device actions:

```bash
git switch main
python -m arbiter seed
python -m arbiter run samples/events.jsonl
```

For both local models, install [Ollama](https://ollama.com) and obtain the models:

```bash
ollama pull qwen3.5:4b
ollama pull gemma4:12b
```

Then start an explicitly configured two-brain dashboard:

```bash
python -m arbiter serve --backend ollama --model qwen3.5:4b --l2-model gemma4:12b --l2-review-seconds 180
```

For terminal operation, configuration, hardware considerations and separate state
directories, follow [the two-brain setup guide](docs/TWO-BRAIN-SETUP.md).
The simple `arbiter run` command is a single-brain file runner; use the configured
dashboard or terminal final-review preset for the worker pipeline above.

### Dashboard, collectors and replay

The React dashboard reads through the authenticated local API. **Data Sources**
configures collection and shows worker health. **Live Events** links evidence to
the recorded decision. **Demo & Replay** uses isolated practice state and simulated
responses. Customer dashboard assets are self-hosted, with no analytics or CDN.

Implemented collectors include Windows Events, Sysmon, Defender, osquery,
Suricata, Wazuh, private UDP syslog and optional AWS CloudTrail/GuardDuty readers.
Only enabled and permitted sources are collected. Optional AWS acquisition
contacts configured AWS APIs; it does not send events to cloud inference.
Real AWS account validation and production-scale delivery remain future work.

[Live lab](docs/LIVE_LAB.md) · [Connectors](docs/CONNECTORS.md) ·
[AWS permissions](docs/CLOUD_INTEGRATION.md) ·
[Ingestion limits](docs/INGESTION_ARCHITECTURE.md) ·
[Monitoring and isolated demos](docs/DEVICE_MONITORING_AND_DEMO.md)

### Installable builds

Releases use a readable Python zipapp and bootstrap scripts that verify
`SHA256SUMS`. Read the script before running it. Installations start in shadow
mode with response in dry-run; device actions require their separate controls.
Build the customer dashboard with `npm ci` and `npm run build` in `frontend/`,
then run `python tools/build_release.py` from the repository root.

[Releases](https://github.com/Haryshwa29/Arbiter-AI/releases) ·
[Windows installation](docs/WINDOWS-INSTALLER.md) ·
[Portable demo](docs/PORTABLE.md)

## Reports and evidence, newest first

| Publication | What it contains |
|---|---|
| [20 November progress tables](docs/PROGRESS-2026-11-20.md) | Initial-run comparison, correct attack percentages, remaining findings and next tests. |
| [20,002-record checkpoint](evals/2026-11-20-20k-checkpoint/README.md) | Full measured report, downloadable raw results, one missed attack, processing failures and checksums. |
| [Compact decisions and report worker](docs/DECISION-REPORT-WORKER.md) | The implemented source update and its software validation. |
| [Initial 26,002-record checkpoint](evals/2026-11-18-26k-checkpoint/README.md) | The published baseline, with no attack-labelled records. |
| [Arrival simulation](evals/2026-11-18-arrival-simulation/README.md) | Reconstructed waiting under original arrivals; simulation is distinct from observed run latency. |
| [Earlier findings](docs/FINDINGS-IN-PLAIN-ENGLISH.md) | Historical single-brain results and earlier safeguards. |

For full-dataset reproduction, see [the resumable evaluation guide](docs/FULL-PUBLIC-RUN.md)
and [chronological runs](docs/CHRONOLOGICAL-PUBLIC-RUN.md). Dataset labels are
used for scoring, not supplied as model evidence.

## Contributing and safety

The decision engine returns verdicts; collectors, reporting, UI and device
response have separate responsibilities. Classification does not authorize a
block or a command. The [planned controller/edge design](docs/BREACH_CONTAINMENT_ARCHITECTURE.md)
is a future architecture, not a shipped fleet-protection claim.

```bash
python -m pytest -q
python -m unittest discover -s tests -v
python -m arbiter eval
```

[Project vision](CONCEPT.md) · [Architecture](docs/ARCHITECTURE.md) ·
[Private security reporting](SECURITY.md) ·
[GNU Affero General Public License v3.0 or later](LICENSE)
