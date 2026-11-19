# Arbiter AI

Self-hosted AI security analyst for small companies with no security team. Read `CONCEPT.md` for the full product vision and `README.md` for how to run the current slice.

## Current state

November 18 integrated upgrade: Qwen3.5:4b L1 and Gemma4:12b L2 now share the
five bounded worker stages in the terminal and explicitly configured dashboard.
The L2 pre-filter suppresses supported routine cases or passes escalations to
Gemma; missing context no longer bypasses L2. Native security/CVE/ATT&CK context
and the shared final gates are integrated. No new dependency or action authority.

Scoped live repeat memory lets each brain teach its own pre-filter exact routine
matches; host/source/raw agent/rule/content/model/environment scope, one-hour or
25-hit lifetime, no self-training, and human revocation are enforced. API/file/
demo/replay inputs cannot teach or use these shortcuts. Native Sysmon process
learning retains the prior five-real-model-assessment requirement. See
docs/LEARNED-PATTERNS.md. No bulk deletion or host-wide model allowlist is added.

Dashboard event/API projections preserve L1 evidence and show L2 final decisions,
pending/failure status and human rejection. Response approval and scheduling use
the final projection: quiet L2 outcomes cannot enter the action flow. Data Sources
shows all five workers, queues/errors, separate L2 outcomes and learned counts.
The second transport accepts only loopback/local inference, including the
installed runtime's private port. New frontend fields reuse existing components;
Magic/ui-ux-pro-max were unavailable, so neither was invoked for these incremental
changes in Data Sources and EventPanel. No new view or runtime dependency was introduced.

The stopped AIT-ADS checkpoint is public at issue #12 and
evals/2026-11-18-26k-checkpoint, frozen at commit 58e30ea: 26,002 records in
14h31m28s; 14,957 quiet, 11,045 retained, zero attack annotations. It did not use
these subsequent upgrades. The shared normalized host label covers 11 raw agent
identities and 22 native rule IDs, not proof of one machine. 57.52% label agreement
is not attack accuracy. Models and cold-start/original-order limits are explicit.

Validation: 587 tests passed, 2 skipped, 25 subtests; frontend build/type check,
lint (two existing Fast Refresh warnings), 17 frontend checks and source/packaged
22-event mock CLI smoke passed. Four seen-record handoffs exercised real Qwen,
four Gemma assessments and four challenges with no worker errors; an earlier
selection quieted at L1 and did not exercise L2. The compatibility archive records
the source-provenance limit and is not a new accuracy/throughput benchmark.
Parallel context uses an ordered partial time index rather than sorting all
matching history. This removes a database wait exposed by the large installed
history, without changing evidence eligibility. The local updater verifies the
release hash, fresh-process readiness, five workers and retained history, with
protected backups and rollback on failure. Existing 30-day telemetry retention
is distinguished from lost unexpired records. Real attack quality and GPU
speedup of the new architecture and learning remain unmeasured.

November 18 follow-up: source hostname precedes Wazuh's generic agent label.
Wrapped network records use an endpoint matching the recorded agent address;
unmatched passive-sensor conversations retain both endpoints with unverified
ownership. Agent address, then name/ID are fallbacks. Raw identity remains intact;
old stored/frozen rows are not rewritten. New keys invalidate earlier host scopes.
Startup decision backfill explicitly uses its existing missing-decision index,
avoiding a full historical scan exposed by installed startup diagnostics.

The owner's arrival-hour capacity calculation is reproduced without inference
in evals/2026-11-18-arrival-simulation. Source span is 57h00m50s. The Jan 16 17:00
hour has 1,683 records, 1,402 Qwen reviews and zero Gemma reviews, costing 125.83
minutes. A virtual single FIFO worker peaks at 103.63 minutes of waiting (record
20,495), 103.73 minutes arrival-to-completion. These are simulated, not observed
queue times or upgraded throughput. The frozen run's largest service cost was
57.07s. No new accuracy claim. The legacy full_public_eval runner does not
benchmark the five-stage live pipeline or warmed learned-pattern memory.

Installed steady-state tracing also exposed the final-review dossier's separate
history query sorting old records under the shared buffer lock. It now uses the
same ordered index and a five-minute lower bound, matching the intended context
window. The older native-response/advisory query retains its existing behavior.
A regression checks the query plan and exclusion of stale records. Overview
totals explicitly say first review; Data Sources tolerates slower large-history
aggregate responses without aggressive repeated requests. No new dependency.

## Earlier checkpoints (historical state at the date written)

November 18 separate five-worker final-review development: the terminal preset
now uses bounded gateway/L1/L2-prefilter/L2/final-guardrail queues and five
threads. Shared preparation/analysis/persistence helpers retain the ordinary
single-worker mode. L2 preparation, model review and final checking are split
without removing format/evidence/confidence/challenge checks. L1 progresses
while L2 waits; pending alerts, human rejection and exact-event bindings remain.
Status exposes stage activity, queues and errors. Shutdown joins writers before
closing stores; restart reuses durable L1 and rechecks saved L2 exits. Model
changes retain the pipeline and require distinct L1/L2 models. No new dependency
or actuation authority. Real-GPU speedup is unmeasured.
The running public checkpoint and installed app remain unchanged. Changes stay
local pending the owner's requested review/explicit GitHub push approval.
The terminal now uses suppress-or-pass L2 routing: insufficient context no longer
skips Gemma. Known risk still vetoes suppression at the final gate. A narrow
Wazuh 23502 Solved-CVE notification rule and exact human-corrected process history
can independently quiet supported routine cases; neither promises a suppression
rate. Legacy sequential comparison callers keep their earlier routing protocol.
Final local validation: 555 tests passed, 2 skipped and 25 subtests passed;
28 focused queue/routing/noise-lookalike checks passed. The packaged stdlib agent
contains the new pipeline and offline catalog and passed the 22-event mock CLI
smoke. No extra real-model inference was run alongside the frozen checkpoint.
See docs/FIVE-WORKER-PIPELINE.md.

November 18 separate L2 context upgrade: native Wazuh/Suricata extraction now
preserves bounded explicit CVE/MITRE IDs, scanner package/version/status and
conversation details. L2 adds at most eight same-host/account/peer native login
events within five minutes, plus relevant offline reference cards (seven
ATT&CK families; CISA KEV 2026.11.17, 1,782 factual entries). Knowledge is not
incident evidence or a product/version applicability verdict. Later KEV listings
are excluded from positive as-of-event claims. No runtime network lookup or new
dependency. Shared final/L2 guards cover repeated failures, active source-reported
vulnerabilities and protocol anomalies not explained by conversation metadata.
The real synthetic development probe exposed two unsupported Gemma suppressions
accepted by its own critic; the protocol-context veto blocks them. No new public
accuracy claim. JSON knowledge is packaged and included in evaluation identity
checks. This branch/worktree is separate: the ongoing full replay and installed
dashboard remain unchanged. See docs/L2-CONTEXT.md and its development evidence.

November 18 full-data replay tooling: `tools/full_public_eval.py` streams all
2,600,263 supported AIT-ADS records through the unchanged Qwen L1/Gemma L2 route,
with independent empty history per record. It uses an isolated SQLite journal,
atomic result/counter checkpoints, recorded interrupted attempts, per-stage
errors, exact input/model/source identity checks and an exclusive worker lock.
It stops on three consecutive model failures. `tools/Start-FullPublicEval.ps1`
starts a hidden resumable worker; STATUS.txt explains partial progress. Windows
system sleep is temporarily prevented while the worker runs. This adds no
runtime dependency, collection or device-action authority and does not upgrade
the installed dashboard. Full input alignment verified 1,771,136 attack-labelled
and 829,127 unannotated records; 55,558 unsupported AMiner records stay excluded.
See `docs/FULL-PUBLIC-RUN.md`. A started run is not a completed full-data result.

November 17 independent L2 correction: the earlier final-review route did not
wire the requested separate L2 noise pre-filter and complete shared final exit.
`l2_prefilter.py` now resolves known risk and exact human-corrected process
context, or retains isolated protocol/login observations without another model
call when useful context is absent. Gemma sees original facts without Qwen prose
and returns one classification; compatibility outlook is derived. Native Wazuh
DNS question arrays and older IDS endpoint tuples are preserved. L2 evidence
rules protect sudo/root session closures, encoded-looking DNS payloads, explicit
source attack classes and conflicting/incompletely represented evidence.
`guardrails.final_guardrail_check` protects L1 and L2 model/rule exits, preserving
the existing narrow L1 standing-fact exception. The terminal stores both stages;
no new runtime dependency or actuation rights. A fresh 192-record public sample
excludes all 416 earlier selected raw records; results are separately frozen in
`evals/2026-11-17-l2-independent`. Its 13 model suppressions included 11 without
an actual DNS question: agreement with missing attack labels did not justify
those decisions. The shared final/L2 evidence rule now retains missing-question
DNS alerts. A follow-up reuses those frozen L1 outputs and reruns L2, archived in
`evals/2026-11-17-l2-evidence-gated`: 92/94 L2 inputs retain without Gemma;
2 model reviews quiet 2 warnings; final TP64/FN0/FP83/TN45. This is a seen-record
policy retest, not a fresh complete evaluation; no attack annotation reached
Gemma. See `docs/L2-INDEPENDENT-REVIEW.md` for the limits.
Windows denial responses now consume bounded rejected POST bodies before close;
this prevents connection resets without relaxing auth/CSRF. Source validation:
515 tests passed, 2 skipped, 25 subtests; the mock CLI sample passed. Installed
dashboard/portable builds have not been upgraded. Older results below remain
historical, not measurements of the corrected route.

November 17 L1/L2 follow-up: `--l2-final-review` uses Qwen3.5:4b as L1 and
Gemma4:12b as L2. Only successful local-model escalations enter L2; quiet,
mandatory-rule and model-failure policy decisions bypass it. L2 can confirm or
suppress an L1 alert with a written reason; suppression requires confidence
at least 0.9, routine-looking outlook, exact fact checks and an accepted separate
challenge. Invalid, uncertain and unavailable reviews retain the warning. JSON
schemas constrain response format; they do not certify semantic conclusions.
Every final decision is bound to its exact event; newer events cannot inherit
older suppression. Native-response defaults and executor authority are unchanged.
The terminal `events` projection preserves both stages; durable `l2-cases` holds
final reviews. Original ingestion/audit totals remain first-stage evidence.
The source launcher has no containment scope. Customer/portable dashboard builds
were not replaced. See `docs/TWO-BRAIN-SETUP.md` and the separate public replay
report for measured results and limits. No new runtime dependency.
The completed 202-record replay retained 74/74 attack annotations and quieted
48/128 unannotated records. Gemma reviewed all 97 eligible Qwen escalations,
returned 97 checked replies, proposed no suppressions and changed no decisions.
Median L2 review was 31.58s; total measured L2 work was 50.51 minutes. Its own
challenge accepted all 97, including inspected explanations with interpretation
limits. Added L2 did not reduce warnings on this run. A minimal-code efficiency
review attributed about 97.2% of measured L2 time to server-reported model work;
no speculative performance rewrite or model-setting changes were applied.

November 17 documentation follow-up: the public findings now start with
`docs/FINDINGS-IN-PLAIN-ENGLISH.md`. The detailed evaluation and frozen evidence
remain available separately. The architecture diagrams name Qwen3.5 as the
evaluated local model, show that a compatible local model can replace it, and
explain each stage in everyday language. Ollama is documented as the current
runner, not the model itself; another serving system needs a compatible adapter.
Only documentation and diagram renderers changed in this follow-up.

November 17 public-data hardening: local `qwen3.5:4b` on AIT-ADS exposed
14 directory-enumeration annotations suppressed by the LLM, not the prefilter.
Native Wazuh web attack/recon classification now carries a deterministic review
floor. Bounded source observations preserve wrapped Suricata priority/endpoints
and distinguish PAM/sudo transitions from narrowly scoped same-address TLS mail
login observations. FreshClam update-start observations have a separate narrow
prefilter; neither observation certifies safety. Ten distinct client-error paths
within five minutes can correlate by host, peer and agent. No new dependencies
or actuation authority. See `docs/PUBLIC-DATA-EVAL-2026-11-17.md` for the original
pilot, same-raw-alert regression run, disjoint-alert evaluation, percentages,
tier attribution and limitations. Improvements on inspected cases are regression
results, not independent production accuracy. Correlation is fixture-tested;
these public-data runs evaluate independent cold-start alerts. Customer/portable
installs still require an updated build and restart.

October 23 evidence presentation: alert details and expanded audit entries lead
with the source event description, separate from the decision rationale. Priority
scores are not diagnoses. Flood/connection alerts explain the reported service
risk and use network/service checks; authentication alerts distinguish missing
context from demonstrated credential misuse. Only recorded origin fields appear.
Read-only enrichment updates historical views without rewriting saved verdicts;
model guidance remains labelled separately from policy guidance. The local model
prompt asks for observed behavior, concrete concern and evidence gaps.

October 23 portable isolation: portable monitoring state is now scoped to a hash
of the Windows installation identity under `data/devices/`. Audit, memory,
ingestion/source checkpoints, IAM and runtime logs/cache stay within that device
profile. Unidentified Windows installations fail closed. Legacy shared databases
are preserved but never automatically loaded because they may mix devices.
Explicit portable `local_access: true` opens as loopback-only Local owner without
credentials. Updating source does not replace an existing USB zipapp.

October 23 alert explanations: audit entries and event details show the rule
match, executable/parent/account, uncertainty and manual next steps before raw
records. Historical telemetry gets a read-only explanation on retrieval.
Collector script text is a clue, never an attribution bypass. Backlog selection
now uses indexed identity lookups; L1 discovery uses a covering scan index so
large payload reads/sorts do not monopolize the shared ingestion lock. Regression
checks cover query plans, urgent/FIFO scheduling and future-event exclusion.

October 21 L1 guided response: the dashboard now has recommended investigation
steps (model-provided advice when available, labelled policy fallback otherwise),
durable severity review deadlines, bounded deferral/rejection, per-incident
explicitly approved timed peer blocks, persistent emergency stop and verified
undo. Timed execution independently rebuilds fresh supported evidence; default
expiry is overdue review only. Demo cases remain isolated, and playback is capped
at steady 2x with one in-flight event. No new runtime dependencies. Source/build
validation does not establish real Windows enforcement or model quality; the
installed app requires the new release and service restart. See docs/L1-RESPONSE.md.

October 20 independent L2 engine: dedicated local inference transport, bounded
evidence dossier, independent prefilter, grounded assertions and an analysis /
challenge review flow. Larger inference requires metadata above 4B, with explicit
reasoning and a separate review budget. Code-validated Defender/Sysmon critical
cases bypass inference queues while preserving policy deadlines and narrow
executor authority; deeper review follows. Native Linux validation uses owned
synthetic evidence and fixture model responses. Real-model accuracy and latency
are not established. Changes are included with the guided alert explanation integration.

October 20 optional L2 iteration: the terminal agent accepts `--l2-model` and
`--l2-policy`. A separate durable scheduler supplies severity-based deadlines,
bounded acknowledgement/deferral, rejection, persistent emergency stop, local
notices and verified revert. Per the owner's explicit authorization, narrowly
enrolled deterministic correlations may trigger a five-minute peer block after
an unanswered deadline and a valid L2 recommendation. The model itself still
cannot execute commands or grant authority. Advice-only is the default; triage
remains side-effect free. Larger-model quality and Windows native enforcement
remain unverified. See docs/L2-RESPONSE.md for scope and deployment limits.

October 19 containment iteration: `arbiter agent` runs a local terminal agent
on Windows/Linux using shared ingestion and explicit rules-only or local Ollama
analysis. Approved, scoped private/public peer IP blocks have management/service
exclusions, native rule checks and five-minute OS-owned expiry. Linux OpenSSH
file collection and an nftables adapter are implemented. `tools/build_agent.py`
packages a stdlib-only zipapp without requiring the dashboard. Linux network
namespace validation uses synthetic detection input and real packet filtering;
it is not a live breach or THM result. A THM Windows VM has been launched and
reached over a target-only VPN route. The deployed package detected and escalated
three preliminary process/network findings. Further THM testing was stopped
after reviewing its current Acceptable Use Policy sections 9.2–9.3, which
restrict AI-agent access and AI-system evaluation/development using lab content.
Written THM authorization is required before resuming. Administrator elevation
was not approved in the VM; Windows enforcement remains unverified. Local snapshots detect
sustained CPU use by a temporary executable with network activity. See
docs/AGENT-LIVE-VALIDATION.md for coverage, commands and acceptance criteria.

October 14 website demo: explicit owner-authorized cloud exception for the public
simulator only. `arbiter.site_cloud.WebsiteCloudBackend` calls Ollama Cloud
Nemotron using a server-only OLLAMA_API_KEY; it is never registered in the
installed backend selector. Public serving defaults to cloud; missing credentials
disable starting runs, and cloud failures are labelled policy escalations, never
mock output. Uploaded sample/sanitized events require cloud consent. Live model,
request status and per-verdict provenance are visible. Cloudflare container/Worker
deployment files are prepared; no deployment or live credentialed request has
been performed. See docs/PRODUCT-WEBSITE.md. Customer inference remains local-only.

October 13 local access: this PC's owner requested a dashboard without sign-in.
Explicit `serve --local-access` / installed `[server] local_access = true` opens
as Local owner (admin), requires loopback binding and direct local Host/Origin
checks, and retains CSRF and typed response approvals. Other installs retain
password authentication by default. Existing accounts/history are preserved.

October 12 decision integration: reboot verified native Sysmon delivery. High-priority
Defender/Wazuh/Suricata/GuardDuty findings have a deterministic review floor; osquery
checks executable startup/process commands against existing rails; Windows protection
posture is observed automatically. Exact Defender-file/Sysmon-network matches can
propose an approved TTL-limited IP block. Queue/history/index performance fixes and
exact process-context learning preserve legacy Event/Verdict signatures. Local Qwen
is connected on the installed device. See docs/SECURITY_TOOL_INTEGRATIONS.md for
validation and backlog/capacity limitations.

October 11 tool integration: explicit verified Windows tool provisioning via
`arbiter setup-monitoring`, automatic local source discovery in real runtimes,
Microsoft Defender findings and local Wazuh manager alert-file ingestion. Disabled
sources and isolated demos are preserved. See docs/SECURITY_TOOL_INTEGRATIONS.md
for supported setup, privacy boundaries and transport limits.

October 10 iteration: isolated paced DemoManager, shared clickable EventPanel,
recent-feed recovery, explicit packaged UAC setup, persisted local model selection,
and approved reversible Windows IP blocks. See docs/DEVICE_MONITORING_AND_DEMO.md.
No ingestion path executes generic response command strings. Protection is manual
approval only; demos cannot act on the real device.

Live ingestion iteration (2026-10-09): `arbiter/ingestion` now provides the
SecurityEvent v1.0 adapter, durable bounded queue, shared worker, source registry,
Windows/Sysmon/osquery/Suricata/private UDP syslog and optional AWS readers.
Source, installed and portable runtimes own this lifecycle. Data Sources, Live
Events and Demo & Replay are authenticated React views. Existing Event, brain,
guardrails, verdict routes, feedback and response boundaries stay compatible.
See `docs/INGESTION_ARCHITECTURE.md` for actual support and MVP limitations;
Coming Soon sources have no transport. AWS API retrieval is an explicit opt-in
exception authorized for this iteration; the triage path still uses local AI.
Only explicitly approved typed firewall operations invoke an actuator. Refer to code and tests rather
than older "future collector" descriptions below.

First vertical slice of the triage engine (Python, stdlib-only):

- `arbiter/schema.py` — Event/Verdict data contract. **This is the stable boundary a future Go collector agent must honor. Do not change it casually; keep it dependency-free.**
- `arbiter/memory.py` — SQLite memory layer: asset criticality, verdict history per signature, environment facts. Deliberately human-readable (transparency is a product feature).
- `arbiter/facts.py` — scoped environment facts (the fact-overreach fix): a fact may carry `user`/`path`/`process`/`event_types`/`window` constraints, checked in code against each event before the LLM sees it; out-of-scope facts render with a `[SCOPE MISMATCH]` annotation that can never justify suppression. Scope facts to the event class they explain — over-scoping mismatches legit events (see `cmd_seed`).
- `arbiter/prefilter.py` — cheap tier: severity × criticality × history. Thresholds are provisional; shadow-mode data should tune them.
- `arbiter/llm.py` — pluggable backends: `OllamaBackend` (local open-weights model) and `MockBackend` (deterministic heuristics for tests/dev).
- `arbiter/triage.py` — orchestrator, shadow mode, JSONL audit trail.
- `arbiter/respond.py` — response actuator: surgical, TTL-limited actions from escalation verdicts (block IP / lock account / kill session / quarantine host). Dry-run default; AUTO only for prefilter-tier + auto-safe catalog entries, LLM-tier is always RECOMMEND. Allowlists (CGNAT/office NAT) deliberately deferred.
- `arbiter/store.py` — queryable SQLite audit store (audit rows + IAM events); `lifetime_counts()` gives aggregate, non-identifying totals; `day_buckets()` backs the overview chart; `rows_since()`/`max_id()` back the live-feed poller; `acknowledge()` repurposes the `actor` column to mean "reviewed by"; 30-day `prune()`. Separate from `memory.py`, which is never pruned.
- `arbiter/iam.py` — built-in IAM: local accounts, `hashlib.scrypt` hashing, HMAC-signed session cookies, `analyst`/`admin` roles, lockout. Stdlib-only. `load_or_create_secret()` persists the HMAC signing secret (0600) so sessions survive a restart — previously `IAM(secret=None)` picked a fresh one every process start.
- **`arbiter/web/` removed (2026-07-26), replaced by `arbiter/api/` (2026-07-27).** The old web layer — stdlib `http.server`, server-rendered UI, JSON API, SSE feed — and the Svelte `frontend/` were deleted to rebuild the frontend from scratch. `arbiter/api/server.py` is the new thin JSON API over `store.py`/`iam.py`/`memory.py`: same stdlib-only `http.server` approach as before (see AGENTS.md for why, not FastAPI), session cookie + CSRF double-submit + security headers, and a background thread that polls the audit store for new rows and fans them out over SSE (`/api/stream`) — so it never talks to the triage engine directly, and doesn't care whether `arbiter run`, a real collector, or the dev-only `--demo-feed` wrote the row. `memory.py` now also takes `check_same_thread=False` + a lock, matching `store.py` — required once a threaded HTTP server started calling it from multiple threads.
- `arbiter/cli.py` — `python -m arbiter seed` / `run samples/events.jsonl [--respond]` / `eval` / `review` / `bench` / `serve`. Note `--db` is a **global** flag and must precede the subcommand. `serve --demo-feed` is dev-only (off by default) and replays `--events` through the triage engine on a timer so the dashboard has data without a real collector wired up.
- `arbiter/install/` — cross-platform installer (ADR-002). `plan.py` makes an install an inspectable list of `Action`s, so `--dry-run` and the real run walk the same list; `preflight.py` gates on python/disk/RAM/port/Ollama; `service.py` registers systemd (Linux) or a Task Scheduler task (Windows), both derived from one `serve_argv()` so they can't drift. Lifecycle: `--install/--upgrade/--uninstall/--status`, all accepting `--dry-run` and `--prefix`. Data dir is never touched by upgrade, and uninstall asks about it separately. `serve_argv()`'s flags (`--host/--port/--store-db/--iam-db/--events`) match `arbiter serve` exactly; the installed service never passes `--demo-feed`, so it never runs the synthetic feeder.
- `packaging/install.sh`, `packaging/install.ps1` — thin bootstraps: find Python, download the `.pyz` + `SHA256SUMS` from GitHub Releases, verify, hand off. **Never publish pipe-to-shell instructions** — the prefilter escalates that pattern.
- `tools/build_release.py` — builds `dist/arbiter-<version>.pyz` (transparent zipapp of readable source) + `SHA256SUMS`. Version's single source of truth is `arbiter/__init__.py`; `.github/workflows/release.yml` enforces that the git tag matches it.

## Design invariants (do not violate)

1. **Asymmetric error costs**: missing a real breach is fatal; false escalations are cheap. Suppression always requires stronger justification than escalation. LLM failure → escalate by policy.
2. **Every suppression carries a written rationale; every escalation carries an evidence summary.** No silent verdicts.
3. **Nothing leaves the customer's network.** No cloud API calls in the triage path. LLM inference is local (Ollama) or mock.
4. **Adaptation through context, not weights** — learning lives in the SQLite memory layer, never in fine-tuning.
5. Collection logic stays out of the brain. Anything that reads logs communicates with triage only through the `Event` schema.
6. **Response mirrors both 1 and 5**: blocking requires stronger justification than alerting (false blocks are costly). Response logic stays out of the brain — `respond.py` consumes verdicts, `triage.py` never gains side effects. Actions are surgical, reversible, TTL-limited; never service-wide. The LLM tier never auto-executes.

## Verify changes

```bash
python -m arbiter --db /tmp/arbiter.db seed
python -m arbiter --db /tmp/arbiter.db run samples/events.jsonl --audit /tmp/audit.jsonl
```

Expected: backup IO spikes suppressed (LLM tier first, prefilter after 5 benign verdicts), brute force + curl|sh escalated by prefilter, laptop priv-escalation caught by LLM tier, unknown host escalated.

## Next steps (agreed with Haryshwa)

0. **Build the new frontend** (React + Vite + TypeScript + Tailwind, per AGENTS.md) against the now-restored `arbiter/api/`. Supersedes the old ADR-001/ADR-002 dashboard-and-website plan. The public landing's hero is built: `frontend/src/site/TransitField.tsx` + `Landing.tsx`, spec in `docs/HERO-TRANSIT-BRIEF.md` (which supersedes `docs/LANDING-BRIEF.md` §3a; `CyberField.tsx` and `ArbiterMark.tsx` are deleted). **The public positioning line changed 2026-07-29** — "a shield you can raise before you can afford an army"; no SIEM comparison and no pricing claim ships publicly. Dashboard views remain the open work.
1. Labeled eval set to answer "minimum viable local model" — biggest open question.
2. Human feedback loop CLI (confirm/overrule → `memory.label_verdicts`) — done via `arbiter review`; `/api/label` now exposes the same action to the frontend.
3. Collector wrapper decision (Vector vs Wazuh) emitting the Event schema.
4. Event-triggered micro-rescans for unknown assets.
