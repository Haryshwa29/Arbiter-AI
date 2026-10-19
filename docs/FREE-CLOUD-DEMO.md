# Free hosted Arbiter demonstration

The website uses Cloudflare Pages Functions and live Ollama Cloud inference.
Cloud inference is only for the public demonstration. Installed Arbiter remains
local-first and never selects this cloud backend for customer monitoring.

## Decision flow

The hosted policy now mirrors the core demo's intent-class guardrails, severity
and asset-criticality scoring, scoped synthetic environment facts, and signature
history screening. Guardrails run first; clear high-score events escalate without
a model call. Ambiguous events receive the correct criticality, scoped facts and
session history in the standard Arbiter prompt. Suppressions below 0.7 confidence
escalate. After five benign verdicts, a sufficiently low-scored repeated signature
can earn prefilter suppression. Nothing forces a fixed ratio of decisions.

The browser receives an HMAC-signed history token from the Function and sends it
with the next event. Only actual server-issued verdicts advance its counters.
Client edits cannot manufacture benign history. The token expires after 30 idle
minutes and is limited to 500 decisions / 128 signatures. Refreshing/replacing a
run clears browser history. Tokens can be replayed to an older state; they are a
demo integrity mechanism, not authentication or the production SQLite audit store.

`demoPolicy.js` is a portable implementation, not the full Python runtime. Tests
compare its guardrail hits, initial scores/decisions and rendered facts against
Python for all 318 exported sample events. Tests separately cover learned history,
scoped-fact mismatches and history-token tampering. Native collection, correlation,
admin feedback, long-term SQLite memory and response planning stay in the installed
product; the hosted demo neither collects activity nor executes device actions.
Incoming uploaded data cannot assert internal trusted telemetry/collector flags.

## Datasets and maintenance

All eight original JSONL datasets and sixteen named Active scenarios are included.
`python tools/export_cloud_demo.py` regenerates their normalized event data, policy
constants and Python parity fixtures. CI checks these generated files for drift
and runs `npm run test:demo`. Missing occurrence timestamps stay unknown; receive time is not treated as event time.
Labels such as expected decisions are not inputs to
cloud inference. Demo assets and the two scoped facts match the demo context.
Only scope-verified matching facts can explain routine behavior; a fact about IO
cannot justify a new shell command on the same host.

The browser supports simple-schema JSON, JSONL and CSV uploads, validation,
pause/resume, pacing, shuffled ordering, details, counts and filtered history.
The cap is 500 events per run, 12 KiB per normalized event and 5 MiB combined files.
Native tool-export formats supported by installed adapters are not all supported
here. Use synthetic or sanitized events and confirm cloud processing. Model failures
are visible failures and stop delivery; no mock verdict is inserted. Completed
suppressions, escalations for review, pending analysis and failures have distinct
status labels. An escalation is not an analysis still in progress.

## Deployment and credentials

Git-connected Pages uses root `frontend`, command `npm run build:public`, output
`dist`. Save `OLLAMA_API_KEY` as a Production Secret and redeploy. Optional plain
variable `OLLAMA_MODEL` selects a cloud API model ID; default `nemotron-3-nano:30b` (30-billion-parameter model class).
The model is configurable and the policy does not depend on Qwen or a particular
model's name. The API key is never placed in browser code or git. No new runtime
packages, paid container, purchased domain, or always-on PC is needed.

`GET /public-demo/status` reports configuration. `POST /public-demo/analyze` runs
policy and calls the cloud model only if needed. Same-origin/custom-header and
explicit consent checks precede analysis. Payloads, response lengths, output token
budget and request duration are bounded. No payload/key logging is implemented.
Static pages are excluded from Functions invocation using `_routes.json`.

Limits are best effort per Worker isolate: four active model requests, 500 model calls
per caller IP per hour and 2,000 total per hour. Deterministic decisions do not consume
that model allowance. Large selections can hit the shared allowance. Multiple
isolates/restarts can exceed these totals; they are not a distributed spending cap.
Use provider free-allowance/spending settings and do not add paid credits for a
zero-cost demonstration. Origin checks are not authentication.

Verification includes deterministic parity and controlled-provider tests. Live
model evaluation must check benign and malicious scenarios separately; successful
transport alone is not detection accuracy. UI changes adapt existing components;
21st.dev Magic and ui-ux pro max were unavailable and were not used.


Temporary busy responses carry distinct error codes and retry delays. The browser
retries the same event up to four times without changing its history or inventing
a verdict. Website hourly limits are explicitly distinguished from provider usage.
Escalations receive a browser response-policy recommendation (not an AI-generated
command). Approve records a simulated approval; Review defers action. Both remain
in browser session memory. No device operation, provider call or installed response
endpoint is invoked by these controls.

Nemotron Super is reserved for a possible future L2 analyst architecture; the current demo uses Nano only. Nano model reference: https://ollama.com/library/nemotron-3-nano:30b-cloud
