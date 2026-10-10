# Live ingestion implementation plan

Repository: Haryshwa29/Arbiter-AI, local checkout `C:\Users\harys\Open-AI\Arbiter-AI`.
Baseline: clean working tree; 152 unittest tests pass before changes.

## Current architecture

`schema.Event` is the stable collector/brain contract. CLI run and the editable
JSON/JSONL demo feeder invoke `TriageEngine`: security guardrails, severity ×
criticality × history prefilter, optional local Ollama/mock, post-model guardrails,
written verdict and memory history. SQLite AuditStore serves authenticated API
routes and a verdict SSE feed. React/Vite/TypeScript views are Overview, Live feed,
Verdicts & audit, Assets & facts. Portable and installed launchers use the same
API. IAM provides session cookies, CSRF and analyst/admin roles. CI runs Python
tests and mock smoke/evaluation, plus frontend typecheck/lint/public build.
Existing manual datasets and named editable demo cases remain supported.

## Proposed architecture and order

1. Versioned SecurityEvent -> legacy Event adapter; collector interface/registry;
   durable bounded SQLite event queue; persisted Live Events and demo adapter.
2. Windows Security/System/Application polling; Sysmon operational channel;
   fixed osquery inventory queries, lightweight asset context.
3. Suricata EVE tailing; documented Zeek foundation; loopback UDP syslog parser.
4. AWS CloudTrail lookup and GuardDuty polling via optional SDK; profile/region
   configuration; explicitly unavailable Azure/GCP/future AWS adapters.
5. Authenticated Data Sources, Live Events and Demo & Replay views, health,
   metrics and configuration. Existing verdict views remain.
6. Bounded correlation of login failures/success, process/network, account/group,
   cloud IAM and tool findings; observation vs alert promotion; asset enrichment.

Collectors only normalize and enqueue. A single worker calls the existing brain.
Routine telemetry receives deterministic written observation decisions; only
escalations become alerts. No response actuator is called by ingestion.

## Files changed / created

Change: prefilter (telemetry routine rules), API server, portable/installed runtime
wiring, frontend App/AppShell/API client, pyproject optional dependencies,
.gitignore and README. Preserve schema.Event's constructor and serialization.
Create: arbiter/ingestion/{schema,normalization,base,registry,store,pipeline,
correlation,files,service}.py; collectors for Windows, Sysmon, osquery, Suricata,
syslog, AWS and future-source stubs; three React views; fixture/queue/API tests;
INGESTION_ARCHITECTURE, CONNECTORS, LIVE_LAB, CLOUD_INTEGRATION, ADDING_A_CONNECTOR.

## Database / dependencies

Add telemetry, connector configuration/checkpoints, metrics and asset-context
tables to a separate ingestion SQLite database beside existing audit data.
No destructive migration of memory, IAM or audit tables. SQLite buffers persist
pending work/replay schedules across restart. A replaceable queue interface is
the future production boundary. Core remains stdlib-only; optional boto3 SDK
is justified by AWS credential-chain, request signing and pagination support.
No new frontend runtime dependencies.

## Security / compatibility

All operational APIs require existing IAM session; writes retain CSRF; connector
configuration is admin-only. Body/upload limits, strict parsing and bounded
records; uploads never become executable files. Paths are administrator-selected
local log paths, never derived from upload filenames. Collectors disabled on
fresh startup; syslog loopback by default and private-only optional binding with
sender allowlist. Credentials stay outside config; SDK reads standard chain.
Raw telemetry remains local; explicit AWS polling retrieves customer data and
does not call external AI. Connector exception text is not exposed.

Compatibility risks: raw event volume differs from verdict volume; separate
views/metrics distinguish them. Existing sample shape is adapted without changing
signature semantics. Sample replay gets fresh IDs while live records deduplicate
by source identity. MVP processing is at-least-once after unexpected termination;
already stored audit verdicts are reused on recovery. Correlation is bounded and
does not equate a source event ID/name with maliciousness. Privileged tools are
never installed automatically. Future integrations remain visibly Coming Soon.
