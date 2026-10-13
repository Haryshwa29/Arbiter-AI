# Ingestion architecture

Arbiter now accepts live telemetry and demo/replay data through one pipeline:

```text
Windows / Sysmon / osquery / EVE / syslog / AWS / authenticated API / files
  -> collector or file adapter -> SecurityEvent v1.0 -> SQLite event buffer
  -> one worker -> Event adapter -> existing TriageEngine
  -> guardrails -> deterministic prefilter -> local AI when ambiguous
  -> final guardrails/verdict -> observation or alert -> correlated incident
  -> SQLite read models -> authenticated dashboard
```

## Contracts and compatibility

`arbiter.ingestion.schema.SecurityEvent` contains versioned source, identity,
network, process, file, cloud, rule, tags and metadata fields. Missing optional
values are allowed. Timestamps normalize to UTC. Severity is 0–10. Raw events
are retained for forensic review, not executed. Source-specific fields live in
metadata. Each record is limited to 256 KiB; unsupported schema versions,
non-finite numbers, invalid timestamps, IPs and ports are rejected.

`SecurityEvent.to_event()` adapts to the existing `schema.Event` contract:
source/host/type/message/severity/id/timestamp/fields and unchanged signatures.
Legacy Event constructors, CLI evaluations, labelled suites and named demo cases
remain valid. Metadata records provenance; uploaded normalized records cannot
assert trusted routine-filter provenance. Bare legacy records preserve their
original deterministic/history policy. Labelled dataset facts are preserved in
raw data but do not automatically become trusted environment facts.

## Queue and lifecycle

`EventBuffer` is the replaceable queue/read-model boundary: enqueue, enqueue_many,
claim, finish and fail. SQLite uses parameterized statements, WAL, and a lock.
The ingestion database sits beside the audit DB, named `<audit-stem>_ingestion.db`.
No existing IAM/memory/audit tables are destructively migrated.

At most 10,000 pending/processing records are buffered. Atomic imports reserve
capacity for the entire batch. HTTP writes return 429 on queue pressure. File,
Windows and AWS collectors retain cursors until accepted and retry. Syslog is
UDP and can lose packets; it is not a reliable transport. One worker per database
is supported. Do not start multiple Arbiter processes against the same data DBs.
Collectors never invoke the model; slow inference delays analysis, not acquisition.

Pending schedules and checkpoints survive restart. Interrupted processing returns
to pending. If a completed verdict already exists, recovery reuses it. Delivery
is at-least-once: a crash between updating memory and storing its audit verdict
can duplicate memory history. This is an explicit MVP limit, not exactly-once
processing. Failed analysis remains visible for administrator review. Automatic
retry of arbitrary failed events is not implemented.

Source, portable and installed runtimes start the same service. Real Windows
runtimes auto-connect discovered local tools. Configuration stores no credentials. Enabling a
source persists across restarts; disabling stops it but does not erase events.
Real Windows runtimes now auto-connect discovered local tools (October 11);
explicit source disabling is preserved. See `SECURITY_TOOL_INTEGRATIONS.md`.
Shutdown
waits for the current local inference call (up to its existing 120-second timeout).

## Events, observations, alerts, incidents

Every incoming record is an event. Written suppression decisions produce
observations, including routine login/logout, passive network context, inventory
and simple standard-shell launches. Guardrails run first. Only recognized low
severity telemetry profiles qualify for cheap routine handling; correlations
remove that eligibility. Other activity enters the existing severity, criticality,
history and AI decision process. Single event IDs/names do not prove an attack.

Escalations are alerts. Correlated escalations get a persisted incident ID and
related-event links. This foundation groups activity without remediation or a
full incident-management workflow. The five-minute, 300-record correlation
window supports repeated login failures/success, account creation/group change,
suspicious process/network, cloud login/IAM activity and cross-tool findings.
It uses event time so original-timing replay behaves coherently. Late/out-of-order
events and noisy windows can miss matches; no impossible-travel claim is inferred
without geographic/baseline evidence.

Asset context supplements the existing curated criticality store. osquery snapshots
provide system/OS/process/user/port/interface/software/startup/task rows. They never
assign business criticality, invent an owner or silently create trusted facts.
The latest snapshot per table is kept, limited to 100 rows per query in this MVP.

## APIs and observability

All operational reads require the existing session. All writes require session,
double-submit CSRF and administrator role. Static UI remains public but carries
no customer data. Existing verdict APIs and SSE remain available.

| Endpoint | Purpose |
|---|---|
| GET `/health` | Authenticated process/worker health |
| GET `/api/ingestion/status` | Catalog, health, configuration and metrics |
| GET `/api/events` | Source/host/severity/category/time/IP/username filtering and pagination |
| GET `/api/event?id=…` | Normalized/raw event, analysis and related IDs |
| GET `/api/ingestion/assets` | Observed inventory |
| GET `/api/datasets` | Prepared dataset names |
| POST `/api/ingestion/configure` | Enable/disable/configure a collector |
| POST `/api/ingestion/submit` | Normalize one event and enqueue |
| POST `/api/ingestion/import` | Preview or queue an uploaded text dataset |
| POST `/api/ingestion/dataset` | Preview or queue an allowlisted prepared dataset |

Live Events polls every two seconds; the existing Live feed is the verdict SSE
view. Data Sources shows received counts, last record, events/minute, errors,
queue depth, filtered observations, deterministic decisions, AI-tier decisions,
alerts and mean analysis time. Counts describe retained telemetry (30 days), not
unbounded lifetime totals. AI tier counts include mock reasoning when selected.
Pending/failed records are never reported as filtered. Processing latency measures
analysis duration, not replay delay or queue wait. Completed raw events and
incidents are pruned hourly after 30 days; pending work is not silently deleted.

## Security and data flow

Uploads are parsed in memory, never saved as executable content; filenames are
plain labels. JSON/JSONL/CSV only, 5 MiB/5,000 records. Request bodies are limited
to 8 MiB with bounded socket reads. Errors do not include SDK exception text.
React escapes raw records; no raw HTML renderer is used. Local log paths and
tool paths are administrator-controlled, not taken from uploaded filenames.

Endpoint/network telemetry stays in local SQLite and the configured local model
service. Raw payload remains available only through authenticated local APIs.
Opt-in AWS retrieval contacts AWS to read the organization's own data, then
returns to this same local pipeline. No external AI, analytics or telemetry is
introduced. Protect the data directory with OS permissions and disk encryption;
SQLite raw records can contain sensitive user/command/IP information. The existing
stdlib server remains a local/lab server; use a reviewed same-origin TLS reverse
proxy and access controls for a shared deployment. Cloud SDK credentials and the
local inference URL are deployment administrator trust boundaries.

## Validation and limits

Fixture tests cover mapping, malformed records, files, registry, queue pressure,
restart recovery, deterministic compatibility, correlation, AWS pagination,
syslog parsing and authenticated HTTP behavior. CI requires no AWS credentials,
Sysmon, osquery, Suricata or model service. Azure/GCP/Zeek and future AWS transports
are scaffolding. CloudTrail covers regional management-event history, not all
S3 data events. Production multi-worker delivery, authenticated syslog TLS,
full baseline modeling and incident lifecycle management are future work.

The repository's requested Magic generator and ui-ux pro max skill were not
available in this session. Data Sources, Live Events and Demo & Replay reuse the
existing React/Tailwind design and StatTile rather than adding UI dependencies;
accessibility and browser layout are checked directly. Neither named tool was
used for these three views.
