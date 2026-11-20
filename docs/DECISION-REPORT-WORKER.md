# Compact decisions and separate reports

The local source now separates the urgent L2 decision from its longer report.
Qwen3.5:4b remains L1, Gemma4:12b remains L2, and the five bounded decision
stages remain independent. A sixth, CPU-only report worker formats saved
evidence without calling either model. No runtime dependency was added.

## Immediate decision

Qwen keeps its existing short verdict interface. Its actual input context,
reason, confidence and proposed/final decisions are now preserved as receipt
metadata outside the stable Event/Verdict serialization contract.

Gemma's final-alert-review route now requests seven fields: decision,
confidence, short decision reason, benign explanation, suspicious explanation,
missing context and 1–3 evidence IDs. Those IDs are selected from an enum built
from the actual packet. The application resolves each ID to its original,
typed fact; the model no longer needs to copy a username, port or count into
its answer. Unknown/duplicate IDs, invalid confidence and incomplete answers
are rejected. The response budget is 768 tokens rather than 1,536; it is a
ceiling, not a measured new output length or latency.

Both competing explanations remain required. A proposed suppression still
requires the separate Gemma checking call, at least 90% confidence and all
existing final suppression gates. Retain-only decisions keep the existing
one-call optimization. The packet, its digest and the decision receipt are
saved with the L2 result. Existing validated full replies remain compatible;
the new requested schema is compact. Native device-response and advice-only
L2 routes keep their existing formats and authority restrictions.

This change addresses field-copying failures structurally. It does not itself
establish better judgement on the previously missed authentication record.
The shorter format and preserved checks need a fresh model evaluation.

## Reports and templates

Reports use six local, versioned templates: authentication, web, network,
software/update, process and generic security events. Each combines recorded
facts, the actual saved reason, evidence references, uncertainty and standard
manual checks. Template checks are identified as policy text, not model output.
Missing information stays missing; a report cannot authorize a device action.

While a review is pending, event details can show a partial template with
recorded facts and an explicitly pending decision. Final decision persistence
also queues a durable report job in the ingestion database. The report worker
loads one job at a time and renders outside the shared database lock. It
stores a report snapshot and input digest; the full model packet remains in
the decision receipt rather than being copied again into every report.

Report rendering can fail or pause without changing or delaying a completed
decision. Pending jobs survive restart. There is no eager regeneration of an
installed customer's historical database. Report retention follows its source
event. Human rejection queues a new revision, and an older in-flight render
cannot overwrite it. A stale or corrupt report is withheld while the saved
decision remains available.

## Learned pre-filter patterns

Both stages now store the selected report template alongside a learned pattern,
its original model, reviewed event and saved reason. On a later match, the
report identifies the current decision as a pre-filter match and identifies
the original model-reviewed event separately. It does not claim that Gemma or
Qwen reviewed the repeated record again.

Existing exact matching, source/host/model scope, expiry, 25-hit limit,
revocation and final guards remain in force. Template selection adds no new
suppression authority and does not broaden which patterns can match. Old
memory databases receive the template column without discarding their rules.
Templates are application-defined; models do not write executable template
code or rewrite the pre-filter's source.

## Availability and validation

The authenticated event-detail API exposes report state and content; terminal
agent events include it too. Event details and Data Sources reuse their existing
components to show partial/ready reports and the independent report worker.
Magic and ui-ux pro max were unavailable in this session; neither was used for
those two incremental views. Existing spacing/type styles, contrast, status
announcements and escaped text rendering were retained and manually reviewed.

Tests cover compact evidence IDs, confidence/challenge gates, preserved model
context, durable queue recovery, slow/failed reports, concurrent revisions,
human overrides, retention, partial reports, failed analyses, learned-pattern
provenance, template migration and corrupted report data. Frontend build,
type checking, lint and existing browser/simulation checks are included in
verification. A separately built zipapp is under
`output/decision-report-worker-2026-11-20/release`.

Publication validation passed **649 tests and 25 subtests**, including 27 dedicated
decision/report checks and the portable-hashing regression. Source and packaged CLI each passed the 22-event mock
sample; the packaged asynchronous worker prepared four event-type reports with
zero report errors. All 81 packaged core files matched the source. Frontend
build/type checks, lint and 17 browser/simulation checks passed; two existing
Fast Refresh warnings and the existing bundle-size warning remain.

The published 20,002-record evidence and its frozen runtime remain unchanged.
The installed dashboard and benchmark remain stopped. This source update has
not been deployed or tested with real Qwen/Gemma inference; no new
accuracy, GPU stability or model-latency gain is claimed.
