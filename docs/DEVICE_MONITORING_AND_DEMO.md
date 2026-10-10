# Device monitoring and isolated demonstrations

This iteration implements the user's October 10 feedback about disconnected
views, instant replay, mixed histories, permissions, and protection status.

## Real monitoring

Data Sources identifies the current device, connected sources, permission or
configuration gaps, and the actual analysis backend. System/Application logs
can work without Security access. Collectors still require explicit enablement.
Monitoring this PC does not cover every device on its network; other endpoints
and network sensors need their own configured sources.

Incoming events are clickable. A shared side panel shows their stable event ID,
timestamps, original payload, processing state, rationale, evidence, recommendations
and approved response status. Overview, Live Feed and Audit open this same panel.
Live Feed loads recent decisions before following SSE updates; periodic refresh
recovers missed updates. Detection decisions do not imply protective actions.

The local packaged `serve` dashboard offers **Request Windows log access**.
It explains the administrator restart, then invokes Windows UAC only after the
operator clicks and confirms. Cancellation leaves the current server running.
The elevated helper waits for the old process to exit before relaunching with
the same databases. The session signing key and accounts persist. Source/Vite
and the portable/managed supervisor do not offer this standalone relaunch.
No administrator access was requested during automated validation.

**Check local AI models** discovers models only on the configured local Ollama
service. **Connect local AI** switches the worker and saves the selected backend
and model for restart. Stop active simulations before switching. Missing Ollama
or models remains visible; nothing is downloaded implicitly. Test heuristics
are explicitly labelled, including inside the simulation and event panel.

## Controlled protection

This rollout supports manually approved five-minute Windows firewall IP blocks
and undo. A proposal requires a completed escalation from a trusted Windows or
Sysmon collector on this device, plus repeated-login-failure or suspicious-process
network correlation and a specific globally routable address. Private, loopback,
demo, replay, arbitrary API-uploaded and remote-device events cannot qualify.

An administrator operator must confirm the exact address and impact. Blocking
affects all inbound/outbound connections to that address. Windows administrator
access is also required. Commands are fixed, typed operations; model-provided
commands and the older generic shell responder are never executed by ingestion.

A SYSTEM scheduled cleanup task is registered before firewall rules are created.
It removes the named rules after five minutes even when Arbiter stops, or on the
next Windows start if the deadline was missed. An undo button removes the same
rules/task. Approval, failure and undo are audited. `expiry_due` means cleanup
is due; it does not falsely claim that Arbiter verified rule removal.

Automatic blocking, process termination, account locks and host quarantine are
not enabled by this rollout. The broader network does not receive inline
protection from this PC's firewall. Native UAC approval and real firewall changes
still need an approved interactive Windows test; automated tests mock these
operations and verify eligibility, input validation, expiry registration, failure
states and audit records. No real firewall rules were created during validation.

## Separate simulation workspace

Demo & Replay selects any combination of bundled datasets or uploaded files,
with Select all, validation, repeatable random seeds, mixed sequences or full
shuffling, and steady arrivals, bursts/pauses or variable delays.

Start opens a dedicated side workspace with incoming records, detection/response
feed, progress, pause, resume and stop. At 1x one event arrives every three seconds;
2x/5x/10x shorten that interval. Burst/variable profiles alter intervals without
prequeuing the entire dataset. Original timestamps remain available for forensic
review and correlation. This is demonstrable pacing, rather than reconstruction
of timestamp gaps in old datasets. Pause/Stop halt delivery; already queued work
can finish. Closing the panel does not stop the session. Reopen it on this page.

Every simulation has separate telemetry, audit, inventory, correlation and memory
databases. Synthetic context is seeded only there. Responses use the pure planner
and are labelled simulated; the actuator is never called. Simulation history is
temporary and ends when replaced by a new session or the server exits. Only the
latest 100 delivered records are listed in the workspace; the session keeps all
delivered records until it closes. Up to 5,000 events are accepted per session.

Earlier file/replay imports in this local installation remain in SQLite but their
verdicts are classified as `demo_verdict`, excluded from real counts/feed/audit.
They are not deleted. Old import/dataset HTTP routes support preview only when
the simulator is installed; playback must use `/api/demo/start`. The low-level
library import API remains available for compatibility. Live HTTP submissions
use `/api/ingestion/submit`. Portable launch no longer auto-feeds demonstrations
or seeds fake production assets; editable Active cases appear as allowlisted
simulation datasets and are reread before each new session. Explicit development
`--demo-feed` routes into simulation when that lifecycle owner is present.

## Validation

Browser walkthrough: sign-in, select all/clear, paced start (zero arrivals at
start, one after three seconds), pause/resume/stop, clickable simulation details,
clickable real records, recent Live Feed backfill, no simulation IDs in real
events/audit, and no page errors. Existing tests plus simulation isolation,
identity, permissions cancellation and response safety tests pass. Frontend
TypeScript/build and lint pass apart from pre-existing Fast Refresh warnings.

Magic and ui-ux pro max were unavailable in the session. The existing React,
Tailwind, buttons and side-panel patterns were used and visually inspected for
Demo & Replay, Event Details, Overview, Live Feed, Audit and Data Sources.

## Unified Live timeline (2026-10-10)

Live replaces the separate Live Events and Live feed navigation entries. `/events` redirects to `/live`. Each telemetry row keeps its event ID and displays arrival, pending/running analysis, and the actual suppress/escalate verdict. The same status helper is used in the event inspector. Completed suppressions are labelled Suppressed, never Observation. An escalation means an alert for review, not executed protection. Failed analysis remains visible. The page refreshes every second; fast processing may finish between refreshes, so completed rows also show Received → Analyzed → decision without artificially delaying analysis. Demo telemetry stays isolated.

Validation: frontend build and lint (three existing Fast Refresh warnings); headless Edge verified real records and clickthrough, legacy redirect and one Live navigation entry, and browser-only mocked pending/processing/suppress/escalate/failure transitions. No synthetic events were inserted into production history. Existing components were adapted because the requested Magic generator and ui-ux pro max skill were unavailable.

## Aligned simulation timeline (2026-10-10)

The separate incoming/detection lists are replaced with one table: event, decision/reason, simulated response. Each row stays aligned regardless of content height and opens its own EventPanel. Live simulation shows the latest 20 arrivals. Verdicts & history opens completed session events, with 100-row pagination through authenticated `/api/demo/history?offset=`. Failed analyses are retained. Responses remain simulated and no-response outcomes are explicit. An older server lacking the history endpoint falls back to completed records in its latest 100 arrivals and displays a restart notice. Full history lasts only for this temporary session.

Validation: 209 tests plus 3 subtests passed, frontend build/lint passed with existing warnings. Browser checked aligned rows, shared event ID details, simulated response label, Live/history switch and isolation. The active server had an older backend; the compatibility history view was browser-tested. Full pagination is implemented but not exercised against that running process. The current listener has unavailable command-line metadata, so it was not forcibly terminated; the verified extra dashboard process created during testing was stopped.

## Explained simulation history (2026-10-10)

Verdicts & history shows the same arrived events as Live simulation, including pending analysis. The latest history page is refreshed from live event records by stable event ID so decisions stay consistent. Each history row has full recorded rationale, evidence, analysis tier description, score, source severity, response reason or explicit no-action policy explanation, source and received/occurred timestamps. Score is not presented as probability, mock reasoning is labelled, and all responses remain simulated. History paging still needs the updated backend; the older-backend fallback covers the latest 100 arrivals.

Validation: 6 demo-session tests passed, including pending-to-final identity/verdict parity and history offset; frontend build/lint passed with existing warnings. Headless Edge verified aligned rows, matching records across tabs, visible explanation/evidence/response headings, click-through and simulation isolation with no page errors. Magic/ui-ux tooling remains unavailable; existing components were adapted and visually reviewed.

## Simulation history filters (2026-10-10)

History can be filtered by decision (suppressed/escalated/pending/failed), event type, source, host, response selected/none/pending, and case-insensitive search across event data, reasons, evidence and response fields. Filters combine, reset pagination and display matching counts; Clear filters restores all rows. Updated backend applies filters across the bounded 5,000-event session before 100-row pagination. Older backend compatibility applies the same filters to the latest 100 available arrivals and retains its restart notice.

Validation: build/lint passed with existing warnings; 7 simulation tests passed, including a match beyond the first unfiltered page, combined filters and empty results. Browser verified ID search, combined decision filtering, event type empty state, reset, visible reasons and click-through. No live collection or simulation controls were changed during browser validation.
