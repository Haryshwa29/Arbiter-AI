# L1 guided response and severity deadlines

The dashboard event panel now includes recommended next steps. LLM-tier answers
may include up to four bounded manual investigation steps in the existing local
triage call; no extra model call delays ingestion. These are labelled AI advice,
not verified conclusions or executable commands. Rules-only decisions, unavailable
models and older records receive explicitly labelled policy-guided steps.
Package-update advice checks authorization, provenance/version and service health;
an update alone cannot authorize containment or automatic rollback.

## Deadlines and authority

The separate `ingestion.response_workflow.ResponseWorkflow` owns durable SQLite
review cases, deadlines, review notes, one bounded deferral, rejection and an
emergency stop. It runs independently of inference. Default windows are critical
60 seconds, high 300 seconds, medium 1800 seconds; low has no automatic deadline.
Severity uses source severity and deterministic guardrail/correlation findings,
never model confidence or the L1 numeric score. The deadline starts at analysis
completion, recorded in the local read model. Older records use received time.
Repeated reads do not reset it. Overdue reviews are shown in the Live review queue
and recorded in the audit trail. No external notification delivery is implemented.

Default mode is **review required**: expiry marks a case overdue without touching
the device. Analysts can read cases; control POSTs require a local administrator
session and CSRF. Mark reviewed, reject, or defer require a reason. Deferral is
allowed once, before expiry, for one original severity window.

A local administrator may explicitly enroll one eligible case for a five-minute
peer block at its deadline. This is per-incident approval, not blanket model
authority. Only repeated-login-failure or verified Defender/Sysmon malware/network
correlations qualify. The existing local-host/collector/proposal restrictions
remain, and the operator must supply protected management/service networks.
No free-form command or new action kind is accepted.

At execution the scheduler rebuilds the correlation using local collector evidence,
requires a same-host/account or process-identity peer match and a current record
no older than 30 seconds, checks scope, capacity and native firewall verification,
and then invokes the typed executor. Old or unsupported evidence, changed targets,
protected peers, missing permissions or failed native checks require human review.
No automatic retry is performed. Repeated telemetry cannot re-enroll the same
tracked incident identity. Stop cancels pending enrollments and persists across
restart; resume does not re-arm cancelled cases. Interrupted execution requires
inspection rather than blind retry.

The response deadline and native block expiry are separate timers. Undo uses the
existing native removal verification and audit record. It cannot restore an
interrupted session or undo downstream effects. Native expiry is independent of
the scheduler. Expiry is not reported as verified until cleanup is checked.

## Simulation and playback

Local Demo & Replay uses isolated databases for cases, timers and simulated
responses, without constructing or calling an OS actuator. The public browser
simulator now shows the same guidance, severity countdown, one-time deferral,
rejection, explicitly scheduled simulated approval, stop and Undo. Public controls
modify browser memory only, expire simulated responses after five minutes and
reset on refresh. Background tabs can delay updates. They never call operational
APIs, create an OS actuator or execute the recommended operation. No public
device-control endpoints are added. Model-provided manual steps are bounded in
the public AI function and labelled separately from policy-guided fallback.

Playback supports only steady 1× (three-second minimum interval) and 2× (1.5-second
minimum). The backend rejects 5×, 10× and burst/variable delivery, not just the UI.
Local replay will not enqueue a second event while analysis is pending/running.
The public browser implementation remains sequential and uses the same speed cap.

## Validation and deployment

Tests cover model advice provenance, package verification guidance, auth/CSRF/role
gates, deadlines, deferral limits, cancellation, restart, simulated isolation,
untrusted/stale evidence, native verification failure, undo and slow-model playback.
Native calls are mocked in these tests: they do not establish real Windows
enforcement or real-model recommendation quality. No live firewall changes were
made during this implementation.

The updated self-hosted frontend and release archive must be installed and the
existing dashboard service restarted before the running installed app changes.
No new runtime dependencies were added. Demo & Replay, Event Details and Live
reuse existing controls; Magic and ui-ux pro max were unavailable in this session.
