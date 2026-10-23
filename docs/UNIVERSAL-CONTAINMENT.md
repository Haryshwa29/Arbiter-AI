# Shared containment and portable deployments

Status: architecture and implementation milestones, updated October 19, 2026.
The terminal agent, scoped approval and Linux nftables adapter are implemented;
see AGENT-LIVE-VALIDATION.md for tested coverage and remaining live validation.

## Product direction

Keep containment, CLI operation and portable packaging in this repository.
Windows and Linux are first-class targets with shared policy and contract tests.
Device images, launchers, resource profiles and lab deployment manifests are
deployment options rather than a separate product fork. One implementation owns
ingestion, triage, response policy and the shared enforcement interface.
Customer telemetry stays within
the customer's network, including private cloud networks.

## Current implementation and gaps

- `arbiter/ingestion/protection.py` implements approved local IP blocks. The
  dashboard retains its global-address Windows gate; the terminal agent opts
  into explicit network scope, management exclusions and native verification.
  Windows scheduled cleanup and Linux kernel element expiry last five minutes.
- `arbiter/respond.py` has a broader action catalog. Catalog command strings
  are not evidence that those actions have production-ready actuators.
- `docs/PORTABLE.md` describes an existing Windows portable distribution;
  small Linux/ARM devices and isolated hosted rooms need additional packaging
  and validation. No minimum hardware claim is established for those targets.
- Passive monitoring cannot isolate a host without an authorized enforcement
  point: a host agent, an inline gateway/firewall, or a cloud control interface.

## Shared containment contract

Use a typed request containing deployment scope, enrolled asset identity,
action kind, validated target, evidence references, policy version, approval,
expiry and an idempotency key. Do not execute commands supplied by a model or
an ingested event. Adapters construct their own narrowly scoped operations.

Discover capabilities per enrolled asset. Unsupported operations return an
explicit unsupported result; neither product may claim a breach was contained
from an alert or an action proposal alone.

Persist the action lifecycle: proposed, approved, applying, applied, verified,
undo requested, reverted, expired or failed. Record actor, scope, evidence,
timestamps and adapter results. Reconcile interrupted operations on restart.
Verify enforcement and removal with the adapter; elapsed time alone is not
proof that a rule disappeared. Expiry must survive controller failure.

Preserve the current manual approval boundary. LLM findings remain proposals.
Any future deterministic automatic policy requires separate explicit opt-in
and validation. Keep response effects outside `triage.py`.

Protect management connectivity, DNS and explicitly configured essential
services. Bind approval to the exact action and reject stale evidence. Limit
duration, concurrent actions and scope; preserve operator rollback access.
Do not present process termination as reversible: session/account/process
actions require action-specific recovery semantics before being enabled.

## Deployment profiles

| Profile | Analysis location | Enforcement requirement |
|---|---|---|
| Existing installation | Local model or explicit rules-only mode | Enrolled local host adapter |
| Small appliance | Local rules; model on device if measured capacity permits, otherwise a private-network model service | Enrolled host agents or an explicitly configured gateway |
| Private cloud lab | Per-room controller or tenant-isolated service within the deployment network | Room-scoped agent, virtual firewall or cloud adapter |

Share behavior and policy across profiles; advertise only capabilities actually
available on each target. Keep public website simulation separate from real
containment and credentials.

For HTB/THM-style exercises, enroll only machines and enforcement points the
operator can administer and is permitted to modify. VPN access alone provides
neither control nor permission to install agents. Support explicit private lab
CIDRs through scoped enrollment, rather than globally relaxing IP validation.
Do not infer platform integration from generic telemetry compatibility.

## Implementation milestones and acceptance

1. Extract a typed adapter boundary around existing Windows protection while
   preserving its proposal, approval and expiry behavior. Add shared contract
   tests for validation, duplicate requests, expiry, restart and failed undo.
2. Add a Linux nftables adapter with dedicated Arbiter-owned rules, native TTL,
   protected management routes and verified rollback. Exercise it in disposable
   network namespaces/VMs before enabling it on real hosts.
3. Add explicit asset enrollment and lab scopes. Test an authorized isolated
   Linux room end to end: receive telemetry, detect, approve, apply, verify,
   expire and verify restored connectivity. Include benign traffic and noisy
   events to measure false containment.
4. Build portable packages from the same tested source revision. Benchmark
   x86-64 and ARM64 separately for queue throughput, detection/containment
   latency, RAM, disk and recovery after power loss. Keep unsupported profiles
   visibly unavailable.
5. Add room isolation and narrowly scoped cloud credentials where needed.
   Test that actions and telemetry cannot cross room boundaries. Record exact
   OS/provider capabilities and limitations in release notes.

## Next checkpoint: a live vulnerable box

Run `python -m arbiter readiness` inside the target Windows or Linux machine;
`--json` supports saving the report and `--require-ready` fails explicitly when
CLI enforcement is unavailable. This read-only command does not connect to a
remote VM, request elevation, collect telemetry or modify firewall rules.
Executable discovery is a prerequisite check, not a functional firewall test.

The checkpoint is reached only when an authorized live exercise demonstrates:

1. Real target telemetry reaches Arbiter and produces an evidence-backed alert.
2. The operator approves an exact, temporary containment action through the CLI.
3. Independent connectivity checks demonstrate the selected attacker flow is
   blocked while management and the chosen legitimate service remain reachable.
4. Explicit undo and automatic expiry are each exercised and independently
   verified, including controller shutdown during an active block.
5. Evidence records detection, approval, enforcement and recovery timestamps,
   affected traffic and resource usage. Report narrow flow containment honestly;
   do not infer removal of attacker persistence or complete host recovery.

Run the same acceptance procedure on both Windows and Linux. The first
successful box is an initial result; cross-platform completion requires both.
Management/lab scope protection, typed IP firewall operations, approved CLI
execution and the Linux adapter are now implemented. Next steps are live-room
validation, broader Linux telemetry and privileged Windows firewall validation.
No THM machine has passed this checkpoint yet. Isolated namespace filtering
tests use synthetic authentication input and do not count as a live breach.

Before claiming implementation complete, run the repository test suite and
seed/sample-run checks, shared adapter tests, and real disposable-environment
enforcement/expiry checks. Simulation alone does not establish live containment.
