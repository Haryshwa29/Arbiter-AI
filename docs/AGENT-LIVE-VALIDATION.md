# Terminal agent: Windows and Linux live validation

The same Arbiter package runs inside the protected VM. No TryHackMe room names,
answers or attacker addresses are built into detection. The terminal agent owns
its own state and uses the existing ingestion, correlation, triage and audit
pipeline. It starts no web server and makes no cloud inference calls.

## Build and transfer

From the repository run `python tools/build_agent.py`. This creates
`dist/arbiter-agent.pyz` and its SHA-256 sidecar. Transfer both to the target
through the room's available file-transfer mechanism and verify the digest.
The artifact contains readable Python source, requires Python 3.10 or newer on
Windows/Linux, and has no Python runtime dependencies. It does not bundle
Python, Ollama, a model or nftables; a target missing Python needs provisioning
before this artifact can run. The dashboard build is not required.

**Policy hold (2026-10-19):** THM's current Acceptable Use Policy sections
9.2–9.3 restrict AI-agent access and using lab content to evaluate or develop AI
systems. Do not resume automated THM access, collect more lab evidence, or use
the existing lab observations for product tuning without written authorization
from THM covering this activity. User consent to their account is insufficient
to override these platform restrictions. See
https://tryhackme.com/legal/acceptable-use-policy.

The initial evaluation candidate was THM's Windows **Incident Response Process**:
https://tryhackme.com/room/incidentresponseprocess. It provides a running Windows
workstation and browser/RDP access. This is a candidate, not a verified Arbiter
integration: check installation permission, Python, privileges and active
telemetry after launching it. Its miner/outbound-connection scenario may need
additional detection coverage; do not substitute a brute-force fixture for a
successful response to the actual room's incident.

Windows **Windows Threat Detection 1** is another collection/detection candidate:
https://tryhackme.com/room/windowsthreatdetection1. Linux **Linux Live Analysis**
and **Linux System Hardening** provide complementary investigation and firewall
validation environments:
https://tryhackme.com/room/linuxliveanalysis
https://tryhackme.com/room/linuxsystemhardening
Existing log evidence is not proof of a currently active breach or containment.

## Start with observation

Windows, from a terminal inside the target:

```powershell
python .\arbiter-agent.pyz readiness
python .\arbiter-agent.pyz agent --state-dir .\arbiter-room-state
```

Linux, from a terminal inside the target:

```sh
python3 ./arbiter-agent.pyz readiness
python3 ./arbiter-agent.pyz agent --state-dir ./arbiter-room-state --auth-log /var/log/auth.log
```

The agent defaults to explicitly labelled **rules-only** analysis. Deterministic
rules still run; ambiguous events escalate for operator review without claiming
model inference. For installed local inference, add `--backend ollama --model`
followed by the installed model name. No model download occurs. Keep inference
inside the deployment network.

Windows reads Security and Defender logs and an installed Sysmon channel.
Linux currently tails OpenSSH password/public-key authentication from
`/var/log/auth.log`, `/var/log/secure`, or `--auth-log`. Journal-only distributions
need a local auth log configured first. Both systems also take local process/TCP
snapshots. Two sustained high-CPU samples from a temporary executable with
same-process TCP activity produce a review finding, without room-specific names
or addresses. This narrow rule can also match legitimate temporary software.
This release does not provide Windows/Linux full EDR coverage or an SSH/RDP
deployment client. Readiness discovers tools; `status` reports actual collector
errors. Both must be inspected before assuming coverage. Collection begins at
the log end on first use and resumes a persisted cursor on later runs.

## Enable approved containment

Use a privileged target terminal (Windows administrator; Linux network-admin
privileges and an installed nft executable). Specify the permitted target
network and every management, DNS and essential service address that must never
be blocked. These are deployment configuration, not detection signatures.

For example, if the authorized lab network is `10.20.0.0/24`, management peer is
`10.20.0.2`, and DNS is `10.20.0.3`, append:

```text
--enable-containment --allow-network 10.20.0.0/24 --protect-network 10.20.0.2 --protect-network 10.20.0.3
```

Replace these examples with the actual room values. Do not enroll broad ranges
without knowing the room's network. The SSH client address from SSH_CONNECTION
and resolved local interface addresses are added to protection automatically.
RDP peers, VPN gateways, DNS, alternate management paths and essential remote
services must be included explicitly. A peer used for management cannot also be
a containment target. This release does not automatically discover all critical
infrastructure or offer guaranteed availability under arbitrary network changes.

Commands at the running agent's terminal:

```text
status
events
actions
approve EVENT_ID EXACT_IP
undo ACTION_ID
quit
```

Output is JSON, suitable for a terminal transcript. `events` shows up to 100
recent events with analysis, proposals and action history. It can include
sensitive host/log detail; retain the transcript within the lab boundary.

The first shared containment case is repeated authentication failures for one
host/account/source within five minutes. Existing Windows/Sysmon correlations
also support qualifying suspicious process/network activity, including verified
Defender findings. These are finite supported cases; an arbitrary malicious
process or an unrelated outbound connection will not automatically qualify.

Approval must repeat the exact proposed IP. Only recent, local, collector-owned
evidence qualifies; API uploads, demo and replay inputs cannot authorize blocks.
Protected or unenrolled addresses are refused. The maximum is ten active
actions. Approval installs a five-minute bidirectional peer IP block and checks
the native rule state. It does not terminate processes, patch vulnerabilities,
revoke stolen credentials or remove persistence.

Windows registers OS-owned scheduled cleanup before creating its firewall rules.
Linux uses an atomic nftables transaction and kernel-expiring set elements.
Expiry remains effective if the agent exits. Linux empty tables may remain until
recovery/undo; they have accept policies and cannot match the expired peer.
Failed verification triggers rollback; failed cleanup stays visible and blocks
another approval for that target. Restart reconciles interrupted/expired actions
without replaying enforcement. Preserve the same state directory for recovery.

`quit` stops collection; it does not claim immediate rollback. Use `undo` first
for immediate release. Keep an independent console available for recovery.

## Acceptance evidence

1. Confirm real target logs are received and distinguish current activity from
   historical artifacts. Record source health, backend and detection rationale.
2. Confirm the proposed action is tied to the actual incident and supported by
   evidence. Do not provide room answers as trusted findings.
3. Probe the selected connection and legitimate/management traffic before action.
4. Approve the exact action; verify that the selected traffic stops using an
   independent probe. Native rule presence alone is insufficient.
5. Verify undo restores connectivity. Repeat separately to verify five-minute
   expiry while the agent is stopped, preserving legitimate connectivity.
6. Record timing, false positives and remaining attacker access. Report exactly
   what was contained; one IP block does not prove a host is clean.

## Evidence obtained during development

`tools/smoke_agent_linux.py` refuses the initial network namespace and runs only
inside a disposable root-owned Linux namespace. It creates a local echo service
and separate source addresses, tails synthetic auth records through the real
collector/pipeline, approves a real nftables block, probes filtering and protected
management traffic, and verifies native removal and restored connectivity.
`--expiry` additionally waits the real five minutes with the agent stopped.

This is synthetic detection input with real network enforcement. It is not a
THM connection, a real SSH breach, or validation of the Windows firewall adapter.
A THM Incident Response Process Windows VM has now been launched and reached
over a target-only VPN route. The portable package and official Python embedded
runtime were transferred and their SHA-256 digests verified inside the VM.
A 35-second observation run collected three real process/network findings:
a temporary-folder executable repeatedly consumed approximately one CPU core
and attempted outbound TCP connections. The shared prefilter escalated them;
no room-specific executable or peer was built into detection. The unprivileged
terminal could read 19 processes and Defender events, but Security log access
was denied. Raw evidence is retained locally in `work/thm-observation.json`.
The user approved elevation, but the VM approval prompt was not accepted after
the policy review identified the restriction above. No containment action was
performed. Local VPN and transfer services were stopped. Actual incident
containment is not verified. Preserve the observations as a restricted session
record; do not promote them into model data, fixtures or tuning inputs.

The latest package passed native Linux namespace filtering/undo validation
(`work/agent-linux-artifact.json`), and the suite passed 307 tests with two
platform skips and 18 subtests. Earlier five-minute Linux expiry validation
remains synthetic detection input with real packet filtering, not a THM result.
