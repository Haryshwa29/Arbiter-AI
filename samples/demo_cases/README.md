# Arbiter live demonstration cases

Arbiter continuously watches the files in `Active`. It reloads the folder when
a `.json` or `.jsonl` file is added, edited, renamed, or removed. Files run in
filename order and repeat while the portable demo is open.

These are simulated security events processed through the real Arbiter pipeline:
deterministic guardrails, prefilter, local Qwen reasoning when needed, memory,
audit storage, and the dashboard. They are not telemetry collected from the
computer hosting the demonstration.

## Active scenarios

| File | Scenario | Intended result | Main decision path |
|---|---|---|---|
| `01-benign-backup-learning.json` | Seven normal database backup spikes | Suppress | LLM first; history can earn prefilter suppression |
| `02-ssh-brute-force-then-success.json` | Root brute force followed by success | Escalate | High deterministic score |
| `03-remote-download-and-execute.json` | Database user pipes a remote script into a shell | Escalate | Security guardrail |
| `04-suspicious-privilege-escalation.json` | User added to sudo by a temporary helper | Escalate | Security guardrail/context review |
| `05-unknown-host-creates-root-user.json` | Unknown asset creates a UID 0 user | Escalate | Security guardrail |
| `06-benign-ci-container-burst.json` | Expected CI container churn | Suppress | Scoped environment fact + local model |
| `07-unfamiliar-failed-login.json` | Low-severity failed login with no history | Escalate conservatively | Local model |
| `08-http-request-flood.json` | Large distributed HTTP flood | Escalate | High deterministic score |
| `09-syn-flood.json` | Kernel reports a SYN flood | Escalate | Deterministic score/context |
| `10-slowloris-connection-exhaustion.json` | Connections held open with incomplete headers | Escalate | Local model |
| `11-benign-launch-traffic-spike.json` | Product-launch traffic with normal errors | Demonstrates false-positive pressure | Local model; no launch fact is seeded |
| `12-impossible-travel-vpn-login.json` | Same user appears in two countries six minutes apart | Escalate | Security guardrail |
| `13-unusual-country-admin-login.json` | Admin uses an unfamiliar residential proxy | Escalate | Local model/context |
| `14-system-binary-tampering.json` | SSH binary changes without a package update | Escalate | Security guardrail |
| `15-ransomware-mass-file-rename.json` | Thousands of files receive a new extension | Escalate | Security guardrail |
| `16-failing-disk.json` | SMART degradation and filesystem damage | Escalate for attention | Local model; operational risk rather than attack |

The intended result documents the demonstration purpose; model-routed cases are
probabilistic and may vary. A differing result is useful evidence to discuss and
can become a new evaluation case. Guardrail decisions remain deterministic.

## Add a requested case during a demonstration

1. Copy `Templates/00-new-live-case.json` into `Active`.
2. Keep the `00-` prefix so the new case runs next after Arbiter reloads.
3. Give it a descriptive filename, such as `00-requested-powershell-case.json`.
4. Edit `name`, `expected`, `notes`, and the fields inside `event`.
5. Save valid JSON. Arbiter detects the change automatically and reports the
   reload in the Start Arbiter window.

Required event fields are `source`, `host`, `event_type`, and `message`.
`severity` is a number from 0 to 10. `fields` contains useful structured clues
such as `user`, `src_ip`, `path`, `binary`, or counts. `expected` and `notes`
explain the scenario to people; Arbiter does not use them to make its decision.

Do not paste real secrets, credentials, customer names, or sensitive logs into a
demonstration case. Test only environments and events you are authorized to use.

