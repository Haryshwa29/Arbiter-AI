# Local security tools

Real Windows runtimes discover tools every 30 seconds and auto-connect sources
that have never been configured. Explicitly disabled sources remain disabled.
Simulations never discover local tools. Discovery makes no external requests.

## Provisioning

`python -m arbiter setup-monitoring` provisions osquery 5.23.1 from its official
release with a pinned SHA-256 and requests Windows approval for Sysmon's service
and driver. Where available, setup enables Windows' built-in Sysmon feature using
local Windows components without an automatic restart. Older systems use the
Microsoft standalone download. Its Microsoft Authenticode signature
must be valid. Downloads occur only during explicit setup. Offline deployments
can preinstall the tools. This setup currently supports Windows x64.

Existing Sysmon installations/configurations are preserved. New installations
record process creation, non-loopback network connections and DNS queries, with
SHA-256 hashes. Certificate revocation lookup is disabled in the supplied Sysmon
configuration. Installation accepts the Sysmon license. No remote enrichment
or response scripts are configured. Antivirus settings are unchanged.

osquery runs fixed read-only inventory queries every five minutes, with extensions
disabled. Setup installs a protected Program Files copy for system services.
Elevated discovery excludes the per-user LocalAppData copy. `--inventory-only`
provisions that per-user copy without elevation.

Discovery connects readable Windows System/Application/Security channels, Sysmon,
Microsoft Defender's operational channel and standard/managed osquery paths.
New log sources start with future events; inventory is collected immediately.
Existing channel configuration is preserved rather than silently widened.
An installed Sysmon with an unreadable Windows logger is shown as a source error,
not as an uninstalled tool or a connected source.

Defender findings include malware detections, action results/failures, attack
surface reduction and protection/configuration changes. Event 1117 preserves
its action (including Allow) and does not prove remediation. Log access does
not prove antivirus protection is enabled. Arbiter runs no antivirus scans.

## Wazuh and network sensors

Wazuh reads an administrator-selected absolute path to existing manager
`alerts.json`, typically `/var/ossec/logs/alerts/alerts.json`. Arbiter and the
manager need a readable local file/mount. This does not install a Wazuh manager,
agent or indexer, or connect its remote API. Configure the file in Data Sources.
Reading historical records is explicit; future records are the default.

The reader handles partial lines, replacement/truncation, invalid/bounded records
and queue pressure. Cursors persist; stable IDs deduplicate redelivery. Rotation
between polling cycles can lose unread records in the old file; this is not a
lossless forwarding service.

Rule/agent/manager identity, groups, MITRE metadata, raw logs, usernames, network
and file-integrity evidence are retained. Levels 0–15 map linearly to Arbiter's
0–10 severity and the original level remains in metadata. Authentication groups
provide correlation semantics; other findings have generic security semantics.
Wazuh active response is never invoked. Wazuh, Defender and osquery findings
cannot qualify for Arbiter's local Windows firewall actuator.

Existing Suricata EVE/private syslog readers support configured network sensors.
Endpoint tooling does not provide network-wide visibility. Zeek transport and
managed network-sensor provisioning remain unimplemented.

## Verification

Tests cover normalization, raw evidence, severity validation, file reads, queue
pressure, deduplication, triage, protection exclusion, Defender action semantics,
local discovery and disabled sources. Real installation is reported separately.

Data Sources and Live reuse existing components; only explanatory copy and source
filters changed. No runtime dependency was added. Magic and ui-ux pro max were
unavailable; neither was used for these small UI changes.

### October 11 installed-device validation

The system installation was upgraded and restarted with accounts/history preserved.
Protected osquery auto-connected and delivered 18 real inventory snapshots across
the validation restarts. Defender's channel connected without errors; no new
detections were observed. The worker is running with the existing mock backend,
not local AI inference.

Microsoft's standalone Sysmon failed event-manifest registration on this device.
Setup enabled the Windows built-in component without rebooting, and its service
is running. Its channel currently fails with Windows' "instance name passed was
not recognized as valid by a WMI data provider" error. Re-registering/refreshing
the channel did not resolve that fault. Arbiter explicitly shows this installed
source as Error, with zero received events. Sysmon telemetry is not verified.

The full suite passes 270 tests, with 12 platform skips and 3 subtests. The release
contains the setup resources and updated collectors. Native installation findings
above are separate from fixture/temporary-store tests.

### October 12 decision integration

The reboot resolved native Sysmon's event-log fault; its channel was queried
successfully as administrator, and over 55,000 real Sysmon records had reached
the installed store during verification. These counts include older retained
records and are not counts of attacks.

High-priority findings from Defender, Wazuh (level 12+), Suricata (priority 1)
and GuardDuty (severity 7+) now require deterministic review. The model and benign
host history cannot dismiss them. Severity priority is based on the original tool
record, not a correlation-raised score. A tool finding is an alert for review,
not proof of compromise or executed remediation.

osquery process/startup/task snapshots check observed command fields against
existing guardrails. At most five findings per 100-row snapshot are summarized;
this is bounded sampling, not an exhaustive endpoint scan. No SQL, commands or
scans supplied by events are executed.

Windows protection status is automatically sampled every five minutes using
fixed read-only Defender/firewall queries. Known disabled controls produce an
alert, unknown controls remain unknown, and healthy observations stay inexpensive.
The latest snapshot is supplied as dated asset context. Enabled settings do not
guarantee safety or prove that individual firewall rules are correctly scoped.

Defender malware findings correlate to the exact file path of recent Sysmon
executables and their network connections on the same host. Container/multi-path
descriptions are not guessed into a process identity. A temporary IP-block proposal
requires the actual Defender transport plus a real local Windows/Sysmon escalation
and a public address. Uploaded metadata cannot assert that transport provenance.
Execution still requires explicit administrator approval and keeps the existing
five-minute expiry/undo/audit requirements. No real firewall blocks were performed
as part of validation.

Native telemetry's broad host/event-class history can no longer suppress an
unrelated executable. A bounded exact process-context key includes SHA-256,
command, user, parent path/command, environment facts, asset criticality, observed
protection context and model. Only real local-model processing of native Sysmon
events can teach that context; five benign assessments are required, with no
unresolved escalation or overruled suppression. Changes produce a new key. Broad
human feedback also applies to these scoped memory rows. Event/Verdict signatures
and audit rows retain their original compatibility. Guardrails and correlations
still precede the shortcut.

Queue scheduling prioritizes guardrails, then inexpensive context, ahead of
ambiguous model work, with every hundredth claim preserving FIFO progress. Indexed
audit lookups, bounded time-range correlation, covering metric indexes and cached
signature counts remove repeated full-record scans. Memory caches detect writes
from other SQLite connections so external human feedback cannot become stale.
An additive migration preserves retained records, decisions and raw evidence.
There remains one analysis worker and a 10,000-record queue. Backpressure retries
source cursors; it does not guarantee lossless Windows log retention under a
sustained flood. The installed device had a substantial backlog after reboot;
capacity limits remain visible rather than being described as complete protection.

The installed local `qwen3.5:4b` model was verified without remote model/host
metadata, answered a real local inference check, and was connected through the
authenticated API. Model choice persists. The analysis backend/model is now
recorded per new event and preserved during recovery; old unrecorded decisions
are not relabelled as local AI when the current backend changes.

UI changes reuse Live's source filter and EventPanel's existing reasoning label.
Magic/ui-ux pro max were unavailable for these small edits; neither was used.

Arbiter's own read-only log queries are recognized only for native Sysmon records
on this host with the exact executable, approved command/flags and matching parent
PID or service launch arguments. Other uses of wevtutil, including log clearing,
are not exempt. Guardrails and new correlation signals still take precedence.
This reduces the monitor's feedback loop without exempting a general utility.

Cloud-model names and declared remote models are omitted from the local model
selector. Every inference checks local model listing/details before sending the
event prompt, rejecting cloud routing and remote aliases. Prompt requests bypass
system HTTP proxies. These checks rely on the configured inference service being
administrator-controlled, as before. Ollama documents that even its local API can
route cloud models: [Ollama cloud documentation](https://github.com/ollama/ollama/blob/main/docs/cloud.mdx).
Non-finite or boolean confidence values fail toward escalation.

Reordered processing cannot overwrite a newer protection or inventory snapshot
with an older one. Reserved protection context fields cannot be overwritten by
arbitrary inventory table names. Accounts, historical decisions and raw records
remain preserved; no retention policy or global firewall settings were changed.

Final code validation: 289 tests and 3 subtests passed, with 12 platform skips;
the sample seed/triage checks, dashboard build and lint passed (two existing Fast
Refresh warnings). Native inference and collector checks are reported separately
from the tests. Model throughput and Windows log rollover remain capacity limits.

Final installed-device check: local Qwen, Security/System/Application logs, Defender,
osquery and protection snapshots were active; Sysmon had delivered over 60,000
retained records. The queue remained close to its 10,000-record limit and Sysmon
was reporting backpressure, so complete real-time coverage was not claimed.
The final additional optimization (avoid reserializing inventory for every ordinary
event and narrow correlation for verified collector reads) passed tests and was
packaged, but Windows reported cancellation of the administrator prompt for its
activation. That last optimization is not yet active in the system installation.

Activation follow-up: the user reported that the hidden Windows approval prompt
had not appeared. Retrying with a visible approval window succeeded on
2026-10-13 at 02:22 UTC. The installed build's SHA-256 matched the tested package,
and the service reopened its local API after startup. A read-only device check
confirmed the local Ollama worker was alive and over 85,000 Sysmon records had
arrived. Approximately 10,000 records remained queued; collectors were still
reporting backpressure. Read-only indexed database metrics completed in under
0.1 seconds, but the live status API still exceeded its 20-second client timeout.
The optimization is now installed; the throughput limitation remains unresolved.
An extended authenticated check subsequently returned successfully in 48.9
seconds: local `qwen3.5:4b`, worker alive, zero processing/normalization failures,
9,990 queued records, and Defender/Windows sources connected. Sysmon had received
85,837 records; osquery and protection snapshots still reported queue-full retries.
The retained protection snapshot showed all four observed Defender controls and
all three firewall profiles enabled. This snapshot does not prove freshness of
every control while collection is delayed.
