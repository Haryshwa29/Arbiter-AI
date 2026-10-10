# Connectors and setup

Start Arbiter, sign in as an administrator, open **Data Sources → Add Data Source**,
fill in the source settings and select **Enable collection → Save source**.
One source is enough. No live source starts on a fresh installation.

| Source | Implemented transport | Setup |
|---|---|---|
| Windows Events | Built-in wevtutil XML polling | Select Security/System/Application; grant log-read permissions if needed |
| Sysmon | Sysmon Operational event log | Install/configure Sysmon yourself, then enable |
| osquery | Fixed osqueryi JSON queries | Set absolute installed osqueryi executable path |
| Suricata | Tail EVE JSON file | Set absolute readable eve.json path |
| Syslog | UDP RFC3164/5424 | Loopback:5514 default; specific private IPv4 + sender allowlist for lab forwarding |
| CloudTrail | AWS LookupEvents | Optional AWS SDK, region, credential profile |
| GuardDuty | AWS finding APIs | Optional AWS SDK, region, existing detector |
| API | Authenticated JSON POST | Session + CSRF + admin; no anonymous public endpoint |
| File/Replay | JSON/JSONL/CSV | Demo & Replay; preserves existing cases |
| Zeek/Azure/GCP/future AWS | Coming Soon | No collection transport implemented |

**Available** means an implemented connector can be configured. **Configured**
means settings have been saved or collection is starting. **Connected** means a
poll completed successfully. **Listening** means the UDP socket is bound.
**Disabled** means collection was turned off. **Not detected** means the enabled
Sysmon channel could not be read; it can also mean insufficient permissions.
**Error** describes unavailable sources or collection failures. **Coming Soon**
connectors cannot be enabled. Configuration alone is not a connection test.

## Windows

The collector reads Security, System and Application every three seconds in
batches of up to 200 records/channel. First enable starts at the current end,
unless **Read existing history** is checked. It records channel/record/time
identity for deduplication and detects a lower record ID after a log clear.
Security reads often require membership in Event Log Readers or an appropriately
authorized elevated process. Arbiter never changes membership or audit policy.
Enable only the access appropriate to your lab/deployment.

Mappings prioritize 4624, 4625, 4634, 4648, 4672, 4688, 4697, 4720, 4726, 4732
and 1102. Other events remain generic system observations with source level
mapped to severity. Do not clear logs to test reset behavior. For event details,
use Live Events → click event → Normalized Event / Raw Event / Arbiter analysis.
`wevtutil` is launched with fixed argument arrays and no shell; logs are XML
parsed with entity/doctype rejection. See [Microsoft wevtutil documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil).

## Sysmon

Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
Review the license and configuration before installing the privileged service.
For an authorized disposable lab, from an elevated terminal in the download
folder, explicitly install the provided lab configuration:

```powershell
.\Sysmon64.exe -accepteula -i C:\path\to\Arbiter-AI\docs\sysmon-lab.xml
```

Review that XML first: it enables process, network, file-create and DNS telemetry
and may be noisy. It is a lab example, not an organization-wide policy. Existing
Sysmon installations should use their reviewed configuration; installing it a
second time is unnecessary. Updating that policy is your separate administrative
action. Arbiter reads the existing `Microsoft-Windows-Sysmon/Operational` channel.

Mappings cover process (1), network (3), driver (6), image (7), process access
(10), file creation (11), registry (12–14) and DNS (22). Collection cannot invent
events that Sysmon's active configuration excludes. The supplied minimal lab
configuration does not enable every supported event class. An ordinary shell
launch should be an observation; risky command lines retain existing guardrails.

## osquery

Install osquery yourself, then set the `osqueryi.exe`/`osqueryi` absolute path.
Arbiter uses fixed `SELECT * FROM <table> LIMIT 100` queries, JSON output and
disabled extensions; no arbitrary SQL from uploads/UI. Tables include system_info,
os_version, processes, logged_in_users, listening_ports, interface_addresses,
programs, startup_items and scheduled_tasks. Platform-specific unavailable tables
are reported, not fabricated. Default interval is 300 seconds (minimum 60).
Snapshot observations enrich **Assets & facts → Observed asset context**.
See [osquery command-line flags](https://osquery.readthedocs.io/en/latest/installation/cli-flags/).

## Suricata

Run your existing Suricata sensor and enable EVE output. Set its readable
`eve.json` path; Arbiter does not install a sensor or sniff traffic directly.
The first read includes existing records. Subsequent reads checkpoint byte
offsets, hold incomplete writer lines, skip malformed/oversized lines and handle
inode change or truncation. Rapid copy-truncate/regrowth between polls can evade
rotation detection; use rename rotation when possible. Supported EVE event types
are alert, dns, http, tls, flow and fileinfo. Passive records are observations;
signature findings receive Arbiter's own guardrail/criticality/history/AI treatment.
See [Suricata EVE documentation](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html).

## Syslog

Arbiter binds `127.0.0.1:5514/UDP` by default and accepts only loopback senders.
For a lab firewall/Linux host, bind a specific private IPv4 address and set
allowed sender IPs/CIDRs; use your host firewall to restrict those senders too.
Wildcard/public binding is rejected. Example sender configuration for rsyslog:

```text
*.* @192.168.1.10:5514
```

This MVP is UDP, without TLS or cryptographic authentication. Sender allowlists
do not prevent spoofing on an untrusted network. Use an authenticated local
forwarder/TLS gateway if transport authentication is required. Do not expose
5514 to the Internet. RFC3164 lacks year/timezone; Arbiter records the UTC and
current/previous-year assumption. RFC5424 timestamps retain their explicit zone;
structured data is retained for review. Raw syslog input is never executed.

## Zeek foundation

The registered Coming Soon adapter uses the same Collector interface. Future
parsers should map conn.log, dns.log, http.log, ssl.log/tls.log, files.log and
notice.log to SecurityEvent, preserving Zeek UID for links and notices as findings.
JSON log support and TSV header handling are not implemented in this iteration.
Zeek cannot currently be connected from the dashboard.

AWS setup and deferred cloud adapters are in [CLOUD_INTEGRATION.md](CLOUD_INTEGRATION.md).
