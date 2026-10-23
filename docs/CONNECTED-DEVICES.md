# Connected devices and network edges

Arbiter includes a stdlib-only, read-only `attachments` source. Source and
portable dashboards discover it automatically on Windows/Linux, and the
terminal agent starts it as well. Explicitly disabled configurations stay
disabled. Isolated simulations never discover local devices.

In **Data Sources → Connected devices & network edges**, administrators can
enable/disable collection and set the polling interval (default 15 seconds,
minimum 5 seconds). A poll takes additional time to collect native snapshots.
The card shows counts and coverage limitations. Events and evidence are retained
in **Live**, with verdicts in the normal audit path. A retained baseline means
"previously observed," not "trusted."

## What it observes

| Signal | Windows | Linux |
| --- | --- | --- |
| USB device presence and changes | Present PnP entries | USB sysfs identity, class, vendor/product and serial when available |
| Bluetooth device enumeration | Present BTHENUM/BTHLEDEVICE entries; not proof of an active link | Not implemented |
| Active adapters, including observable tethering adapters | Get-NetAdapter | sysfs; labels wireless/USB when observable |
| Nearby peers | Usable IPv4 neighbor-cache entries | Complete IPv4 ARP-cache entries |
| Established TCP connections involving those peers | Local/remote port evidence; owning PID | IPv4 TCP table, ports; no process attribution |
| Direct execution from mounted removable storage | USB disk/partition/drive mapping (including USB BusType/UASP), readable executable paths | USB-backed or removable mount mapping and readable `/proc` executable paths |

There are no network probes, file-content reads, downloads, packet capture,
phone unlocks, driver installation, remote commands or security-setting changes.
Device identity/name strings are observations, not trusted instructions.
Serials, MACs and process paths remain in the customer's local telemetry store.

## Findings and response

Initial device/adapter/neighbor inventory and subsequent removals are routine
observations. Newly observed or changed identities go through normal triage.
Cache disappearance does not establish that a device physically disconnected.

Direct executable activity from removable storage always requires review through
the existing native-tool guardrail. Observed neighbor TCP traffic using port 23
or 5555 also requires review because these ports are commonly associated with
Telnet and Android debugging. Ports 135/139/445/3389/5900 receive elevated triage
severity. Neither a port number nor a newly attached device proves a
vulnerability or compromise; evidence explains this and recommends verification.
Existing Defender/Sysmon and other configured sensors remain complementary.

These events cannot authorize device quarantine, USB disabling, phone actions
or firewall blocking. The collector has no actuator. Existing containment
authorization remains unchanged; an attachment event alone cannot trigger it.

## Limits

- Monitoring a PC does not inspect a connected phone's OS, installed apps,
  encryption or vulnerabilities. A phone agent/MDM or an explicitly authorized
  assessment would be needed for that.
- A charge-only cable may expose no data device. An MTP phone is not a mounted
  executable drive. Bluetooth presence can include cached enumerated devices;
  it does not provide phone identity attestation or traffic analysis.
- Neighbor caches only cover peers the host has observed, with stale entries
  possible. This is not a complete LAN inventory, IPv6 monitor, gateway sensor,
  or protection for every device on a connected or remote network.
- Polling misses short-lived attachments/processes. Copied executables, scripts
  interpreted from USB by a system binary, dormant malicious files and BadUSB
  behavior require complementary endpoint detection. This collector does not
  scan USB contents or automatically claim they are safe.
- Inaccessible or oversized categories preserve their prior baseline and report
  partial coverage rather than fabricate disconnections. Limit: 1,024 entries
  per snapshot category. Each category advances its checkpoint after enqueue;
  deterministic IDs tolerate retries across backpressure/restarts.

## Verification

Tests cover baseline vs. hotplug, reconnect/restart, identity changes, partial
failure, bounded snapshots, retry IDs, exact removable path boundaries, Linux
sysfs/proc fixtures, native-vs-imported provenance, deterministic review,
pipeline processing, configuration bounds, and explicit-disable preservation.
The fixed Windows query is attested against its exact command, native Sysmon
provenance, local host and Arbiter parent process before being classified as
collector activity. This avoids recurring LOLBin false alarms without granting
an exemption to modified commands or imported lookalikes; other guardrails and
correlations remain active.
Windows native read-only validation on this PC observed 44 present device
entries, 3 active adapters and 5 usable neighbor entries without collection
errors. This was an observation check, not a malicious USB/phone or real hotplug
test. Linux parsing is fixture-tested; native Linux hardware was not tested.

UI changes reuse the existing Data Sources cards and configuration form; no new
component generation was needed. UI/UX Pro Max's accessibility guidance was
applied to the added coverage/count/limitation text, and the native-source card
was inspected in the browser. No runtime dependencies were added.

Final checks: 401 Python tests passed, 2 skipped, 25 subtests passed; frontend
production build and sample seed/triage passed. Lint reports the two existing
auth-module Fast Refresh warnings; Vite retains its bundle-size advisory.
The terminal zipapp was built and its CLI smoke-tested. These are workspace
changes and test runs, not an upgrade of an existing installed service.
