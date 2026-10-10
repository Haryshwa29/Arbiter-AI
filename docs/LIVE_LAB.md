# Live lab: what should I see?

Use an authorized lab account/machine. These exercises generate ordinary
telemetry, not attacks. No Red-AI or Healer AI integration is required.

## Run from source on Windows

In the repository folder:

```powershell
cd frontend
npm ci
npm run build
cd ..
python tools/build_release.py
python -m arbiter serve --host 127.0.0.1 --port 8787
```

For source development with the Vite proxy, run `npm run dev` in a second
frontend terminal and use its printed address (the proxy targets API port 8787).
The built zipapp bundles the dashboard; run `python dist\arbiter-0.1.0.pyz serve`
to use it directly. A source API process does not automatically serve
`frontend/dist`; use Vite or the packaged build. First-run credentials appear
in the local terminal. Use your existing accounts when the databases already
exist. For local reasoning add `--backend ollama --model qwen3.5:4b` after `serve`
with the configured model installed locally. The default mock backend is a test
heuristic, not a real AI model. It preserves conservative escalation of ambiguous
events. The portable launcher already supplies its bundled local model URL.

Open **Data Sources**, select Windows Events, leave **Read existing history** off,
enable and save. Wait for status. Security permission failures should appear as
an error, while readable System/Application channels can still work. Enable
Sysmon only after installing/configuring it yourself (see CONNECTORS.md).

## Safe activities and expected results

| Activity | Expected source/event | Expected Arbiter behavior |
|---|---|---|
| Sign in/out normally with your lab account | Security 4624/4634 if audit policy emits them | Observation unless correlated failures or other risk context exists |
| Enter one incorrect password for your own disposable lab account, then correct it | Security 4625/4624; remote vs local context depends on authentication method | Isolated failure is an observation; repeated same-account/source failures correlate |
| Open Command Prompt without arguments | Sysmon 1; Security 4688 if process auditing enabled | Standard shell launch observation |
| Open Windows PowerShell without a script | Sysmon 1; Security 4688 if enabled | Standard shell launch observation; no alert solely for powershell.exe |
| Create a harmless text file | Sysmon 11 if policy includes its path | File creation observation |
| Resolve example.com | Sysmon 22 if enabled; Suricata DNS when visible to sensor | DNS context observation |
| Request https://example.com | Sysmon 3 if enabled; Suricata flow/TLS | Network context observation unless a correlated detection exists |
| Start/close Notepad | Sysmon 1 for creation; termination not collected in this MVP | New process may require context/AI; stop is not guaranteed to produce a supported record |
| Run osquery snapshot | osquery asset_snapshot | Observation, inventory updated |

Example benign commands, run yourself:

```powershell
cmd.exe
powershell.exe
New-Item -ItemType Directory -Force "$env:TEMP\ArbiterLab"
Set-Content "$env:TEMP\ArbiterLab\hello.txt" 'Arbiter lab telemetry'
Resolve-DnsName example.com
Invoke-WebRequest https://example.com -OutFile "$env:TEMP\ArbiterLab\example.html"
notepad.exe "$env:TEMP\ArbiterLab\hello.txt"
```

An HTTP request from PowerShell can enter deeper analysis because Arbiter's
existing LOLBin guardrails consider network-capable PowerShell contexts. That
is distinguishable from an unadorned shell launch; inspect the written rationale.
Avoid repeated password failures against your normal account: its lockout policy
still applies. Use fixture replay to demonstrate brute force instead. Do not
create privileged users, weaken firewall rules, clear logs or run encoded attack
commands to prove the pipeline works.

## Observe, don't assume

Open **Live Events** and filter source/host/category/time. Click a record to see
normalized fields, original payload, analysis, reason and related links.
Received time is when Arbiter queued it; source timestamp is when the activity
occurred. Record fields and available event classes depend on OS audit policy,
Sysmon configuration and log-read permissions. Starting a process does not
guarantee Security 4688 without the relevant audit policy. Command-line content
also requires the appropriate Windows policy; Arbiter does not enable it.

## Demo & Replay without real attacks

Open Demo & Replay, select one or more datasets (or Select all), and Validate
selection. Start opens a separate simulation workspace. Watch incoming events,
decisions and simulated responses together. Click any event for details.
1x delivers one event every three seconds; 2x/5x/10x shorten the interval.
Pause, Resume and Stop control delivery. Choose random mixing, full shuffling,
bursts or variable delays. Demo events never appear in real monitoring counts,
Live Events, Live Feed or Verdicts & Audit. Simulation histories end on a new
session or server restart. No simulated action modifies your device.

For real Windows activity, use Live Events. Click an event to see its analysis
without changing views. Live Feed also loads recent decisions when opened.
Data Sources offers an explicit Windows permission request on the local
packaged dashboard, and discovery/connection of installed local AI models.
Supported real responses require approval; see
[Device monitoring and demo](DEVICE_MONITORING_AND_DEMO.md) for limits and setup.

## Troubleshooting

- No records: collection starts at the log end; generate new activity after
  enabling, or explicitly select Read existing history before first enable.
- Sysmon Not detected: verify the operational channel and permissions. Arbiter
  does not install it. Network/DNS/file events require matching Sysmon policy.
- Security access denied: use approved log-reader access; System/Application can
  work independently. Do not change privileges merely to silence the warning.
- Large queue: check local inference service/latency; disable noisy collection
  while reviewing configuration. A full queue returns 429 rather than losing an
  uploaded batch. UDP syslog may drop records under pressure.
- Cloud samples: upload CloudTrail Records/GuardDuty Findings JSON with the
  matching adapter; no AWS credentials required for these offline tests.
