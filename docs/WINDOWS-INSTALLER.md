# Arbiter AI Windows installer

`Install Arbiter.exe` is the permanent-install entry point for Windows. It is
a small .NET Framework launcher containing the readable `install.ps1` script;
the Python installer inside `arbiter-*.pyz` remains the single source of truth
for layout, configuration, accounts, service registration, upgrade, and
uninstall behavior.

## Download and install (development preview)

1. [Download Install Arbiter.exe for Windows x64](https://github.com/Haryshwa29/Arbiter-AI/releases/download/v0.1.0/Install%20Arbiter.exe).
2. Run the downloaded file and choose **Local AI** or **Rules only**.
3. Follow the prompts. Missing Python and Ollama can be installed through Windows
   Package Manager; local AI also downloads its model.
4. Keep the initial account credentials printed by setup and open the local
   dashboard address it prints.

[All release files and checksums](https://github.com/Haryshwa29/Arbiter-AI/releases/tag/v0.1.0).
The launcher is unsigned and this is a development preview. Review the source
and checksums before installation. No cloud inference is used after installation.

## What the user sees

Setup checks 64-bit Windows, total RAM, and available disk space before making
changes. It then offers two clearly labelled installations:

- **Local AI — Qwen 3.5 4B:** recommended with at least 8 GB RAM and 8 GB free.
- **Rules only:** the smaller fallback for incompatible hardware. Guardrails
  and deterministic triage work, but there is no local-model reasoning.

Qwen 3.5 4B is the only local model recommended in this installer because it
has current Arbiter evaluation evidence. Additional models belong here only
after they pass the evaluation suites.

## From the USB

Run `Install Arbiter.exe` beside the portable bundle. Setup verifies the
portable Arbiter application and Ollama executable, copies bundled Python,
Ollama, and the selected model to the computer, writes only permanent local
paths into the configuration, and registers Arbiter to start at sign-in.
No model or runtime download is needed.

The default user installation is under `%LOCALAPPDATA%\Arbiter`. The USB can be
removed after setup completes.

## From GitHub

Download `Install Arbiter.exe` from a tagged GitHub Release. The embedded
bootstrap downloads `SHA256SUMS` and the release `.pyz`, verifies the application
checksum, and refuses to execute a mismatch. If Python or Ollama is missing,
setup offers to install it through Windows Package Manager. Ollama then downloads
the selected public model.

The model download is the only large network step. Arbiter does not use cloud
inference after installation.

## Safety and lifecycle

- New installations use shadow mode and response dry-run.
- The dashboard binds to `127.0.0.1:8787` by default.
- The installer creates an initial `admin` account and prints its password.
- The task starts immediately, and again at sign-in for user scope or at boot
  for system scope.
- Reinstalling preserves accounts, audit history, and learned memory.
- `--upgrade`, `--status`, and `--uninstall` remain available through the
  installed `arbiter.pyz`. Uninstall asks separately before deleting data.

Windows/Sysmon and other implemented collectors can be enabled in Data Sources.
A fresh permanent install starts with no enabled collectors and no seeded demo
assets or facts. Demo sessions remain isolated. Existing data is preserved.
Automatic protective responses remain disabled.

## Unattended Windows operation

System installations start at boot as SYSTEM, before sign-in. User installations
start at sign-in and require that user's session. Task settings explicitly allow
indefinite execution and battery operation, ignore duplicate starts, retry
failures every minute and check every five minutes for a stopped task.

Installed runtimes use an OS file lock, bounded logs and a ten-second heartbeat.
A stopped/stalled analysis worker or exited collector causes a failed process
exit for scheduler recovery. Source access errors remain visible as degraded
health while collection retries. Data is stored separately from the application.
Protect application/configuration/data from unprivileged writes when running a
system task. A service account needs its own accessible local model/runtime;
per-user Ollama startup cannot be assumed before sign-in.

Health is in `data/service-health.json`. Logs rotate at 5 MiB with three backups
in `logs/service.log`. A recent heartbeat is not proof of full device coverage.
Sleeping or powered-off machines are not actively monitored. No power policies
are changed by this implementation.

Task generation was validated against Windows Task Scheduler in validation-only
mode. Packaged-runtime startup, duplicate rejection, restart and account
persistence were checked in an isolated installation. Actual boot/logout,
sleep/resume and a multi-day soak remain required before claiming 24/7 readiness.

The development Windows PC was subsequently migrated to a system installation
under `C:\ProgramData\Arbiter`, with a private Python runtime and installed files
restricted to SYSTEM and Administrators. Existing accounts, session secret,
memory, audit and ingestion databases were copied using SQLite backups after
the verified temporary dashboard was stopped. The installed task started and
authenticated checks confirmed the preserved login, elevated analysis worker,
connected System/Application collector, retained events and full demo-history
API. This installation uses the mock test-analysis backend; local-model startup
before sign-in still needs its own setup and validation. A regular unelevated
terminal may not read the protected installation or query the system task.

Deployment order: Windows first, then Linux systemd hardening and macOS launchd
plus native collectors, then server/fleet deployment. macOS native deployment
is not implemented. Shared schemas and UI do not replace platform-specific
service managers and telemetry permissions.

## Verification

`tools/smoke_windows_installer.py` runs the setup EXE against a portable payload
inside a temporary directory. It verifies both hardware choices, removal of all
USB paths, bundled local-AI startup, and authenticated dashboard access without
registering a real scheduled task on the test machine.
