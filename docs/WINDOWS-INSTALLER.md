# Arbiter AI Windows installer

`Install Arbiter.exe` is the permanent-install entry point for Windows. It is
a small .NET Framework launcher containing the readable `install.ps1` script;
the Python installer inside `arbiter-*.pyz` remains the single source of truth
for layout, configuration, accounts, service registration, upgrade, and
uninstall behavior.

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
- The Windows scheduled task starts immediately and again at user sign-in.
- Reinstalling preserves accounts, audit history, and learned memory.
- `--upgrade`, `--status`, and `--uninstall` remain available through the
  installed `arbiter.pyz`. Uninstall asks separately before deleting data.

The current installed product displays the dashboard and accepts normalized
Arbiter events. General Windows/Sysmon collection is a separate roadmap phase;
the installer does not claim that synthetic demo cases are live host telemetry.

## Verification

`tools/smoke_windows_installer.py` runs the setup EXE against a portable payload
inside a temporary directory. It verifies both hardware choices, removal of all
USB paths, bundled local-AI startup, and authenticated dashboard access without
registering a real scheduled task on the test machine.
