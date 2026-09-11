# Arbiter portable Windows demo

Copy the entire folder to a writable USB drive or portable SSD. Open
**Start Arbiter.exe**. It checks the bundled model, starts its own local AI,
prints your initial admin password, and opens the dashboard. Keep the password
for future launches. In the portable dashboard, **Sign out & shut down** clears
the browser session and stops Arbiter. Wait for the start window to report
**Stopped** before ejecting the drive. **Stop Arbiter.exe** remains available
if the browser is closed or unavailable; Ctrl+C in the start window also requests
a clean stop. Do not pull the USB while analysis is running.

This is a **sample-event demonstration**, not monitoring of the host computer.
No firewall changes, response execution, service registration, or model downloads
occur. The dashboard displays a sample-data banner. There is no mock fallback
if local AI is unavailable.

## Live demonstration cases

The 16 named scenarios are in `Demo Test Cases/Active`. Arbiter watches that
folder while it is running and automatically reloads `.json` and `.jsonl` files
when they are added, edited, renamed, or removed. The Start Arbiter window prints
the folder path and reports every successful reload.

Open `Demo Test Cases/README.md` for the scenario catalogue and intended results.
To add a request during a presentation, copy
`Demo Test Cases/Templates/00-new-live-case.json` into `Active`, rename it with a
descriptive `00-...` filename, edit the simulated event, and save it. The `00-`
prefix places it first after reload. These files are demonstration inputs; they
are processed through the real guardrails, local model, memory, audit store, and
dashboard.

## Supported first target

- Intel/AMD 64-bit Windows 10 22H2 or Windows 11.
- At least 8 GB total RAM for the initial Qwen 4B bundle; actual free RAM and
  driver compatibility determine whether it loads. Startup checks model loading.
- Bundled Python and Ollama; no installed Python, Node, or Ollama required.
- CPU inference is supported by Ollama; compatible GPU drivers enable acceleration.
- A writable drive with room for the complete bundle plus at least 500 MB free.
  A fast portable SSD is preferable to a slow USB stick for model loading.
- Windows may display a warning for these unsigned development executables.
  The binaries are not yet signed or a general public release.

## Data and processes

`data/` contains local accounts, memory, audit records, and runtime temporary files.
`logs/ollama.log` explains model/driver startup failures. `config/portable.json`
selects a model already included under `models/`. Do not select a cloud model.
The local server binds only to loopback and chooses available ports. Your installed
Ollama is not reused, stopped, or reconfigured. Cloud features are disabled in the
bundled process. The launcher's Windows Job Object contains its Ollama descendants.

Arbiter-controlled state stays in this folder. Windows, GPU drivers and your
browser can still create their own caches, history, paging or diagnostic records;
this is not a forensic no-trace environment. Ordinary browser login state is stored
by your browser. Always sign out on shared computers.

Shutdown waits for any active model request (up to the request timeout). Initial
model loading can take up to three minutes before a stop request is processed.
If an abrupt termination leaves a stale session file, the next launch replaces
it; the running lock is released by Windows when its owner exits.

## Build from source

Build `frontend` with `npm ci` and `npm run build`, then run
`python tools/build_release.py`. Use `python tools/build_portable.py --help` for
explicit runtime, model, checksum, release and destination inputs. The builder
does not download files or copy development databases. It verifies model digests
and records checksums. Runtime/model licensing must accompany redistribution.

Run `python tools/smoke_portable.py dist/Arbiter-Portable-Windows` to test a
fresh relocated copy in a path containing spaces. It removes Python/Ollama
from PATH, checks login and a real local-model verdict, and requests shutdown.
Test data is temporary and the source bundle's accounts are left untouched.

Sources: [Python Windows distributions](https://www.python.org/downloads/windows/),
[Ollama standalone Windows runtime](https://docs.ollama.com/windows),
[Ollama local-only configuration](https://docs.ollama.com/faq).

## Still to validate / implement

- A clean Windows machine with no Python/Ollama installation and actual USB removal.
- Hardware coverage beyond the development machine, including CPU-only performance.
- A permanent installation EXE with hardware-driven model choices.
- Real event collectors, admin/password-management UI, and signed public releases.
