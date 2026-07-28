"""Cross-platform installer for Arbiter (ADR-002).

The two bootstrap scripts (`packaging/install.sh`, `packaging/install.ps1`)
are thin launchers: they only ensure a Python interpreter exists, download
and checksum the zipapp, and then hand control to this package. All real
install logic lives here, once, in Python — so Windows and Linux cannot
drift apart.

Design rules carried over from the product itself:

* **Nothing leaves the machine.** The installer makes exactly one class of
  network call — fetching the local model via Ollama, which the user
  explicitly approves and can decline (MockBackend fallback). No telemetry,
  no update pings, no license check.
* **Transparent.** `--dry-run` prints every step it would take, in order,
  without touching the system. The same plan is what `--install` executes.
* **Idempotent and resumable.** Re-running is safe: existing directories,
  config, databases and services are detected and left alone unless the
  step is explicitly asked to replace them.
"""

from .plan import Action, Plan, Layout, layout_for
