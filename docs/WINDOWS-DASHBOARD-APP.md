# Double-click dashboard on this PC

The **Arbiter AI** shortcut is created on the Windows desktop and under the
Start menu's **Arbiter AI** folder. It targets
`%USERPROFILE%\Arbiter AI\Arbiter AI.exe`.

The normal profile folder is deliberate: creating the EXE under LocalAppData
from the packaged Codex host redirected it into private MSIX storage, making
the earlier shortcut unusable outside that host. The rebuilt path was checked
from a separate Python process as well as through the shortcut.

The small .NET Framework launcher opens the installed dashboard at
`http://127.0.0.1:8787/overview` in a Microsoft Edge app window. If Edge is
unavailable it uses the default browser. It adds no bundled browser engine or
runtime dependency. Closing the window leaves the existing background
monitoring service running.

If the backend is unavailable, the launcher requests the existing `Arbiter`
scheduled task to start. Windows may ask for administrator approval if the
current user cannot start that task. The launcher does not install a second
backend or create a second set of databases. Existing local-owner access,
accounts, sources and model selection are preserved.

Source: `packaging/DashboardLauncher.cs`. Rebuild the launcher and shortcuts
with `tools/Create-DashboardShortcut.ps1`. This launcher is configured for this
PC's loopback port 8787; it is not a replacement for the general installer.
`--check` checks backend readiness without opening a window or starting the
service. A visible startup window reports waiting or failure, with a retry
button; the launcher no longer waits invisibly in the background.

The installed release was updated with Windows administrator approval, its
checksum verified, and its previous build retained as `arbiter.pyz.previous`.
The updated installed Brief Arbiter route and live attachment observations
were verified in the browser. The desktop shortcut's target was checked.

The subsequent backend repair adds a covering audit-summary index, materializes
the analysis backend alongside decision/tier, and runs ingestion metrics from a
covering metadata index. Lightweight service health no longer invokes dashboard
aggregates or per-source history scans. Tests reject any attempt by metrics to
read stored analysis/payload text and any attempt by health to run metrics.
History, model selection and source configuration are preserved.
