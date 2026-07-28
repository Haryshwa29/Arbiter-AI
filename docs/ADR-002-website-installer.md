# ADR-002: Coupled website + dashboard, and a dynamic cross-platform installer

> **Partially superseded (2026-07-26).** Decision 1 (the public marketing website coupled into the dashboard's public tier) is **withdrawn** — the web layer was removed to rebuild the frontend from scratch, and the marketing-site direction is dropped. Decision 2 (the cross-platform installer, `arbiter/install/`) still stands: `arbiter serve` was restored the next day (2026-07-27) as a thin JSON API, and `serve_argv()`'s flags already match it exactly — see AGENTS.md.

**Status:** Decision 1 withdrawn; Decision 2 (installer) in force — see note above
**Date:** 2026-07-17
**Deciders:** Haryshwa
**Related:** ADR-001 (dashboard/IAM/retention), `CONCEPT.md`, `CLAUDE.md` invariants, `arbiter/web/`, `pyproject.toml`

## Context

Arbiter needs (a) a public web presence where someone can learn about the product and download it, and (b) an install experience professional enough for an MVP. Decisions taken 2026-07-17:

1. **The website and the dashboard are one thing, not two.** The official Arbiter site is a public-facing Arbiter instance: marketing pages are routes in `arbiter/web`, served by the same stdlib server every customer runs. This is deliberate dogfooding — "this site runs on the software you're about to install" is the trust pitch.
2. **A dynamic installer**: one download that detects the platform (Windows and Linux both required — first deployment is a week-long shadow-mode trial on Haryshwa's second machine) and does the right thing on each.
3. Spec before code (this document).

Constraints inherited from ADR-001 and the design invariants:

- The public tier is **zero-recon**: aggregate lifetime counts only (`store.lifetime_counts()`), no hosts/IPs/signatures/live state. Marketing routes join this tier and must obey the same rule.
- **Stdlib-only, no CDN, no external fetches.** The website's inspectability is part of the product argument.
- Nothing about serving public pages may touch the triage path or add side effects to `triage.py`.

## Decision 1 — Website: public routes inside `arbiter/web`

Extend the existing public (unauthenticated) tier of `server.py` with static, server-rendered marketing routes:

```
/            → splash (exists; becomes the landing page: pitch + lifetime counts + Download + Sign in)
/product     → what Arbiter does: triage tiers, memory, response policy, shadow mode
/security    → the trust page: nothing-leaves-your-network, stdlib-only, audit trail, threat model summary
/install     → install instructions + download links + checksums (links point at GitHub Releases)
/docs        → rendered from the repo's markdown (README, quickstart)
```

Rules that keep the coupling honest:

- **Same zero-recon discipline.** Marketing routes render only static copy plus the pre-aggregated lifetime counters already exposed to the splash. No new code path from anonymous requests to `audit` rows or `memory` tables.
- **Every instance ships these pages.** A customer's install serves the same `/product` and `/security` pages on their LAN — the docs travel with the product. The existing ADR-001 toggle extends here: admins can disable the public tier entirely (sign-in wall only), and that remains the default until opted in.
- **Binaries do not live on the box.** `/install` links to GitHub Releases for artifacts and checksums. The canonical download home must be versioned, checksummed, and independent of any one instance's uptime — and you can't download an installer from software you haven't installed. The site is the storefront; Releases is the warehouse.
- **The official arbiter site** is simply a hosted instance with the public tier enabled, behind a reverse proxy (Caddy or nginx) for TLS termination and rate limiting. The stdlib server continues to bind LAN/localhost; the proxy is deployment configuration, not product code. This keeps invariant compliance identical between the marketing instance and customer instances.
- New attack surface is bounded: routes are GET-only, template-rendered from constants, no query parameters that reach storage, standard security headers.

**Rejected alternatives.** A separate static marketing site (loses the dogfood story, splits maintenance, and was explicitly ruled out); serving release binaries from the instance itself (uptime + integrity problems; Releases does this better for free).

## Decision 2 — Installer: thin native launchers over one Python core

"Dynamic" is implemented as platform-native entry points that converge on a single cross-platform installer module:

```
get.arbiter.example/install.sh    → Linux/macOS bootstrap (POSIX sh, ~80 lines, readable)
get.arbiter.example/install.ps1   → Windows bootstrap (PowerShell, ~80 lines, readable)
arbiter-x.y.z.pyz                 → zipapp: the product + arbiter_install (the real installer, Python)
```

The bootstrap scripts do only four things: detect OS/arch, ensure Python ≥ 3.10 (Linux: distro package manager; Windows: `winget install Python.Python.3` with user consent), download the release `.pyz` + `SHA256SUMS` from GitHub Releases and verify the checksum, then run `python arbiter-x.y.z.pyz --install`. Everything after that is shared Python code — one installer logic, not two.

Note the brand-consistency point: Arbiter's own prefilter escalates `curl | sh` as an attack pattern. The published instructions are therefore **download → verify checksum → run**, never pipe-to-shell, and the scripts are short enough to read first. The install page says exactly that.

### Packaging: zipapp, not PyInstaller

| Option | Verdict |
|--------|---------|
| **zipapp (`.pyz`)** — chosen | Stdlib-only codebase makes this trivial (`python -m zipapp`). Single file, runs anywhere with Python 3.10+, and is a *transparent* artifact — unzip it and read the source. Matches the auditability pitch exactly. |
| PyInstaller / Nuitka binary | No Python prerequisite, but opaque blobs contradict "inspect it yourself", routinely trip Windows AV/SmartScreen (fatal for professional first impressions, ironic for a security tool), and add a build toolchain. Rejected. |
| pip / pipx from PyPI | Fine for developers; kept as a secondary channel (`pipx install arbiter`). Not the primary story — the target buyer doesn't know what pipx is. |
| Docker Compose | Deferred to launch as an alternative for Docker-native shops (Arbiter + Ollama in one file). Not required for the MVP trial. |

### What `arbiter_install` does (idempotent, resumable)

1. **Preflight:** OS/arch, Python version, disk space, port availability; RAM check with model-size guidance.
2. **Layout:** Linux `/opt/arbiter` + `/var/lib/arbiter` (data) or `~/.local/share/arbiter` for user installs; Windows `%ProgramData%\Arbiter` (data) + `%LocalAppData%\Arbiter` (app). Config in one INI/TOML file.
3. **LLM backend:** detect Ollama; offer to install it (Linux: official installer with the same download-verify-run discipline; Windows: fetch the installer and hand off to its GUI) and pull the configured model. **Declining is a first-class path** — install proceeds with `MockBackend` and the dashboard banner reads "mock backend — triage heuristics only," so the demo works on any machine in minutes.
4. **Seed + bootstrap:** initialize DBs, run the equivalent of `cmd_seed` on consent, print the one-time admin setup token (ADR-001 first-run flow), open the dashboard URL.
5. **Service registration** so it survives reboots: Linux → systemd unit (or `--user` unit for non-root installs); Windows → Task Scheduler at-startup task (avoids service-wrapper dependencies like NSSM; stdlib ethos extends to install-time dependencies).
6. **Lifecycle flags:** `--install`, `--upgrade` (replace `.pyz`, migrate DB schema, restart service), `--uninstall` (remove app + service; asks separately before deleting data — memory DB is the analyst's accumulated learning), `--dry-run` (print every action without executing; the transparency ethos applied to installation), `--status`.

### Release pipeline

Tag → CI builds `.pyz`, wheel, `SHA256SUMS`, and the two bootstrap scripts → GitHub Release. The `/install` page always points at `releases/latest`. Version surfaces in the dashboard footer and `arbiter --version`. (Signing — Sigstore or GPG — noted for launch; checksums suffice for the MVP trial.)

## The week-long shakedown (first real deployment)

The trial on the second machine is the shadow-mode validation run `prefilter.py`'s provisional thresholds have been waiting for, and the first end-to-end test of the install story itself.

- **Day 0:** install via the real installer artifacts — no manual repo setup allowed. Any step needing a manual fix is an installer bug; log it.
- **Config:** shadow mode, response dry-run only, real Ollama backend with the guardrail sandwich active, dashboard on LAN.
- **During:** feed it the machine's actual auth/syslog events (manual JSONL export into the feeder is acceptable this round — the collector decision is still open and stays out of scope). Check the dashboard daily; overrule wrong verdicts once the feedback CLI lands.
- **Exit criteria:** installer completed unattended except for consent prompts; service survived ≥ 2 reboots; zero silent verdicts; audit JSONL + store agree; a written list of threshold adjustments backed by the week's data; upgrade path exercised at least once mid-week (ship a point release to yourself).

## Consequences

**Easier:** one web codebase to maintain; docs ship inside the product; the marketing claim is self-demonstrating; installs stop being "clone the repo."

**Harder:** the public tier's zero-recon bar now applies to marketing pages forever; a release pipeline must exist before the trial; Windows service management via Task Scheduler needs real testing; the official site needs a host + reverse proxy config (small, but new ops surface).

**To revisit:** Docker Compose channel at launch; artifact signing; auto-update checks (off by default — phone-home tension with invariant #3; at most a manual "check for updates" button that the admin clicks).

## Action items (phased)

**Phase 1 — release plumbing:** zipapp build + `SHA256SUMS` in CI on tag; `arbiter --version`.
**Phase 2 — installer core:** `arbiter_install` module (preflight, layout, seed, token, service, `--dry-run`/`--upgrade`/`--uninstall`); `install.sh` + `install.ps1` bootstraps.
**Phase 3 — website routes:** `/product`, `/security`, `/install`, `/docs` in the public tier; extend the ADR-001 public-tier toggle to cover them; security headers.
**Phase 4 — the trial:** install on the second machine from release artifacts; run the week; write up findings (thresholds, installer bugs, upgrade test).
**Phase 5 — official site:** host a public instance behind Caddy; point DNS; enable the public tier there.

Ordering note: Phases 1–2 block the trial; Phase 3 doesn't — website routes can land during the trial week.
