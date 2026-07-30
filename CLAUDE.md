# Arbiter AI

Self-hosted AI security analyst for small companies with no security team. Read `CONCEPT.md` for the full product vision and `README.md` for how to run the current slice.

## Current state

First vertical slice of the triage engine (Python, stdlib-only):

- `arbiter/schema.py` — Event/Verdict data contract. **This is the stable boundary a future Go collector agent must honor. Do not change it casually; keep it dependency-free.**
- `arbiter/memory.py` — SQLite memory layer: asset criticality, verdict history per signature, environment facts. Deliberately human-readable (transparency is a product feature).
- `arbiter/facts.py` — scoped environment facts (the fact-overreach fix): a fact may carry `user`/`path`/`process`/`event_types`/`window` constraints, checked in code against each event before the LLM sees it; out-of-scope facts render with a `[SCOPE MISMATCH]` annotation that can never justify suppression. Scope facts to the event class they explain — over-scoping mismatches legit events (see `cmd_seed`).
- `arbiter/prefilter.py` — cheap tier: severity × criticality × history. Thresholds are provisional; shadow-mode data should tune them.
- `arbiter/llm.py` — pluggable backends: `OllamaBackend` (local open-weights model) and `MockBackend` (deterministic heuristics for tests/dev).
- `arbiter/triage.py` — orchestrator, shadow mode, JSONL audit trail.
- `arbiter/respond.py` — response actuator: surgical, TTL-limited actions from escalation verdicts (block IP / lock account / kill session / quarantine host). Dry-run default; AUTO only for prefilter-tier + auto-safe catalog entries, LLM-tier is always RECOMMEND. Allowlists (CGNAT/office NAT) deliberately deferred.
- `arbiter/store.py` — queryable SQLite audit store (audit rows + IAM events); `lifetime_counts()` gives aggregate, non-identifying totals; `day_buckets()` backs the overview chart; `rows_since()`/`max_id()` back the live-feed poller; `acknowledge()` repurposes the `actor` column to mean "reviewed by"; 30-day `prune()`. Separate from `memory.py`, which is never pruned.
- `arbiter/iam.py` — built-in IAM: local accounts, `hashlib.scrypt` hashing, HMAC-signed session cookies, `analyst`/`admin` roles, lockout. Stdlib-only. `load_or_create_secret()` persists the HMAC signing secret (0600) so sessions survive a restart — previously `IAM(secret=None)` picked a fresh one every process start.
- **`arbiter/web/` removed (2026-07-26), replaced by `arbiter/api/` (2026-07-27).** The old web layer — stdlib `http.server`, server-rendered UI, JSON API, SSE feed — and the Svelte `frontend/` were deleted to rebuild the frontend from scratch. `arbiter/api/server.py` is the new thin JSON API over `store.py`/`iam.py`/`memory.py`: same stdlib-only `http.server` approach as before (see AGENTS.md for why, not FastAPI), session cookie + CSRF double-submit + security headers, and a background thread that polls the audit store for new rows and fans them out over SSE (`/api/stream`) — so it never talks to the triage engine directly, and doesn't care whether `arbiter run`, a real collector, or the dev-only `--demo-feed` wrote the row. `memory.py` now also takes `check_same_thread=False` + a lock, matching `store.py` — required once a threaded HTTP server started calling it from multiple threads.
- `arbiter/cli.py` — `python -m arbiter seed` / `run samples/events.jsonl [--respond]` / `eval` / `review` / `bench` / `serve`. Note `--db` is a **global** flag and must precede the subcommand. `serve --demo-feed` is dev-only (off by default) and replays `--events` through the triage engine on a timer so the dashboard has data without a real collector wired up.
- `arbiter/install/` — cross-platform installer (ADR-002). `plan.py` makes an install an inspectable list of `Action`s, so `--dry-run` and the real run walk the same list; `preflight.py` gates on python/disk/RAM/port/Ollama; `service.py` registers systemd (Linux) or a Task Scheduler task (Windows), both derived from one `serve_argv()` so they can't drift. Lifecycle: `--install/--upgrade/--uninstall/--status`, all accepting `--dry-run` and `--prefix`. Data dir is never touched by upgrade, and uninstall asks about it separately. `serve_argv()`'s flags (`--host/--port/--store-db/--iam-db/--events`) match `arbiter serve` exactly; the installed service never passes `--demo-feed`, so it never runs the synthetic feeder.
- `packaging/install.sh`, `packaging/install.ps1` — thin bootstraps: find Python, download the `.pyz` + `SHA256SUMS` from GitHub Releases, verify, hand off. **Never publish pipe-to-shell instructions** — the prefilter escalates that pattern.
- `tools/build_release.py` — builds `dist/arbiter-<version>.pyz` (transparent zipapp of readable source) + `SHA256SUMS`. Version's single source of truth is `arbiter/__init__.py`; `.github/workflows/release.yml` enforces that the git tag matches it.

## Design invariants (do not violate)

1. **Asymmetric error costs**: missing a real breach is fatal; false escalations are cheap. Suppression always requires stronger justification than escalation. LLM failure → escalate by policy.
2. **Every suppression carries a written rationale; every escalation carries an evidence summary.** No silent verdicts.
3. **Nothing leaves the customer's network.** No cloud API calls in the triage path. LLM inference is local (Ollama) or mock.
4. **Adaptation through context, not weights** — learning lives in the SQLite memory layer, never in fine-tuning.
5. Collection logic stays out of the brain. Anything that reads logs communicates with triage only through the `Event` schema.
6. **Response mirrors both 1 and 5**: blocking requires stronger justification than alerting (false blocks are costly). Response logic stays out of the brain — `respond.py` consumes verdicts, `triage.py` never gains side effects. Actions are surgical, reversible, TTL-limited; never service-wide. The LLM tier never auto-executes.

## Verify changes

```bash
python -m arbiter --db /tmp/arbiter.db seed
python -m arbiter --db /tmp/arbiter.db run samples/events.jsonl --audit /tmp/audit.jsonl
```

Expected: backup IO spikes suppressed (LLM tier first, prefilter after 5 benign verdicts), brute force + curl|sh escalated by prefilter, laptop priv-escalation caught by LLM tier, unknown host escalated.

## Next steps (agreed with Haryshwa)

0. **Build the new frontend** (React + Vite + TypeScript + Tailwind, per AGENTS.md) against the now-restored `arbiter/api/`. Supersedes the old ADR-001/ADR-002 dashboard-and-website plan. The public landing's hero is built: `frontend/src/site/TransitField.tsx` + `Landing.tsx`, spec in `docs/HERO-TRANSIT-BRIEF.md` (which supersedes `docs/LANDING-BRIEF.md` §3a; `CyberField.tsx` and `ArbiterMark.tsx` are deleted). **The public positioning line changed 2026-07-29** — "a shield you can raise before you can afford an army"; no SIEM comparison and no pricing claim ships publicly. Dashboard views remain the open work.
1. Labeled eval set to answer "minimum viable local model" — biggest open question.
2. Human feedback loop CLI (confirm/overrule → `memory.label_verdicts`) — done via `arbiter review`; `/api/label` now exposes the same action to the frontend.
3. Collector wrapper decision (Vector vs Wazuh) emitting the Event schema.
4. Event-triggered micro-rescans for unknown assets.
