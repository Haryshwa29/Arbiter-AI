# AGENTS.md — Arbiter AI

Guidance for AI agents working in this repo. Read `CLAUDE.md` for the full
project state and design invariants; this file covers the **frontend rebuild**
currently in progress.

## Where things stand (2026-07-27)

The old web layer (`arbiter/web/`: stdlib `http.server`, server-rendered UI,
JSON API, SSE feed) and the Svelte `frontend/` were **deleted** to rebuild the
frontend from scratch.

Job 1, **rebuild a thin API layer**, is done: `arbiter/api/server.py`
implements the endpoint contract below, `arbiter serve` is back, and
`serve_argv()` needs no changes (see "When the frontend lands"). Job 2,
**build the new frontend** against that API, is what's left.

Do not rebuild the old server-rendered UI. Do not reintroduce a public
marketing site (ADR-002 Decision 1 was withdrawn).

## The backend you are reconnecting to

### `arbiter/store.py` — `AuditStore(db_path="arbiter_audit.db")`

SQLite audit store. Rows are `kind='verdict'` or `kind='iam'`.

- `record_verdict(event, verdict) -> dict` — insert a verdict row, returns it.
- `record_iam(actor, action, detail="")` — insert an IAM audit row.
- `query(decision=None, host=None, tier=None, limit=100, offset=0) -> list[dict]`
  — verdict rows, newest first. Backs the audit/record view.
- `lifetime_counts() -> {"triaged","suppressed","escalated"}` — aggregate,
  non-identifying totals.
- `today_counts() -> {"today","escalated","prefilter"}` — backs the KPI cards.
- `prune(days=30) -> int` — 30-day retention on raw audit detail.

Row shape: `id, ts, kind, event_id, host, signature, decision, score, tier,
rationale, evidence, actor, detail` (`detail` is a JSON string holding
`source`, `message`, `severity`, `fields`).

`decision` is `"escalate"` or `"suppress"`. `tier` is `"prefilter"`, `"llm"`,
or `"guardrail"`.

### `arbiter/iam.py` — `IAM(db_path="arbiter_iam.db", secret=None)`

Stdlib-only auth. Roles are exactly `("analyst", "admin")`.

- `create_user(username, password, role)`, `any_users() -> bool`
- `authenticate(username, password) -> {"username","role"} | None` — returns
  `None` on bad password **and** on lockout (5 failures → 300s lockout).
- `issue_session(user) -> str` — HMAC-signed token, 8h TTL.
- `verify_session(cookie) -> {"username","role"} | None`

**Fixed (2026-07-27):** `secret` used to default to a fresh random value per
process, invalidating all sessions on restart. `load_or_create_secret(path)`
now persists one (0600) next to the IAM db; `arbiter serve` writes it to
`<iam-db>.secret` and passes it into `IAM()`.

### `arbiter/memory.py`, triage engine

`Memory` holds asset criticality, per-signature verdict history, and scoped
environment facts — this backs the "assets & facts" view and the
confirm/overrule feedback loop (`memory.label_verdicts`).

## API contract (implemented in `arbiter/api/server.py`)

```
POST /api/login          {username, password} -> sets session cookie
POST /api/logout
GET  /api/me             -> {username, role}
GET  /api/summary        -> KPI cards (today + lifetime counts)
GET  /api/day?hours=24   -> time-bucketed verdict volume
GET  /api/record?decision=&host=&tier=&limit=&offset=  -> audit rows
GET  /api/estate         -> assets, criticality, environment facts
POST /api/label          {signature, label}  -> memory.label_verdicts
POST /api/acknowledge    {id}
GET  /api/stream         -> SSE live verdict feed
```

Rules: every endpoint except login requires a valid session (401 otherwise).
CSRF is double-submit (`arb_csrf` cookie echoed back as `X-CSRF-Token` on
POSTs — this assumes the frontend dev server and any production reverse
proxy serve the SPA and proxy `/api/*` same-origin, so `SameSite=Strict`
keeps working on both cookies; a cross-origin frontend would need a
different strategy). Security headers (`X-Frame-Options: DENY`, `nosniff`,
`no-referrer`, CSP). `arbiter.api.server.require_admin(user)` exists for
admin-only routes, but none of the routes above need it — that lands with
the Admin view's user/role-management and retention/policy endpoints below,
which aren't specified yet.

The live feed (`/api/stream`) is fed by a background thread that polls the
audit store for rows newer than the last one it saw and republishes them —
it doesn't matter whether `arbiter run`, a real collector, or the dev-only
`arbiter serve --demo-feed` wrote the row, which is what keeps this layer
from talking to the triage engine directly.

## Frontend stack

React + Vite + TypeScript + Tailwind, framer-motion for animation.

### Required tooling — use these, do not hand-roll components

Both are installed in the CLI. Use them; do not write UI components from
scratch when these apply.

- **21st.dev Magic** (MCP server). Invoke `/ui <description>` to generate any
  non-trivial component — cards, tables, forms, nav, modals. Generate first,
  then adapt to the design language below.
- **ui-ux pro max** (skill). Run it over every view before calling that view
  done: layout, spacing, type scale, contrast, and accessibility. It is a
  review-and-refine pass, not a generator.

Sequence per view: Magic generates → you wire it to the API client → ui-ux pro
max refines → then move on. State in your summary which of the two you used
for each view, so it is visible when they were skipped.

**Dependency caution.** Magic emits shadcn/ui, which pulls Radix primitives,
`class-variance-authority`, `clsx`, and `tailwind-merge`. That runs against
constraint 4 (minimal, reviewable dependencies — the customer audits this).
Accept those four if Magic needs them; flag anything beyond them before
installing. And check generated code for runtime CDN fetches — icon and font
imports are the usual leak, and they violate constraints 1 and 2.

Views to build: **Login**, **Overview** (KPI cards), **Live feed** (SSE,
newest-first, "escalations only" filter, reconnect on drop), **Verdicts &
audit** (filter by decision/host/tier, paginated), **Assets & facts**, and
**Admin** (users/roles, retention/policy — admin role only).

Centralize all fetching in one module so auth failure and network failure are
handled once: a 401 redirects to login.

## Hard constraints (do not violate)

1. **Nothing loads from off the network at runtime.** No CDN for fonts, CSS,
   or JS — self-host everything. Auditability is the product's sales argument.
   Build-time npm is fine; runtime fetches are not.
2. **Nothing leaves the customer's network.** No analytics, no telemetry, no
   external API calls. Ever.
3. **The frontend never talks to the triage engine directly** — only through
   the API layer, which reads `store.py` / `memory.py`. Collection and
   response logic stay out of the brain (`triage.py` gains no side effects).
4. **Keep dependencies minimal and reviewable.** The customer is meant to be
   able to audit this. Justify every new runtime dependency.
5. **The public landing page carries no data — zero-recon.** *(Revised
   2026-07-28; see `docs/LANDING-BRIEF.md`.)* The app now serves a public
   marketing landing at `/`, with the dashboard behind login at `/app`. The
   landing is static copy only: no verdicts, no hosts, no counts, no live
   state, and it must make **zero authenticated API calls**. Everything under
   `/app` stays behind the sign-in wall exactly as before.

   On a customer install the landing must be **off by default** — an install
   serves the login screen at `/`, not marketing copy. The landing is for the
   public site deployment. This is the one part of ADR-002 Decision 1 that
   comes back, and only at the frontend; no public routes are added to
   `arbiter/api/server.py`, whose auth gate stays as it is.

## Design language

Calm and restrained. Neutral dark surfaces; color reserved to *mean*
something — red for escalate, green for suppressed/quietly-handled, blue for
prefilter tier, purple for LLM tier. Gentle motion only; nothing that fights
the operator during an incident. The tone is "a colleague who did the work
already," not a threat-o-meter.

## When the frontend lands

- `arbiter/install/service.py`'s `serve_argv()` needs no changes: its flags
  (`--host --port --store-db --iam-db --events`) already match `arbiter
  serve` exactly, and an installed service never passes `--demo-feed`, so it
  never runs the synthetic feeder in production.
- Reinstate a build-output check in `tools/build_release.py`.

## Verify before claiming done

```bash
python3 -m pytest -q                    # 133 tests must pass
python3 -m arbiter --db /tmp/a.db seed
python3 -m arbiter --db /tmp/a.db run samples/events.jsonl --audit /tmp/a.jsonl
```
