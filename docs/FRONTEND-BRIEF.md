# Frontend build brief — Arbiter AI dashboard

**Audience:** the agent building the frontend. **Status of the backend:** done and
verified. `arbiter/api/server.py` is committed (`473b907`), 133/133 tests pass, and
every endpoint below was exercised against a live server on 2026-07-28 — the payloads
in this document are **real captured responses**, not schemas inferred from code.

Read `AGENTS.md` for project-level rules and `CLAUDE.md` for the design invariants of
the engine behind the API. This file is the implementation contract.

**Scope of this pass: five views.** Login, Overview, Live feed, Verdicts & audit,
Assets & facts. The Admin view is explicitly **out of scope** — its endpoints
(user/role management, retention/policy) do not exist yet. `require_admin()` is
defined in `server.py` but no route uses it. Do not build UI for it, do not stub it.

---

## 1. Stack and setup

React + Vite + TypeScript + Tailwind, framer-motion for animation.

**Use the installed tooling — see `AGENTS.md` § "Required tooling".** Short version:
generate every non-trivial component with 21st.dev Magic (`/ui <description>`), wire
it to the API client, then run the ui-ux pro max skill over the finished view before
moving on. Say which you used for each view in your summary. Do not hand-roll
components these tools cover.

The app lives in `frontend/` at the repo root. `.gitignore` already covers
`frontend/node_modules/` and `frontend/.vite/`.

### Vite dev server must proxy, not CORS

Both cookies are `SameSite=Strict`. A cross-origin frontend will silently fail to
authenticate. Configure the dev server to proxy `/api` to the backend so the browser
sees one origin:

```ts
// vite.config.ts
server: {
  proxy: { '/api': 'http://127.0.0.1:8787' }
}
```

Do not add CORS headers to the backend to work around this. Same-origin is the
deployment model — in production a reverse proxy serves the built SPA and proxies
`/api/*` to `arbiter serve`.

### Running the backend during development

```bash
python3 -m arbiter --db arbiter_memory.db seed          # one-time: assets + facts
python3 -m arbiter --db arbiter_memory.db serve \
  --store-db arbiter_audit.db --iam-db arbiter_iam.db \
  --demo-feed --events samples/events.jsonl --dev-accounts
```

`--db` is a **global** flag and must come before the subcommand. Port defaults to
**8787** everywhere — `arbiter serve`, `install/cli.py`'s `DEFAULT_PORT`, and the Vite
proxy. Don't introduce a second port.

`--dev-accounts` forces `admin/admin123` and `analyst/analyst123` on every boot and
clears any lockout. Dev only, off by default, never passed by the installed service.
Use it: without it the server prints generated passwords **only on first run**, and an
automated client that guesses wrong five times locks the account for 300 seconds with
no way back except deleting the database.

`--demo-feed` is dev-only and off by default. It replays sample events through the
triage engine on a 2s timer so the live feed and charts have data without a real
collector. The installed service never passes it.

---

## 2. Hard constraints

These are product requirements, not preferences. The auditability of this system is
its sales argument.

1. **No runtime fetches from outside the network.** No CDN for fonts, CSS, JS, or
   icons. Self-host everything. Build-time npm is fine.
2. **No analytics, no telemetry, no external API calls.** Ever.
3. **The frontend talks only to `/api/*`.** It never reaches into the triage engine,
   the SQLite files, or the response actuator.
4. **Minimal, reviewable dependencies.** The customer is meant to audit this. Justify
   every runtime dependency you add beyond the stack above.
5. **No public or anonymous page.** Sign-in wall only. No marketing routes, no splash.

---

## 3. Auth flow

### The CSRF bootstrap — read this before writing the login form

CSRF is double-submit: the server sets a non-`HttpOnly` `arb_csrf` cookie, and POSTs
must echo it back in an `X-CSRF-Token` header. **The cookie is only issued on a JSON
response, and `POST /api/login` is itself CSRF-checked.** A cold client that POSTs
straight to `/api/login` gets:

```
403  {"error": "csrf token missing or invalid"}
```

So the login sequence is:

1. `GET /api/me` — expect `401 {"error": "unauthenticated"}`. The point is the
   `Set-Cookie: arb_csrf=…` that comes with it.
2. Read `arb_csrf` from `document.cookie`.
3. `POST /api/login` with `X-CSRF-Token: <that value>`.

Do this once at app boot, before rendering the login form. Verified empirically —
skipping step 1 produces the 403 above.

### Cookies

| Cookie | Flags | Meaning |
|---|---|---|
| `arb_session` | `HttpOnly; SameSite=Strict; Path=/; Max-Age=28800` | 8-hour session, HMAC-signed |
| `arb_csrf` | `SameSite=Strict; Path=/` (readable by JS, by design) | double-submit token |

The signing secret now persists to `<iam-db>.secret`, so sessions survive a backend
restart. Sessions do **not** survive 8 hours.

### Failure handling

Centralize all fetching in one module so these are handled once:

- **401 on any request** → drop to the login view. Sessions expire at 8h; users will
  hit this mid-session.
- **403 with `csrf token missing or invalid`** → re-read the cookie and retry once.
- **Lockout is indistinguishable from a bad password.** `authenticate()` returns
  `None` for both (5 failures → 300s lockout), and the API returns
  `401 {"error": "invalid credentials"}` either way. Write error copy that covers
  both without claiming which: *"Sign-in failed. If you've tried several times,
  wait five minutes."*

---

## 4. API reference

All responses are `application/json` with `Cache-Control: no-store` and security
headers (`X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, CSP).
Errors are uniformly `{"error": "<message>"}`.

Every route except `POST /api/login` requires a valid session.

### `POST /api/login`
Body `{username, password}` → `200 {"username": "admin", "role": "admin"}` and sets
the session cookie. `401 {"error": "invalid credentials"}` on failure.

### `POST /api/logout`
→ `200 {"ok": true}`, clears the session cookie.

### `GET /api/me`
→ `200 {"username": "admin", "role": "admin"}`. Role is `"analyst"` or `"admin"`.

### `GET /api/summary`
```json
{"today":    {"today": 7, "escalated": 0, "prefilter": 2},
 "lifetime": {"triaged": 7, "suppressed": 7, "escalated": 0}}
```
Note the awkward nesting — `today.today` is the count of verdicts today. `today` is
UTC-day based. `lifetime` is aggregate and non-identifying, and is never pruned.

### `GET /api/day?hours=24`
`hours` clamps to 1–168. Buckets are hourly, **oldest first**, and zero-filled so a
chart never has gaps:
```json
{"buckets": [
  {"bucket": "2026-07-28T11:00:00+00:00", "escalated": 0, "suppressed": 0},
  {"bucket": "2026-07-28T16:00:00+00:00", "escalated": 0, "suppressed": 7}]}
```

### `GET /api/record?decision=&host=&tier=&limit=&offset=`
Newest first. `limit` defaults 100, clamps to 500. Filters are exact-match and
optional. `decision` ∈ `escalate|suppress`; `tier` ∈ `prefilter|llm|guardrail`.

```json
{"rows": [{
  "id": 7,
  "ts": "2026-07-28T16:15:59.041775+00:00",
  "kind": "verdict",
  "event_id": "9cc85ee2b54e",
  "host": "db-prod-01",
  "signature": "node_exporter:io_anomaly:db-prod-01",
  "decision": "suppress",
  "score": 2.0,
  "tier": "prefilter",
  "rationale": "score 2.0 < 3.0; signature seen 6x, always benign, never overruled",
  "evidence": "",
  "actor": null,
  "detail": "{\"source\": \"node_exporter\", \"message\": \"nightly disk IO spike…\", \"severity\": 2.0, \"fields\": {\"iops\": 9000}}"
}]}
```

Three traps in that row:

- **`detail` is a JSON *string*.** Parse it a second time. It holds
  `{source, message, severity, fields}` where `fields` is free-form per event source.
- **`actor` is `null` until acknowledged**, then holds the reviewer's username. The
  column is repurposed — on a verdict row a non-null `actor` means "reviewed by".
  Use it to render acknowledged state.
- **`evidence` is often an empty string** on suppressions. Don't render an empty
  panel. Per the design invariants, suppressions carry a `rationale` and escalations
  carry `evidence` — expect one or the other to be the substantive field.

### `GET /api/estate`
```json
{"assets": [
   {"host": "db-prod-01", "criticality": 2.0, "role": "production postgres", "confirmed": true}],
 "facts": [
   {"id": 1,
    "scope": "db-prod-01",
    "fact": "backups run at 02:00 — nightly IO spike on db-prod-01 is normal",
    "user": "", "path": "", "process": "",
    "event_types": ["io_anomaly"],
    "window": ""}]}
```
Fact constraint fields (`user`, `path`, `process`, `event_types`, `window`) are
empty string / empty array when unconstrained. `event_types` is an array; the rest
are strings.

### `POST /api/label`
Body `{signature, label}` where `label` is exactly `"confirmed"` or `"overruled"`.
→ `200 {"ok": true}`, or `400` if either is missing/invalid.

**Keyed by signature, not by row id.** Labeling affects every verdict sharing that
signature, historically and in future. Say so in the UI.

### `POST /api/acknowledge`
Body `{id}` (integer row id) → `200 {"ok": true}`, `404` if no such record.

### `GET /api/stream` (SSE)
Emits `data: {…}\n\n` per new verdict row, and a `: keepalive` comment every 15s
(EventSource ignores comments — no handling needed). Message shape is the record row
minus `kind`/`detail`:

```
data: {"id": 5, "ts": "…", "host": "db-prod-01", "signature": "…",
       "decision": "suppress", "score": 4.0, "tier": "llm", "rationale": "…"}
```

A background thread polls the audit store and fans rows out, so the stream carries
verdicts regardless of whether `arbiter run`, a real collector, or `--demo-feed`
wrote them.

**EventSource gotcha:** an unauthenticated `/api/stream` returns `401` JSON, and the
browser's EventSource will reconnect forever on its own. Detect the failure and tear
the connection down explicitly rather than letting it spin — route to login instead.

---

## 5. The five views

### Login
Username + password. Runs the CSRF bootstrap on mount. Generic failure copy per §3.
This is the only unauthenticated screen.

### Overview
KPI cards from `/api/summary` — verdicts today, escalations today, prefilter share,
lifetime totals — over a volume chart from `/api/day`. Let the user switch the window
(24h / 72h / 7d, i.e. `hours=24|72|168`).

The read the operator should get in two seconds: *how much did this handle for me,
and how much needed me?* Escalations are the number that matters; triaged volume is
the reassurance. Don't render suppressions as an alarm colour.

### Live feed
`/api/stream`, newest first, with an "escalations only" filter and reconnect-on-drop.
Cap the in-memory list (a few hundred rows) so a flood doesn't grow it unbounded.

Motion here should be gentle — a row easing in, not a klaxon. This screen may be open
on a wall display for hours.

### Verdicts & audit
`/api/record` with filters for decision, host, and tier, plus pagination via
`limit`/`offset`. Row expands to show `rationale`, `evidence`, and the parsed
`detail` (source, message, severity, fields).

Acknowledge action per row → `POST /api/acknowledge`. Reflect acknowledged state from
the non-null `actor`.

Hosts for the filter dropdown come from `/api/estate` — there is no dedicated hosts
endpoint. Rows can reference hosts absent from the estate (unknown assets escalate by
policy), so allow free-text host entry too.

### Assets & facts
Two sections from `/api/estate`.

**Assets** — host, role, criticality, confirmed flag. Criticality is a float
multiplier (observed 0.5 dev laptop → 2.0 production postgres), not a 1–5 rating;
render it as a weight, not stars.

**Facts** — the environment facts that justify suppression, with their scope
constraints shown explicitly. This is the transparency surface: an operator must be
able to see *exactly* how narrow a fact is. A fact scoped to
`event_types: ["io_anomaly"]` on one host is a very different object from an
unconstrained one, and the UI must make that legible at a glance. Render empty
constraint fields as "any" rather than blank.

**Feedback loop** — confirm/overrule via `POST /api/label`. Two things the UI must
convey, because they are not obvious and getting them wrong damages the memory layer:

- It applies to the **signature**, not the one verdict in front of you.
- Overruling is **direction-aware**: overruling an escalation means *false alarm*
  (confidence decays); overruling a suppression means *missed attack* (confidence
  boosts). The copy should reflect which one the user is doing — "this was a false
  alarm" vs "this should have been escalated" — not a bare "overrule" button.

---

## 6. Design language

Calm and restrained. Neutral dark surfaces. Colour is reserved to *mean* something:

| Token | Meaning |
|---|---|
| red | escalate |
| green | suppressed / quietly handled |
| blue | prefilter tier |
| purple | LLM tier |
| **amber — proposed** | **guardrail tier** |

The `guardrail` tier exists in the API (`Tier.GUARDRAIL`, non-suppressible intent-class
detections) but was never assigned a colour. Amber is proposed because a guardrail
firing is a stronger statement than a tier attribution — it means a rail refused to
let something be suppressed. Confirm before committing to it.

Gentle motion only. Nothing that fights the operator during an incident. The tone is
"a colleague who already did the work," not a threat-o-meter.

---

## 7. Open items

- **Guardrail tier colour** — unassigned, see above.
- **Production CSP.** API responses carry `default-src 'none'`, which is correct for
  JSON but would break an HTML page. Whoever serves the built `index.html` (reverse
  proxy in production, Vite in dev) needs its own workable CSP. Not the API's job,
  but nobody has specified it.
- **`tools/build_release.py` needs its build-output check reinstated** once a build
  output path exists — the zipapp should ship the built frontend.
- **No account management exists.** Without the Admin view, the only accounts are the
  two `serve` creates on first run; there is no CLI user command either. Fine for this
  milestone, blocking for a real install.

---

## 8. Definition of done

```bash
python3 -m pytest -q     # 133 tests still pass — the frontend must not change backend behaviour
```

Plus, by hand:

- Cold load with no cookies lands on Login and signs in successfully.
- Session expiry (or a deleted `arb_session` cookie) drops any view to Login.
- Live feed shows rows appearing while `--demo-feed` runs, and recovers when the
  backend is restarted underneath it.
- Filters and pagination on Verdicts & audit produce correct rows.
- Acknowledge persists across a reload.
- Confirm/overrule round-trips and the wording matches the direction-aware semantics.
- **No network request leaves the origin.** Check the Network tab with a filter for
  third-party domains — this is constraint 1 and 2, and it is the one most easily
  broken by an innocent-looking font or icon import.
