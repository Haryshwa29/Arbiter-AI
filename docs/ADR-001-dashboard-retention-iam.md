# ADR-001: Self-hosted dashboard, 30-day retention, and built-in IAM

**Status:** Proposed
**Date:** 2026-07-04
**Deciders:** Haryshwa
**Related:** `CONCEPT.md` (product vision), `CLAUDE.md` (design invariants), `arbiter/triage.py`, `arbiter/respond.py`, `arbiter/memory.py`

## Context

Arbiter today is a CLI triage engine that writes verdicts to a JSONL audit trail and a SQLite memory DB. To become a product, it needs a way for a non-technical operator at the customer to *see* what the analyst-in-a-box is doing, browse the audit trail, act on escalations, and approve response actions — without ever sending data off the box.

Three decisions are locked (see the questions answered on 2026-07-04):

1. **Access model — self-hosted web UI.** The dashboard runs inside the customer's environment, reached over their LAN/VPN. This is the only option consistent with the validated market signal ("these companies will not ship their logs to a third party") and invariant #3 (*nothing leaves the customer's network*).
2. **IAM — built-in users and roles.** Local accounts with roles, no dependency on an external identity provider. SSO/OIDC is a later option, not the MVP.
3. **Deliverable now — this ADR**, before any dashboard code.

Forces at play:

- The codebase is deliberately **stdlib-only and dependency-light** (auditability is a product feature — "verify yourself that nothing leaves"). Every dependency added to an open-core security tool is trust surface a buyer can object to.
- The dashboard is a **new attack surface on a security product**. A weak dashboard is worse than no dashboard: it becomes the thing that gets breached.
- Security audit trails often want *long* retention for forensics. A 30-day cap is a deliberate product/storage choice, and it trades forensic depth for a bounded disk footprint. It must be configurable.
- The dashboard must not violate the layering invariants: triage (`triage.py`) and response (`respond.py`) stay side-effect-isolated; the dashboard is a **read-and-annotate layer**, not a second brain.

## Decision

Ship a **single self-hosted Python service** that serves a server-rendered dashboard over the existing SQLite store, with **stdlib-first authentication** (local accounts, `hashlib.scrypt` password hashing, HMAC-signed session cookies), **three built-in roles** (admin / analyst / viewer) mapped onto the existing escalate/override/respond actions, and a **scheduled 30-day retention prune** on a queryable audit store. No external services, no cloud, no CDN — the dashboard is fully self-contained and inspectable.

## Options considered

### Dashboard architecture

#### Option A: Stdlib Python service, server-rendered HTML (recommended)
A small service built on `http.server` / `wsgiref` (or one tiny vetted framework), rendering HTML server-side, reading from SQLite. Auth uses stdlib primitives (`hashlib.scrypt`, `hmac`, `secrets`).

| Dimension | Assessment |
|-----------|------------|
| Complexity | Low–Medium |
| Dependencies | Zero to one — preserves the auditability story |
| Attack surface | Small, easy to reason about |
| Team familiarity | High (already a Python codebase) |

**Pros:** Matches the stdlib-only ethos; nothing to vet in a supply chain; server-rendered means no JS build step and no client-side data exposure; trivially bound to localhost/LAN.
**Cons:** More manual than a batteries-included framework; richer interactivity (live updating) needs deliberate work.

#### Option B: FastAPI/Flask + React SPA
Conventional web stack: API backend, JS frontend.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium–High |
| Dependencies | Many (framework, ASGI server, npm tree) |
| Attack surface | Larger; npm supply chain is a real objection for this buyer |
| Team familiarity | High but adds a JS toolchain |

**Pros:** Familiar, fast to build rich UIs, big ecosystem.
**Cons:** Every dependency is trust surface in an open-core security product; a customer auditing "does nothing leave?" now has to audit an npm tree; heavier to ship self-hosted.

#### Option C: Static HTML reading JSONL directly (no server)
Like the local simulator report — a static page over the audit files.

**Pros:** Zero infrastructure.
**Cons:** Can't do real auth/IAM, can't gate write actions (overrule, approve response), can't enforce retention. Fails the IAM requirement outright. Rejected.

**Chosen: Option A.** It's the only one that satisfies stdlib-first auditability *and* real IAM. Interactivity can borrow the same self-contained, CDN-free HTML/JS approach already used for the reports (charts inline, no external fetch).

### Storage & 30-day retention

The audit trail is currently append-only JSONL that grows forever, and the memory DB is SQLite. For a dashboard you need *queryable, filterable, paginated* history, which pushes toward SQLite as the primary store.

**Decision:** Write verdicts (and IAM/response events) into a SQLite `audit` table with an indexed `timestamp`, keeping JSONL as an optional append-only export for customers who want an immutable off-box copy. Retention is a **scheduled prune** — a job (systemd timer / cron / the existing `schedule` mechanism) that deletes `audit` rows and rotates JSONL files older than `RETENTION_DAYS` (default 30, configurable).

| Concern | Handling |
|---------|----------|
| Query performance | Index on `timestamp`, `decision`, `host`, `signature`; paginate in the dashboard |
| Prune safety | Delete in a transaction; log the prune itself as an audit event (how many rows, cutoff) |
| Forensic tension | 30 days is short for incident forensics — expose `RETENTION_DAYS` and an archive/export hook so a customer can ship older records to their own cold storage before prune |
| Memory layer | Verdict *history* used for scoring (`memory.py`) is **not** pruned — it's aggregate counts, not raw logs, and it's what makes the analyst learn. Only the raw audit detail is subject to 30-day retention. |

Note the distinction: **raw audit detail** (every event line) is capped at 30 days; **aggregate signature history** (counts that drive scoring) persists. Pruning the learning would lobotomize the analyst.

### IAM — a public tier plus two signed-in roles

Local accounts only. No external IdP in the MVP (keeps invariant #3 clean and removes onboarding friction for a customer with no IT team).

The original three-role model (viewer / analyst / admin) is revised: the "viewer" is no longer a signed-in account but an **unauthenticated public tier**. From a security standpoint, an anonymous visitor should see essentially nothing operational — only a coarse, non-identifying status splash. All operational detail is behind sign-in. This both tightens the recon surface and doubles the logged-out page as a trust/marketing surface.

| Tier | How reached | Sees | Can do |
|------|-------------|------|--------|
| **Public** | no sign-in | Aggregate splash only: what Arbiter is, lifetime totals ("N events triaged, N suppressed, N escalated to date"). No hosts, IPs, users, signatures, timestamps, or live feed. | Sign in |
| **Analyst** | signed in | Full dashboard (overview, live feed, verdicts/audit, reports, assets & facts) | Overrule verdicts (`memory.label_verdicts`), approve `RECOMMEND` response actions |
| **Admin** | signed in | Everything analyst sees | All of the above **plus** AI settings, thresholds, response policy, retention config, user/role management |

**Why the public page must be zero-recon.** The dashboard is reachable by anyone who can reach its URL on the network. A logged-out page that leaked hostnames, IPs, event signatures, a live feed, or even "escalations happening right now" would hand an attacker reconnaissance and operational timing (e.g. "the analyst is asleep / the system is down / my intrusion is being flagged"). So the anonymous tier is restricted to **cumulative, aggregate, non-identifying counts** — never real-time, never per-asset. Even the agent-health indicator is withheld from anonymous view (an "offline" signal is itself a window). The whole public page is **configurable and can be disabled** — some customers will prefer a plain sign-in wall with no splash at all; default is the splash off until an admin opts in.

This still lines up with the response model in `respond.py`: `AUTO` actions stay gated by policy (prefilter-tier + auto-safe) and are not something a role "clicks"; `RECOMMEND` actions are exactly the one-click-approval surface, and only Analyst/Admin (both signed in) can approve them. The LLM tier still never auto-executes — a signed-in human with the right role is the executor.

*(Open option: keep a signed-in read-only "viewer" role for a manager who should see the dashboard but not act. Deferred unless a customer asks — collapsing to analyst/admin keeps the model minimal for a company with no security team.)*

**Auth mechanics, stdlib-only:**

- Passwords hashed with `hashlib.scrypt` (in stdlib; no `argon2`/`bcrypt` dependency needed).
- Sessions as HMAC-signed cookies (`hmac` + `secrets`), `HttpOnly`, `SameSite=Strict`, `Secure` when TLS is on.
- First-run bootstrap: generate a one-time admin setup token printed to the console (à la Jupyter), forcing a password set — no default credentials ever.
- Login throttling / lockout on repeated failure. **Dogfood:** dashboard auth failures are themselves emitted as `Event`s into Arbiter's own pipeline, so the analyst watches its own front door.
- The IAM actions (login, overrule, approval, user/threshold change) are written to the same audit store — *who did what, when* — so the dashboard's own use is as auditable as the triage it displays.
- The public splash reads only pre-aggregated lifetime counters, never the `audit` detail rows or `memory` tables — so there is no code path from the anonymous page to identifying data.

**Deferred:** SSO/OIDC, SCIM provisioning, per-asset access scoping, an optional signed-in read-only viewer role. Written so the session layer can later accept an OIDC assertion without reworking the role model.

## Trade-off analysis

The central tension is **richness vs. auditability**. A React/FastAPI stack would be faster to make pretty, but the buyer for this product is specifically someone who distrusts opaque third-party software and wants to verify nothing leaves. Every npm/pip dependency erodes the core sales argument. Choosing a stdlib-first, server-rendered service keeps the whole thing inspectable in an afternoon — which *is* the feature. We pay for that with more manual UI work, which is acceptable for a dashboard that is mostly read-and-approve.

The second tension is **retention depth vs. footprint**. 30 days bounds disk use and is a clean default for a small company, but it's short for real forensics. Resolving it by (a) making it configurable and (b) separating prunable raw detail from persistent learned aggregates gets the footprint win without dumbing down the analyst or trapping a customer mid-investigation.

## Consequences

**Easier:**
- A non-technical operator can finally see and steer the analyst; shadow-mode adoption (from CONCEPT.md) now has a UI to watch confidence build.
- The human feedback loop (next step #2, and the fix the stress test demanded) gets its natural home — overruling a false escalation is a dashboard click that calls `memory.label_verdicts`.
- Response approvals get a real surface: `RECOMMEND` actions become an inbox.

**Harder:**
- New attack surface to defend: TLS, CSRF tokens, bound to LAN by default, self-contained assets (no external CDN), rate-limited login. The dashboard must meet the bar of the product it fronts.
- A schema/storage migration: audit trail moves from JSONL-primary to SQLite-primary (JSONL retained as export).
- Ongoing UI maintenance without a framework's conveniences.

**To revisit:**
- OIDC/SSO once a customer with an existing IdP asks.
- Whether 30 days is the right default after seeing real disk growth at log volume.
- Live-updating dashboard (polling vs. SSE) if operators want a real-time feed rather than refresh.

## Proposed data model (additions)

```
users(id, username, role, scrypt_hash, salt, created_at, last_login, failed_attempts, locked_until)
sessions(token_hash, user_id, created_at, expires_at, ip)          # or stateless signed cookies
audit(id, ts, kind, event_id, host, signature, decision, score, tier,
      rationale, evidence, actor_user_id, detail_json)              # ts-indexed, 30-day prune
response_queue(id, ts, event_id, action_kind, target, mode, status, approved_by, ttl_minutes)
```
`kind` distinguishes triage verdicts from IAM events (login, overrule, user-change) and response events, so one queryable table backs the whole "who/what/when" view. `memory.py`'s existing `verdict_history` / `assets` / `facts` tables are untouched and un-pruned.

## Action items (phased)

**Phase 1 — read-only dashboard over current data**
1. [ ] Move the audit sink into a SQLite `audit` table (keep JSONL export); backfill from existing JSONL.
2. [ ] Stdlib web service: verdict list with filters (decision, host, tier, date), verdict detail, memory/facts browser. Bound to localhost/LAN, TLS-ready.
3. [ ] Read-only role plumbing so the view works before write actions exist.

**Phase 2 — IAM**
4. [ ] `users` table + `scrypt` hashing + signed-cookie sessions + first-run admin bootstrap token.
5. [ ] Role enforcement middleware; login throttling; emit auth failures as `Event`s; audit IAM actions.

**Phase 3 — act from the dashboard**
6. [ ] Overrule/confirm a verdict → `memory.label_verdicts` (closes the poisoned-history gap the stress test found).
7. [ ] Response inbox: approve/deny `RECOMMEND` actions → `response_queue`, consumed by `respond.py`. AUTO stays policy-gated.

**Phase 4 — retention & hardening**
8. [ ] Scheduled 30-day prune (configurable `RETENTION_DAYS`) + archive/export hook; log each prune as an audit event.
9. [ ] CSRF tokens, security headers, self-contained assets (no CDN), a short threat-model note for the dashboard itself.

**Deferred (explicitly out of scope for now):** SSO/OIDC, cloud-hosted option, per-asset access scoping, live-streaming UI.
