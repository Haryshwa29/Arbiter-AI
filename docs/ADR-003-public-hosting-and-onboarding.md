# ADR-003: Static public hosting, and setup as a screen instead of a flag

**Status:** Accepted
**Date:** 2026-07-30
**Deciders:** Haryshwa
**Related:** ADR-002 (amends Decision 1's replacement and Phase 5), `arbiter/api/server.py`, `arbiter/install/`, `frontend/`, `CLAUDE.md` invariants

## Context

ADR-002 assumed the official Arbiter site would be a hosted Python instance behind a
reverse proxy — the dogfood pitch. That decision was already withdrawn when
`arbiter/web/` was removed; this ADR replaces it rather than reviving it.

Two frictions forced the question:

1. **A visitor cannot use the trial dashboard.** `/api/login` is a Python route. On a
   static host it 404s, so the sign-in screen fails before `iam.py` is ever reached.
   Nobody visiting a marketing site is going to start a local server first.
2. **A customer install needs a reverse proxy.** `arbiter serve` speaks JSON only, so
   something else has to serve the SPA. That quietly contradicts the one-command
   installer ADR-002 Decision 2 promises.

A third pressure is positioning: if the model is bring-your-own, the onboarding reads
as a developer tool rather than a product.

## Decision 1 — The public site is static; there is no public backend

Host the prerendered `build:public` output on Cloudflare Pages. No VM, no Worker, no
Python reachable from the internet.

**Rejected alternatives.**

- *Cloudflare Worker + D1 reimplementing the read API.* Duplicates engine read-paths in
  TypeScript. For a product whose argument is "read the code yourself," two
  implementations that drift is the worst available outcome.
- *Cloudflare Tunnel to a machine we own.* Free and real, but the site is up exactly as
  long as that machine is. The whole point is not having to babysit it.
- *A VPS running the real thing (ADR-002 Phase 5).* Real product, but it means operating
  a service, and one shared database every visitor can write to through `/api/label` and
  `/api/acknowledge`.

## Decision 2 — The public build has no authentication at all

A public demo with a login form has only bad options: hardcode weak credentials on a
live security product, or gate a demo behind an access request.

So the landing's call-to-action opens the dashboard directly, with a persistent
"demo data" banner. `Login.tsx` ships only in the self-hosted build, where it is
protecting something. Visitors never touch an auth path.

## Decision 3 — Demo data is captured from a real run, not mocked

`api.ts` gains a second adapter behind the same interface, selected by a build flag.
Its data is **the audit JSONL from an actual `arbiter run` against `samples/events.jsonl`
with a real model through Ollama** — not `MockBackend` heuristics and not hand-written
fixtures.

The visitor therefore sees genuine model-written rationales and real guardrail vetoes,
recorded rather than generated. The banner must say exactly that: *recorded from a live
run, not generated in your browser*. Roughly 50 KB, instant load, cannot 500.

**Rejected:** running the engine in-browser via Pyodide. Technically viable — `arbiter`
is stdlib-only and `sqlite3` ships with Pyodide — but ~8 MB before first paint, an
`http.server` shim, and `MockBackend` only. A recording of the real thing is more honest
than a live run of the mock.

**Not viable, for the record:** shipping the model itself. `qwen3.5:4b` is stock public
weights pulled by Ollama at install time; nothing is fine-tuned (invariant #4). Even if
there were an artifact, GitHub rejects files over 100 MB and Pages caps files at 25 MB.

## Decision 4 — `arbiter serve` serves the SPA

`api/server.py` gains static file serving with SPA fallback; `tools/build_release.py`
bundles `frontend/dist` into the `.pyz`. One process, one origin — which is already what
the `SameSite=Strict` session/CSRF design assumes.

This is required for Decision 5 and is worth doing regardless of hosting.

## Decision 5 — Setup is a screen, not a flag

`arbiter install` runs preflight, starts the server, and opens the browser to a setup
route in the React app: preflight results as a checklist, model recommendation
preselected with live pull progress, create the admin account, land in the dashboard.

Reuses frontend work already in flight; no tkinter, no new dependency.

**Constraint:** the setup routes are unauthenticated by necessity (no admin account
exists yet) and must become unreachable the moment setup completes — a persisted
`setup_complete` flag checked server-side, not a frontend redirect.

**Rejected:** a native tkinter installer (dated, needs separate testing on both
platforms, duplicates React work) and a guided CLI wizard (cheapest, but still reads as
a developer tool).

## Decision 6 — Choose the model for them; publish a verified list later

Model choice is an advanced option, never a question put to the user.

- **Now:** extend `preflight.py` — it already reads total RAM and warns *"under 8 GB,
  prefer a smaller model"* — so that the warning becomes a selection. Read RAM, pick from
  a small table, preselect, pull. `--model` stays for people who want it.
- **Later, once the labeled eval set exists (next step #1):** publish a **verified model
  list** — three or four models actually measured against it, with recall, precision, and
  fact-trap survival. On-list models install in one choice; off-list models still work but
  the dashboard shows an "unverified model" badge.

Publishing numbers before they can be measured would be guessing, so the list waits. The
list also gives the eval set a customer-facing purpose instead of being internal
curiosity.

### Why model-agnostic is the claim, not the gap

Without Arbiter, `qwen3.5:4b` caught 0 of 9 fact-traps. Wrapped in `guardrails.py` and
the scope-checking in `facts.py`, 100%. The product is what makes a cheap open-weights
model trustworthy enough to point at logs — safety in code a customer can read, not in
weights they must trust. The model is the witness; Arbiter is the judge that does not
take the testimony at its word. `respond.py` already states this: the model proposes,
rules dispose.

## Consequences

**Easier:** no public infrastructure to operate, patch, or pay for; no shared demo state;
no public write endpoints; customers stop needing a reverse proxy; the eval set acquires
a shipping purpose.

**Harder:** the demo recording must be regenerated when engine output changes materially,
or it becomes a lie; two frontend build targets (public/demo, self-hosted/live) both need
testing; setup routes are a new unauthenticated surface that must fail closed; the
dogfood pitch ("this site runs on the software you're about to install") is gone for
good — replaced by "the demo is a recording of a real run, and here is the code that
produced it."

## Action items

1. Static serving + SPA fallback in `api/server.py`; `frontend/dist` into the `.pyz`.
2. Demo adapter behind `api.ts`; capture the recording from a real Ollama run.
3. Public build: drop `Login.tsx`, wire the landing CTA straight to `/app`, demo banner.
4. Cloudflare Pages deploy of `build:public`.
5. RAM-driven model preselection in `preflight.py` / `install/cli.py`.
6. Setup wizard routes + `setup_complete` gate; `arbiter install` opens the browser.
7. *(after the eval set)* verified model list + unverified-model badge.
