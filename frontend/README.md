# Arbiter frontend

React + Vite + TypeScript + Tailwind. Two things live here: the public landing
(`src/site/`) and the dashboard (`src/views/`), selected by a build mode.

## Running it locally

Two processes. The API serves data; Vite serves the app and proxies `/api` to it on the
same origin, which is what keeps the `SameSite=Strict` session and CSRF cookies working
without adding CORS to the backend.

```bash
# terminal 1 — the JSON API on :8787, with sample data and throwaway logins
python -m arbiter --db arbiter_memory.db serve --dev-accounts --demo-feed

# terminal 2 — landing at /, dashboard at /app
cd frontend && npm run dev:site
```

`--dev-accounts` prints two known-weak logins and resets them on every boot; it is off
by default and the installed service never passes it. `--demo-feed` replays
`samples/events.jsonl` through the triage engine on a timer so the views have something
to show.

### Why `dev:site` and not `dev`

`npm run dev` runs in the default mode, where `VITE_PUBLIC_LANDING` is unset. That is
the **customer install** shape: the dashboard is at `/` and the landing route is not
registered at all (see `App.tsx` and `src/lib/routing.ts`). Use it when you are working
on the dashboard.

`npm run dev:site` is `vite --mode public`: the landing takes `/`, the dashboard moves
to `/app`. Use it when you are working on the landing, or when you want to see both.

## Building

```bash
npm run build         # customer-install bundle: dashboard at /, no landing routes
npm run build:public  # public site: client + SSR + prerender of /
npm run preview       # serve the last build — use this to check the prerender
```

`build:public` is the one to check theme and first-paint behaviour against, since the
prerendered HTML is where a wrong-theme flash or a missing-copy bug would show up.

## Where the specs live

- `docs/LANDING-BRIEF.md` — what the landing must do, and the three rules that keep the
  public build from touching authenticated routes
- `docs/HERO-TRANSIT-BRIEF.md` — the hero sequence, its constants, and the layout band
- `docs/THEME-BRIEF.md` — tokens, the light/dark field, measure, the override toggle
- `docs/FRONTEND-BRIEF.md` — the dashboard views and the API client
- `docs/ADR-003-public-hosting-and-onboarding.md` — how this gets hosted, and why the
  public build has no login
