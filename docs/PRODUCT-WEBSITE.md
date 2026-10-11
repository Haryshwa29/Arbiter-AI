# Public product website

The October 11 redesign supersedes the old transit hero and public dashboard
entry points. The public website is a single static product page: introduction,
an animated event walkthrough, expanded decision architecture, capabilities,
platform setup and practical questions. Dark green / charcoal, warm gold and
system serif typography require no remote assets.

The second revision explains value for operators and implementation for technical
reviewers. Current capabilities and future ambitions are explicitly separated.
The architecture shows guardrails, deterministic decisions, optional local AI,
scoped environment memory, final checks, outcomes and the approval boundary.
Technical details expand on event contracts, queue semantics and MVP limits.

`tools/render_product_flow.py` renders the shipped illustrative GIFs and still
posters locally using Pillow and Windows system fonts. Desktop and portrait
mobile versions are selected responsively. A pause/play control swaps to a
static poster; reduced-motion preferences disable autoplay. A readable HTML
transcript accompanies the illustration. This animation never connects to
customer telemetry and is labelled accordingly.

`npm run build:public` builds and prerenders the product site only. Vite selects
`PublicApp.tsx`, excluding dashboard modules and authentication from that bundle.
There is no public login or operational dashboard shell under `/app`, and no
operational API proxy in public mode. Customer installs retain their authenticated dashboard
through the default `npm run build` target.

No downloadable releases were published at the time of this change. Windows
links to its setup documentation, Linux links to source with validation status,
and macOS is clearly marked in development. Replace the Windows setup link with
a verified release asset when a packaged installer is published. Do not label
unpublished or unvalidated packages as available downloads.

Magic UI and ui-ux pro max, requested by AGENTS.md, were unavailable in this
session. Existing site components were adapted without new dependencies;
layout, keyboard focus, mobile overflow, network requests and browser errors
were checked directly instead.

## Website simulation drawer

The subsequent requested demo uses the same `DemoReplay`, `EventPanel`, parser
and `DemoManager` as the installed product. It is lazy-loaded only after **Try
demo** is clicked. Landing navigation makes no simulation or monitoring requests.
All playback settings, multiselect datasets, structured file uploads, validation,
live results, event details and filtered history are shared with the PC demo.

The website has a separate backend, `arbiter.site_demo`, serving `/public-demo/*`.
It never connects to the installed service on port 8787. Each visitor gets an
unguessable HttpOnly, SameSite=Strict scoped cookie and a separate manager with
temporary SQLite files. It runs the **mock test reasoning backend**, explicitly
labelled; it does not claim to demonstrate an attached local model. Responses
are always simulated. No collection configuration, login, model selection or
firewall route exists on this server. The real device dashboard stays protected.

Limits: 8 visitor sessions, 300 requests per visitor per minute, 30-minute idle
expiry, 20 uploaded files, 5 MiB combined text and 5,000 selected events. Files
must be JSON, JSONL or CSV event data; arbitrary binaries/documents are rejected.
Uploaded event records are processed on the demo server and retained only in
temporary session state until replacement, expiry or clean shutdown. The UI
advises sample or sanitized data. Disk encryption and guaranteed crash cleanup
are not claimed.

Build and run a complete local website preview:

```powershell
cd frontend
npm run build:public
cd ..
python -m arbiter.site_demo --root frontend/dist --port 4173
```

For a static-only host, the product page works but the demo needs this separate
service behind a same-origin `/public-demo/` reverse proxy. Before exposing it
publicly, configure HTTPS and the exact `--origin`, TLS termination, edge request
limits, bounded process resources and temporary-storage cleanup. Never forward
public demo traffic to the installed monitoring API. No public deployment was
performed in this iteration.

Validation covers isolated visitors, source/build separation, expiry/capacity,
upload/path/format limits, cross-origin rejection and unknown operational routes.
Browser checks exercise datasets, upload validation, playback settings, pause,
resume, stop, linked details and history on desktop and mobile with zero
operational `/api` requests.
