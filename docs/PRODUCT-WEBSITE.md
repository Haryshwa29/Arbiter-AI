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
temporary SQLite files. Public serving defaults to **live Ollama Cloud reasoning**
using Nemotron 3 Nano. Deterministic screening and guardrails still decide clear
cases; only ambiguous events call the model. Each AI verdict records its backend
and model. There is no mock fallback: cloud failure escalates by safety policy,
labelled separately from an AI decision. Test fixtures can explicitly inject mock. Responses
are always simulated. No collection configuration, login, model selection or
firewall route exists on this server. The real device dashboard stays protected.

Limits: 8 visitor sessions, 300 requests per visitor per minute, 30-minute idle
expiry, 20 uploaded files, 5 MiB combined text and 5,000 selected events. Files
must be JSON, JSONL or CSV event data; arbitrary binaries/documents are rejected.
Uploaded event records require explicit cloud-processing consent before starting.
Event content and simulation context may be sent to Ollama Cloud. Only sample or
sanitized data belongs here; installed monitoring remains local-only. Cloud runs
are capped at 100 events, 32 KiB prompt context per request, 512 output tokens,
one concurrent request, and 100 requests per hour across all visitors by default
(`--ai-hourly-limit`). Counters/allowances are process-local and reset on restart;
configure provider budgets and edge rate limits for a public deployment.
The live status panel reports configuration, active requests, successful calls and
failures for the service; it never treats key configuration as a successful probe.

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


## Live AI and Cloudflare deployment (October 14)

Set `OLLAMA_API_KEY` in the server environment (never in browser/Vite settings).
The CLI defaults to `--model nemotron-3-nano:30b`; cloud API names differ from
Ollama CLI `:cloud` aliases. Verify available API model IDs and account access at
https://ollama.com/api/tags and https://ollama.com/settings before launch.
An absent key disables starting a public AI run with a clear 503; an invalid key,
provider limit or malformed response produces an explicit policy escalation.
No API key was supplied or live provider request verified during implementation.

The root `Dockerfile.website`, `wrangler.jsonc` and
`deploy/cloudflare/worker.js` prepare an all-Cloudflare deployment. This is not a
Pages-only upload: the current Python/SQLite/threading runtime uses Cloudflare
Containers, which requires Workers Paid. No paid resources were created.

1. Install Docker and Cloudflare Wrangler 4.151.0 (the validated version) or later on the deployment
   machine. Set `WRANGLER_SEND_METRICS=false` to disable CLI usage metrics.
   These are build/deployment tools; no new Python, frontend or Worker
   runtime package is required. The Worker uses native Durable Object APIs.
2. Set `vars.PUBLIC_ORIGIN` in `wrangler.jsonc` to the exact HTTPS origin you will
   serve, with no trailing slash. For workers.dev use the matching worker name
   and account subdomain; for a custom domain configure the corresponding Worker
   route in Cloudflare. The default placeholder deliberately rejects traffic.
3. Authenticate with `npx wrangler login`. Save the key privately with
   `npx wrangler secret put OLLAMA_API_KEY`; enter it at the private prompt.
   Never put it in Wrangler vars, Docker build arguments, logs or git.
4. Review the configuration and Cloudflare costs, then run `npx wrangler deploy`
   from the repository root. The image builds the public frontend and includes
   only source/sample inputs; monitoring data and local environment files are
   excluded. It serves on port 8080 as an unprivileged user.
5. Add Cloudflare edge request/rate limits, provider spending limits, and verify
   an actual sample run before sharing the URL. Check one `ollama-cloud` verdict
   with model/evidence/rationale, one deterministic verdict, and a provider failure.
   Container startup can take a few seconds. Key changes require restarting the
   running container so its startup environment refreshes.

All requests use one named container so visitors retain their isolated sessions.
Sessions and process-local quota are lost on restart or deployment. The container
sleeps after 30 minutes of inactivity. No telemetry or payload logging is enabled.
The Docker image builds successfully and its public-page, missing-key status and
operational-route isolation smoke checks passed. Wrangler 4.151.0 deployment
dry-run compiled the Worker and built its image successfully. No resources were
created. Cloudflare live execution remains unverified. Local Wrangler container
development is unsupported on native Windows; use WSL/Linux for the combined
Worker/container integration check. The direct Docker smoke test works on this PC.

References: https://docs.ollama.com/cloud,
https://developers.cloudflare.com/containers/examples/env-vars-and-secrets/,
https://developers.cloudflare.com/containers/platform/pricing/.

UI tooling: Demo drawer, Demo & Replay, and EventPanel adapt existing components.
21st.dev Magic and ui-ux pro max were unavailable in this session; neither was
used. Public TypeScript/build and lint checks cover the changed frontend.

Validation: full Python suite 301 passed, 12 skipped (11 subtests passed);
seed/sample-run smoke passed; public frontend build and lint passed (two existing
Fast Refresh warnings). Provider tests use controlled HTTP responses and cover
authentication, malformed/failing responses, shared quota, redirect rejection,
missing credentials, upload consent, visitor isolation, recorded model provenance
and explicit policy escalation through the actual demo pipeline. Live Ollama
access and deployed Cloudflare execution still require operator configuration.
