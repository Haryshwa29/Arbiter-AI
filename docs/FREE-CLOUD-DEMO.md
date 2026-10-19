# Free hosted AI preview

The production website uses Cloudflare Pages plus a Pages Function (a Worker),
not the earlier Python container proposal. The function is
`frontend/functions/public-demo/[[path]].js`; Git-connected Pages builds with
root `frontend`, command `npm run build:public`, output `dist` deploy it.
No new runtime packages, container, domain purchase or always-on PC is needed.

In Pages settings, save **Production Secret** `OLLAMA_API_KEY` and deploy again.
Optional plain variable `OLLAMA_MODEL` selects an Ollama Cloud **API model ID**;
default is `nemotron-3-nano:30b`. Account/model access and allowance are enforced
by Ollama. Free access is not unlimited. Do not add paid credits for a zero-cost
demo. Never put the key in git, frontend code or a `VITE_` variable.

## Actual behavior and limits

`GET /public-demo/status` reports model and whether a server key is configured.
`POST /public-demo/analyze` sends one validated event to Ollama and returns a
structured verdict with backend/model, rationale and evidence. It requires the
same Origin, custom header and explicit cloud consent. Provider responses and
keys are never logged or echoed. Payload/response sizes, output tokens and request
timeouts are bounded. Low-confidence suppression is escalated for review.

This is an **AI preview, not a port of the installed Python engine**. All selected
events go to the cloud model. It does not execute Python guardrails, collection,
correlation, environment memory or response planning, and never acts on devices.
The system instructions match Arbiter's prompt; history/facts are explicitly
unavailable. The full installed product continues to use local inference.

The browser handles sample selection, simple-schema JSON/JSONL/CSV parsing,
pacing, pause/resume, shuffled ordering, details and filtered history. It does not
upload raw files to persistent storage. Up to 100 events can be selected; each
event must fit within 12 KiB, with a 16 KiB server request limit. Native tool-export
formats accepted by the installed Python adapters are not all supported here.
Only sample/sanitized events belong in this preview. History disappears on refresh
or replacement. The module retains an active run when the drawer closes. A failed
AI request stops delivery and is displayed as failed, without a fabricated verdict.

Rate limits are **best effort per Worker isolate**: one active request, 25 requests
per caller IP per hour, and 100 total per hour. Multiple Cloudflare isolates or
restarts can exceed these totals. Origin checking is not authentication and cannot
stop non-browser callers. These limits are not a distributed spending cap. Use
provider allowance/spending settings; never rely on an in-memory counter for cost
control. Static pages are excluded from Functions invocation with `_routes.json`.

## Verification

`npm run test:demo` checks credential redaction, same-origin and consent handling,
limits, real-request protocol, provider failures, model provenance, confidence
handling and the browser's validation-to-inference/history flow using controlled
responses. `npm run build:public` verifies types and prerendering.

After deploy, check `/public-demo/status`, then send one synthetic event and
inspect its returned `ollama-cloud` model and rationale. A configured key alone
does not prove successful model access. Real provider verification is recorded in
the task handoff after deployment.

UI work adapted DemoReplay and DemoDrawer; no new form/table component was built.
21st.dev Magic and ui-ux pro max were unavailable and were not used.
