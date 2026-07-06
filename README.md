# Arbiter — triage engine slice

The first vertical slice of the Arbiter concept (see `CONCEPT.md`): sample events in → cheap pre-filter → local LLM on ambiguous alerts → verdict with evidence or rationale → audit trail. No collector, no dashboard — just proof that the brain works.

## Run it

Requires Python 3.10+, no dependencies for the mock backend.

```bash
python -m arbiter seed                      # demo assets + environment facts
python -m arbiter run samples/events.jsonl  # triage with the mock LLM
```

With a real local model (install [Ollama](https://ollama.com), `ollama pull llama3.1:8b`):

```bash
python -m arbiter run samples/events.jsonl --backend ollama --model llama3.1:8b
```

Verdicts append to `audit.jsonl`; memory lives in `arbiter_memory.db` (plain SQLite — open it, that's the transparency story).

## How it maps to the concept

| Concept | Here |
|---|---|
| Event/verdict data contract (future Go agent boundary) | `arbiter/schema.py` |
| Per-company memory layer: assets, verdict history, facts | `arbiter/memory.py` |
| Cheap pre-filter: severity × criticality × history | `arbiter/prefilter.py` |
| LLM tier, local open-weights via Ollama | `arbiter/llm.py` |
| Escalate-with-evidence / suppress-with-rationale, shadow mode, audit trail | `arbiter/triage.py` |

Asymmetric error costs are enforced in three places: the prefilter only suppresses with strong benign history, low-confidence LLM suppressions are upgraded to escalations, and any LLM failure escalates by policy.

## What the sample run demonstrates

The recurring backup IO spike is suppressed by the LLM (environment fact) until the signature accumulates 5 benign verdicts — then the prefilter suppresses it for free. Brute force and `curl | sh` on critical assets escalate at the prefilter tier without spending an LLM call. A privilege escalation on a *low-value* laptop scores too low for the prefilter but is caught by the LLM tier. An unknown host gets elevated criticality and escalates. The sample set also covers DDoS (volumetric flood, SYN flood, slowloris, and a benign launch-day spike), geo-location attacks (impossible travel, anomalous-country admin login), and internal corruption (tampered system binary, ransomware-pattern mass rename, failing disk).

## Response actuator (surgical auto-block, dry-run)

`arbiter/respond.py` turns escalation verdicts into *surgical* actions — one IP, one account, one session, one process, one host; never a service-wide switch:

```bash
python -m arbiter run samples/events.jsonl --respond   # plans actions, executes nothing
```

The trust-model extension: blocking requires stronger justification than alerting, because a false block is costlier than a false alert. So AUTO execution is reserved for deterministic prefilter-tier escalations with auto-safe actions (brute-force IP ban with a 60m TTL, kill/lock an impossible-travel session); LLM-tier escalations always produce RECOMMEND actions for one-click human approval — the model proposes, rules dispose. Actions that could take the service down (quarantining a crown-jewel host, edge under-attack mode for volumetric DDoS) are never auto, regardless of tier. All actions are TTL-limited or held-for-review, land in `response_audit.jsonl`, and dry-run is the default (the response analog of shadow mode). Response logic lives outside the brain, consuming verdicts the same way collectors emit events. Deferred: never-block allowlists (office NAT / CGNAT) and live executors.

## Development

```bash
python -m unittest discover -s tests -v   # unit tests (stdlib only, no pytest needed)
python -m arbiter eval                    # score the mock backend against the labeled eval set
```

CI (GitHub Actions) runs the test suite and an end-to-end smoke run on Python 3.10–3.13, plus a non-blocking eval report. The eval exits non-zero on any missed attack; the mock backend deliberately fails the fact-trap cases, so the eval only becomes a hard CI gate once a real local model runs it.

## Evaluating a model ("minimum viable local model")

`samples/eval_set.jsonl` is 24 hand-labeled cases (clear attacks, attacks disguised behind a plausible-but-wrong environment fact, and benign anomalies) scored by calling the LLM backend directly — bypassing the prefilter, since that's already rule-based and the open question is specifically about model judgment.

```bash
python -m arbiter eval --backend mock                      # baseline: fails the fact-trap cases on purpose
python -m arbiter eval --backend ollama --model qwen3.5:4b  # candidate model
```

The report leads with missed attacks (fatal per the trust model) before accuracy — that's the number that decides whether a model is usable at all. On this eval set, a ~4B model (`qwen3.5:4b`) scored 100% including every fact-trap case, once `OllamaBackend` disabled the model's "thinking" mode (hybrid-reasoning models otherwise put the whole answer in a `thinking` field and leave `response` empty under a forced `format: json`, which broke parsing).

## Dashboard (self-hosted web UI)

A stdlib-only web dashboard (ADR-001) over the triage engine — no external dependencies, nothing loads from off the network.

```bash
python -m arbiter seed
python -m arbiter serve                                   # http://127.0.0.1:8787
python -m arbiter serve --backend ollama --model qwen3.5:4b   # real local model in the feed
```

On first run it prints one-time `admin` and `analyst` credentials. The logged-out page is deliberately zero-recon — only cumulative aggregate counts, no hosts/IPs/signatures/live feed. After sign-in, `analyst` and `admin` see the live feed (Server-Sent Events streaming real verdicts from the triage engine), overview, and audit; `admin` also sees settings/users/retention. Sessions are HMAC-signed cookies, passwords hashed with `hashlib.scrypt`, logins throttled, and a failed dashboard login is itself fed back into Arbiter as an event.

## Next steps

1. Evaluate real local models against the mock: build a labeled eval set, answer "minimum viable local model" (the biggest open question).
2. Human feedback loop CLI: confirm/overrule escalations → `memory.label_verdicts`.
3. Wrap a real collector (Vector/Wazuh decision) emitting the `Event` schema.
4. Event-triggered micro-rescans when unknown assets appear.

## License

Not yet licensed — all rights reserved. A license will be chosen when the product is ready to open up.
