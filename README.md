# Arbiter AI - Triage

The first vertical slice of the Arbiter concept (see `CONCEPT.md`): sample events in → cheap pre-filter → local LLM on ambiguous alerts → verdict with evidence or rationale → audit trail. No collector, no dashboard — just proof that the brain works.

## Install it

Released builds ship as a single zipapp plus a short, readable bootstrap script
(ADR-002). Download, read the script, then run it — Arbiter's own prefilter
escalates `curl | sh`, so the install instructions never ask you to do it.

```bash
# Linux / macOS
curl -fsSLO https://github.com/Haryshwa29/arbiter/releases/latest/download/install.sh
less install.sh
sh install.sh --dry-run     # prints every step, changes nothing
sh install.sh
```

```powershell
# Windows
Invoke-WebRequest https://github.com/Haryshwa29/arbiter/releases/latest/download/install.ps1 -OutFile install.ps1
notepad install.ps1
powershell -ExecutionPolicy Bypass -File install.ps1
```

Both scripts verify the download against `SHA256SUMS` before executing it and
refuse to continue on a mismatch. The installer then handles preflight checks,
directories, config, seeded databases, the first admin account, and a boot
service (systemd / Task Scheduler). Other lifecycle commands:

```bash
python arbiter-x.y.z.pyz --status
python arbiter-x.y.z.pyz --upgrade      # swaps the build, keeps all databases
python arbiter-x.y.z.pyz --uninstall    # asks separately before deleting data
```

New installs default to shadow mode with response in dry-run: nothing is
blocked until you have watched it and said so.

Build the artifacts yourself with `python tools/build_release.py --clean` —
the `.pyz` is a plain zip of readable source, so `unzip -l` shows everything
that will run on your machine.

## Run it from a checkout

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

Labeled eval sets score a backend and report **recall / precision** plus an adversarial PASS/FAIL gate:

- `samples/realistic_suite.jsonl` — **101 cases replicating a deployment day**: routine ops noise (auth, deploy, backup, cloud, dev, hardware, network) plus attacks across the full kill chain (recon → brute force → execution → persistence → privesc → credential access → lateral movement → exfil → impact/ransomware/mining → DDoS → cloud misconfig) and disguised fact-traps. This is the **precision benchmark** — the real question is whether a model keeps 100% recall while suppressing the day-to-day noise.
- `samples/adversarial_suite.jsonl` — 11 disguised-attack categories (the fact-trap gate).
- `samples/stress_set.jsonl` (58) and `samples/eval_set.jsonl` (24) — earlier sets.

```bash
python -m arbiter eval samples/realistic_suite.jsonl --backend ollama --model qwen3.5:4b
python -m arbiter eval samples/adversarial_suite.jsonl --backend mock --no-guardrails  # watch the raw model fail
```

**Honest finding on the fact-trap class.** Evaluated directly, a 4B model (`qwen3.5:4b`) catches every clear, subtle, DDoS and corruption attack and perfectly suppresses legitimate maintenance — but it caught **0 of 9 fact-traps** (attacks disguised as routine maintenance), *worse* than the dumb keyword mock, because a smarter model over-applies the benign "maintenance window" framing. Fact-trap resistance therefore lives in code, not the model: the non-suppressible **security guardrails** (`arbiter/guardrails.py`) wrap the LLM on both sides. With guardrails on (the default), both backends reach 100% recall on the fact-trap set with precision unchanged. `--no-guardrails` isolates the raw model. See `docs/ARCHITECTURE.md` → Guardrails.

(Note: an earlier revision of this README claimed the 4B model scored 100% on fact-traps. The adversarial suite, with harder traps, showed that was over-optimistic — this is the corrected, guardrail-backed picture.)

## Frontend (being rebuilt)

The previous web layer — a stdlib `http.server` dashboard plus a Svelte SPA — was **removed on 2026-07-26** to rebuild the frontend from scratch. The backend it read from is retained: the triage engine, the `store.py` audit store, and `iam.py` (accounts, sessions, lockout). A new server/API will be added when the new frontend lands, at which point the `serve` command and the installer's service target will be rewired.

## Next steps

1. Evaluate real local models against the mock: build a labeled eval set, answer "minimum viable local model" (the biggest open question).
2. Human feedback loop CLI: confirm/overrule escalations → `memory.label_verdicts`.
3. Wrap a real collector (Vector/Wazuh decision) emitting the `Event` schema.
4. Event-triggered micro-rescans when unknown assets appear.

## License

Not yet licensed — all rights reserved. A license will be chosen when the product is ready to open up.
