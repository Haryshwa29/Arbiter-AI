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

The recurring backup IO spike is suppressed by the LLM (environment fact) until the signature accumulates 5 benign verdicts — then the prefilter suppresses it for free. Brute force and `curl | sh` on critical assets escalate at the prefilter tier without spending an LLM call. A privilege escalation on a *low-value* laptop scores too low for the prefilter but is caught by the LLM tier. An unknown host gets elevated criticality and escalates.

## Development

```bash
python -m unittest discover -s tests -v   # unit tests (stdlib only, no pytest needed)
python -m arbiter eval                    # score the mock backend against the labeled eval set
```

CI (GitHub Actions) runs the test suite and an end-to-end smoke run on Python 3.10–3.13, plus a non-blocking eval report. The eval exits non-zero on any missed attac