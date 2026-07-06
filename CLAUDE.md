# Arbiter AI

Self-hosted AI security analyst for small companies with no security team. Read `CONCEPT.md` for the full product vision and `README.md` for how to run the current slice.

## Current state

First vertical slice of the triage engine (Python, stdlib-only):

- `arbiter/schema.py` — Event/Verdict data contract. **This is the stable boundary a future Go collector agent must honor. Do not change it casually; keep it dependency-free.**
- `arbiter/memory.py` — SQLite memory layer: asset criticality, verdict history per signature, environment facts. Deliberately human-readable (transparency is a product feature).
- `arbiter/prefilter.py` — cheap tier: severity × criticality × history. Thresholds are provisional; shadow-mode data should tune them.
- `arbiter/llm.py` — pluggable backends: `OllamaBackend` (local open-weights model) and `MockBackend` (deterministic heuristics for tests/dev).
- `arbiter/triage.py` — orchestrator, shadow mode, JSONL audit trail.
- `arbiter/respond.py` — response actuator: surgical, TTL-limited actions from escalation verdicts (block IP / lock account / kill session / quarantine host). Dry-run default; AUTO only for prefilter-tier + auto-safe catalog entries, LLM-tier is always RECOMMEND. Allowlists (CGNAT/office NAT) deliberately deferred.
- `arbiter/store.py` — queryable SQLite audit store for the dashboard; `lifetime_counts()` is the only public-safe (non-identifying) view; 30-day `prune()`. Separate from `memory.py`, which is never pruned.
- `arbiter/iam.py` — built-in IAM: local accounts, `hashlib.scrypt` hashing, HMAC-signed session cookies, `analyst`/`admin` roles, lockout. Stdlib-only.
- `arbiter/web/` — self-hosted dashboard (ADR-001): stdlib `http.server`, server-rendered UI, public zero-recon splash, sign-in, live SSE feed wired to the real `TriageEngine`. No external deps, no CDN.
- `arbiter/cli.py` — `python -m arbiter seed` / `run samples/events.jsonl [--respond]` / `serve`.

## Design invariants (do not violate)

1. **Asymmetric error costs**: missing a real breach is fatal; false escalations are cheap. Suppression always requires stronger justification than escalation. LLM failure → escalate by policy.
2. **Every suppression carries a written rationale; every escalation carries an evidence summary.** No silent verdicts.
3. **Nothing leaves the customer's network.** No cloud API calls in the triage path. LLM inference is local (Ollama) or mock.
4. **Adaptation through context, not weights** — learning lives in the SQLite memory layer, never in fine-tuning.
5. Collection logic stays out of the brain. Anything that reads logs communicates with triage only through the `Event` schema.
6. **Response mirrors both 1 and 5**: blocking requires stronger justification than alerting (false blocks are costly). Response logic stays out of the brain — `respond.py` consumes verdicts, `triage.py` never gains side effects. Actions are surgical, reversible, TTL-limited; never service-wide. The LLM tier never auto-executes.

## Verify changes

```bash
python -m arbiter --db /tmp/arbiter.db seed
python -m arbiter --db /tmp/arbiter.db run samples/events.jsonl --audit /tmp/audit.jsonl
```

Expected: backup IO spikes suppressed (LLM tier first, prefilter after 5 benign verdicts), brute force + curl|sh escalated by prefilter, laptop priv-escalation caught by LLM tier, unknown host escalated.

## Next steps (agreed with Haryshwa)

1. Labeled eval set to answer "minimum viable local model" — biggest open question.
2. Human feedback loop CLI (confirm/overrule → `memory.label_verdicts`).
3. Collector wrapper decision (Vector vs Wazuh) emitting the Event schema.
4. Event-triggered micro-rescans for unknown assets.
