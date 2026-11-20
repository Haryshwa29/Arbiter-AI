# Arbiter architecture — still-diagram edition

**Current November 20 source: five decision workers plus a separate CPU report
worker.** Qwen3.5:4b is L1; only its successful model escalations enter the L2
pre-filter and, when unresolved, Gemma4:12b. All final routes pass shared checks.
A separate worker prepares reports from saved evidence without an AI call.

![Current architecture: collection and durable queue, gateway, L1 rules and Qwen, L2 pre-filter, independent Gemma, shared final guardrails, saved decisions, separate CPU reports, authenticated dashboard and scoped live repeat memory.](arbiter-flow.svg)

Each box explains its job in everyday language. Side arrows show which cases
avoid a model review. The dashboard can show a saved decision before its longer
report is ready. Either model is replaceable with a compatible local model;
Ollama is the current runner. Classification grants no device-action authority.

The measured 20K checkpoint predates compact replies and the separate report
worker. Those source changes passed software checks and await real-model retesting.

[What the workers do](../ARCHITECTURE-WALKTHROUGH.md#2-triage-decide-with-evidence) ·
[Review and human corrections](../ARCHITECTURE-WALKTHROUGH.md#3-review-explain-before-asking-for-action) ·
[Model and deployment boundaries](../ARCHITECTURE-WALKTHROUGH.md#4-boundaries-keep-reasoning-and-authority-separate) ·
[Latest results](../PROGRESS-2026-11-20.md)
