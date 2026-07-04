# Arbiter AI — Concept & Architecture

*Captured from brainstorming session, July 3, 2026. Living document — revise as the MVP takes shape.*

## One-liner

A self-hosted AI security analyst for companies too small to afford Splunk or a SOC. Your data never leaves your network. Attack knowledge does — anonymized, validated, and shared so everyone gets safer.

## The problem

- Splunk-class SIEMs price per GB ingested (~$1,800/GB/yr, up to ~$50K with features) — absurd for startups with moderate-to-heavy data flow. Verify current pricing before publishing externally.
- Free OSS SIEMs (Wazuh, Security Onion, Elastic) exist but are "free like a puppy": they need an analyst to write rules, tune noise, and watch dashboards. The target customer has no security hire.
- Result: growing companies with real data flow are unprotected and increasingly targeted.
- Validated signal (AWS Summit networking): these companies **will not ship their logs to a third party**. Any solution must run inside their environment.

## Target user

Small companies / startups with moderate-to-heavy data flow, no dedicated security team, no budget for enterprise SIEM or outsourced SOC. For them Arbiter isn't reducing analyst fatigue — **it is the analyst**.

## Positioning

Not "cheaper Splunk." **"The SIEM that doesn't need an analyst, because the analyst is built in."**

- Collection layer = table stakes (wrap/fork an OSS stack; don't rebuild it).
- The AI triage brain = the product.
- Pricing counter-position: per asset / flat monthly, never per GB. "Your data volume is irrelevant, it never leaves your network."

## Core product loop

1. **Onboarding scan** → asset inventory with AI-suggested, human-confirmed criticality scores (top ~20 assets). One-time; not a compliance-grade audit — exists to answer "how much should I care that this happened on *this* machine?"
2. **Continuous monitoring** → agent watches log streams locally.
3. **Triage per alert** → score = source severity × asset criticality × historical verdicts × correlation across events. Cheap pre-filter tier first; LLM only on ambiguous cases (LLM-per-alert is too expensive at log volumes).
4. **Escalate or suppress** → above-moderate verdicts escalate **with an evidence/investigation summary** (triage, not filtering). Everything else suppressed **with a logged rationale**, browsable in an audit trail.
5. **Self-healing risk map** → "need-to-know" rescans are event-triggered, not manual: unknown asset appears in logs, known asset changes communication/auth patterns, or an alert fires on an asset with a stale assessment → targeted micro-rescan of that asset. Never full-estate rescans.

## Trust model (the make-or-break)

The fatal failure mode is suppressing a real breach — one missed true positive and the customer turns Arbiter off forever. Asymmetric error costs are baked into scoring. Therefore:

- **Shadow mode first**: Arbiter scores alongside the human for weeks before it earns the right to suppress anything.
- Every suppression carries a written rationale + audit trail.
- **Open-core**: the agent/collector and the pattern-extraction code are open source (auditable — "verify yourself that nothing leaves"). The scoring engine, curation, and reporting are proprietary. GitHub is also the distribution channel for this buyer.
- Installing a third-party binary with deep read access is *more* trust than shipping logs — auditability is the answer, not marketing.

## Architecture: three layers

### 1. Local agent + open-weights model (customer-owned)
- Runs entirely in the customer's environment. Open-weights base model (Llama/Mistral-class) — customer has complete access and control.
- Same model binary for every deployment: debuggable, updatable, no per-customer snowflakes.
- Resolves the privacy contradiction: a local agent calling a cloud LLM API would leak data anyway. (Fallback options if local inference is too weak: provably-sanitized metadata to cloud LLM, or customer-BYO LLM key.)

### 2. Per-company memory layer (local, private — this is what "evolves")
Adaptation through **context, not weights**. No per-customer fine-tuning (slow, costly, bakes in stale patterns, opaque). Instead, a local database the customer can read:
- Asset inventory + criticality scores
- Historical verdicts ("fired 400×, always false positive")
- Human feedback loop (confirm/overrule escalations)
- Learned environment facts ("backups at 2am — ignore the IO spike")

This is *more* transparent than fine-tuned weights: the customer sees exactly why the system believes what it believes. LoRA adapters remain a later option if a customer truly needs weight-level adaptation.

### 3. Shared brain: curated threat-pattern feed (the network moat)
An attack confirmed at customer A protects B and C — CrowdStrike-style herd immunity. **What travels is the lesson, never the data**: abstracted detection patterns (Sigma-rule-plus-reasoning), stripped of hostnames/IPs/anything identifying.

Flow: local agent confirms incident → extracts anonymized pattern → ships via the existing report channel → **central curation/validation** (unvalidated auto-propagation = one customer's misconfig becomes everyone's false-positive storm) → pushed to every agent's knowledge layer.

Non-negotiables: provably anonymized extraction (open-source that code), opt-in with a clear trade ("share lessons, receive everyone's lessons"), curation step in the middle.

No relevance filtering on distribution — attackers reuse playbooks across industries; carrying an irrelevant pattern costs ~nothing.

## Business model

- Customers own their agents and models; **you own the collective brain** — curation, the pattern feed, and reporting are the subscription.
- Value compounds with every customer (network effect moat).
- Back-channel to vendor: monthly report + attack-possibility notices + anonymized patterns only.
- Pricing: flat / per-asset monthly. "Less than a day of a consultant's time."

## MVP scope (GitHub-first)

1. Log ingestion via wrapped OSS collector
2. Onboarding asset discovery (from log traffic + a few API integrations) with human-confirmed criticality
3. Triage engine: cheap pre-filter + local LLM on ambiguous alerts, scoring against the memory layer
4. Escalation with evidence summary; suppression with logged rationale; audit trail
5. Shadow mode
6. Event-triggered micro-rescans

Defer: shared pattern feed (needs >1 customer), LoRA adaptation, compliance-grade assessment, sales motion.

## Open questions

- Which OSS collection stack to wrap (Wazuh? Vector? Elastic agent?) — pick by license compatibility with open-core and ease of embedding.
- Minimum viable local model: what's the smallest open-weights model that triages acceptably, and what hardware does that demand of a startup customer?
- Pre-filter design: rules? embeddings + similarity to past verdicts? Where's the cheap/ambiguous boundary?
- Anonymization guarantees for pattern extraction — what's "provable" in practice?
- Onboarding friction: how much human criticality-tagging is acceptable before drop-off?

## Competitive landscape (as of mid-2026 — re-verify)

- AI SOC triage (enterprise-focused): Dropzone AI, Radiant Security, Prophet Security, Microsoft Security Copilot — validate the pain, don't serve this segment self-hosted.
- Free OSS SIEM: Wazuh, Security Onion, Elastic — the real alternative; Arbiter's edge is the built-in analyst.
- Attack surface management (Axonius, runZero, Wiz) — deliberately **not** competing; assessment is scoped to just-enough-to-power-triage.
