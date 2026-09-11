# Arbiter AI — Master Project Context

> This document is the primary context file for AI coding agents working on Arbiter AI.
>
> Before modifying the project, read this document together with `ROADMAP.md`, `DECISIONS.md`, `README.md`, and the existing source code.
>
> **Existing working code is authoritative. Do not rewrite functioning architecture simply because another implementation appears cleaner.**

---

## 1. What Is Arbiter AI?

Arbiter AI is a privacy-first, local-first cybersecurity agent intended to provide intelligent security monitoring, alert triage, investigation assistance, and eventually autonomous defensive response.

The original problem is simple:

Large organizations can afford enterprise security platforms and teams of analysts who understand their output.

Smaller organizations may increasingly be able to afford security products, but often cannot afford the security expertise required to continuously interpret alerts, investigate them, prioritize them, and respond appropriately.

Arbiter AI attempts to place part of that expertise directly alongside the protected system.

The goal is NOT to create another generic SIEM dashboard.

The long-term goal is an intelligent defensive security agent capable of understanding what is happening on a system/network, identifying what matters, explaining why it matters, and eventually assisting with or performing carefully controlled remediation.

---

# 2. Core Philosophy

Arbiter follows several principles.

### Local First

Security telemetry should remain on the customer's infrastructure whenever possible.

Raw security events should not need to leave the protected environment simply to receive intelligent analysis.

Local models are therefore a first-class component of the architecture.

### Deterministic Before Generative

An LLM should not decide everything.

Events that can confidently be classified through deterministic logic should be handled without invoking the model.

Examples include:

* severity thresholds
* known detection rules
* protected/critical assets
* known malicious behavior
* baseline deviations
* non-suppressible security conditions

The AI model primarily assists with ambiguous cases and contextual reasoning.

### AI Is Not the Security Boundary

LLM output must never be treated as unquestionable truth.

Guardrails, deterministic controls, validation, and explicit safety boundaries remain outside the model.

### Model Agnostic

Arbiter should not depend permanently on one model.

The reasoning/model layer should be replaceable so deployments can select models based on:

* available hardware
* latency
* accuracy
* organizational policy
* privacy requirements
* customer preference

### Privacy by Architecture

The preferred architecture processes security events locally.

Only information explicitly permitted by the deployment should leave the protected environment.

---

# 3. Current MVP

The CURRENT priority is Arbiter AI itself.

Do not expand development into RedAI or autonomous remediation until the Arbiter MVP is stable.

The current system focuses on:

1. receiving security events
2. normalizing/understanding those events
3. deterministic security evaluation
4. identifying events requiring additional reasoning
5. local-model analysis
6. guardrail enforcement
7. alert prioritization
8. presenting useful information to the operator
9. measuring the system through repeatable evaluations

Arbiter should behave more like a small intelligent security analyst than a chatbot attached to logs.

---

# 4. Current Detection Philosophy

The basic decision pipeline is:

Security Event
↓
Normalization
↓
Deterministic Evaluation
↓
Known High-Risk Condition?
├── YES → Alert / Escalate
└── NO
↓
Can deterministic logic classify confidently?
├── YES → Process according to policy
└── NO
↓
Local AI Analysis
↓
Guardrail Validation
↓
Final Classification
↓
Dashboard / Alert / Investigation

The model is therefore not invoked unnecessarily.

This provides:

* lower latency
* reduced compute requirements
* greater predictability
* easier debugging
* stronger security guarantees

---

# 5. Guardrail Principle

Certain events must NEVER disappear merely because the model believes they are harmless.

High-risk deterministic conditions must be capable of overriding AI recommendations.

The model can provide context.

The model cannot bypass core security policy.

Examples of conditions that may require deterministic protection include:

* critical severity detections
* protected assets
* privilege escalation
* known malicious indicators
* suspicious authentication behavior
* destructive activity
* security control tampering

Exact implementation should follow the existing codebase rather than assumptions made from this document.

---

# 6. Evaluation

Arbiter development must be measurable.

Evaluation should consider at minimum:

* recall
* precision
* accuracy
* false-positive behavior
* false-negative behavior
* latency
* guardrail violations
* adversarial cases

Previous evaluation work has included realistic cases, benign cases, stress cases, adversarial cases, evaluation cases, model-gauntlet cases, and red-team cases.

The evaluation dataset has grown to approximately:

* 88 distinct event types
* 296 labeled cases

Previous local-model testing included Qwen and Gemma-family models.

One previous comparison produced approximately:

Qwen 3.5 4B:

* recall: 100%
* precision: 92%
* accuracy: 95%
* latency: ~4.35 seconds

Gemma 4 12B:

* recall: 100%
* precision: 80%
* accuracy: 86%
* latency: ~7.10 seconds

These results represent a particular evaluation state and SHOULD NOT be treated as permanent benchmarks.

The evaluation pipeline and current repository results are authoritative.

---

# 7. Local AI Environment

Development has been performed with locally hosted models.

The broader development environment has included:

* Ollama
* Open WebUI
* Qwen-family models
* Gemma-family models
* NVIDIA GPUs
* Proxmox-based lab infrastructure

Arbiter should avoid unnecessary dependency on proprietary cloud inference.

Cloud inference may eventually be supported as an OPTIONAL deployment mode.

---

# 8. Dashboard Philosophy

The dashboard exists to help a human understand security state.

It should prioritize:

* important alerts
* why something was classified as dangerous
* affected system/asset
* confidence/context
* relevant evidence
* recommended next actions

Avoid turning the interface into a wall of raw telemetry.

Arbiter should reduce analyst workload rather than reproduce the information overload common in security platforms.

---

# 9. Portability — Current Major Objective

A major immediate objective is making Arbiter portable.

Desired demonstration/lab experience:

1. Place Arbiter on portable storage.
2. Connect it to an authorized machine/lab environment.
3. Launch Arbiter with minimal configuration.
4. Detect the environment.
5. Start required services/components.
6. Begin monitoring/analysis.
7. Present the Arbiter interface.
8. Stop cleanly without leaving unnecessary artifacts.

The target experience is conceptually:

```
plug in → launch → Arbiter runs
```

This is particularly important for:

* demonstrations
* interviews
* labs
* cybersecurity events
* testing environments
* development machines

Portability must NOT weaken security boundaries or silently grant Arbiter privileges it should not possess.

---

# 10. Cross-Platform Direction

Arbiter should ultimately avoid being locked to one ecosystem.

Long-term targets may include:

* Windows
* Linux
* cloud workloads
* servers
* endpoint environments
* lab networks

Platform-specific collectors/adapters may be necessary.

The core analysis architecture should remain as platform-independent as reasonably possible.

---

# 11. What Arbiter Is NOT

Arbiter is not intended to become:

* a generic chatbot
* an LLM wrapper
* another log viewer
* a cloud-only SIEM clone
* an uncontrolled autonomous hacking tool
* an agent allowed to modify systems without policy boundaries

Every feature should contribute to the security-agent objective.

---

# 12. Long-Term Vision

Arbiter eventually becomes one component of a larger autonomous security system.

Three conceptual agents exist.

## Arbiter AI — Defensive / Blue Team

Responsibilities:

* monitoring
* detection
* triage
* investigation
* prioritization
* defensive reasoning
* security-state awareness

## RedAI — Adversarial / Red Team

Responsibilities:

* authorized adversarial testing
* attack simulation
* identifying weaknesses
* stress testing
* validating defensive controls

RedAI is NOT the current development priority.

## Engineering / Healing AI

Responsibilities:

* remediation planning
* configuration hardening
* patch recommendations
* vulnerability mitigation
* controlled repair
* validation

The inspiration is analogous to self-healing systems.

A weakness is discovered, analyzed, repaired, and validated.

---

# 13. Long-Term Interaction

Conceptually:

```
Environment
    ↓
Arbiter AI
Observe + Detect
    ↓
RedAI
Authorized Stress / Validation
    ↓
Engineering AI
Repair + Harden
    ↓
Validation
    ↓
Human / Policy Approval
    ↓
Deployment
```

These agents should eventually cooperate but remain logically separated.

This separation is intentional.

---

# 14. Avoid Infinite Autonomous Loops

The system MUST NOT evolve into an uncontrolled:

```
attack
  ↓
repair
  ↓
attack
  ↓
repair
  ↓
forever
```

Testing needs:

* defined scope
* explicit authorization
* success criteria
* resource limits
* maximum iterations
* rollback capability
* audit logs
* human intervention points

Autonomy must remain bounded.

---

# 15. Engineering Rule: Ship at 90%

This project has a deliberate anti-perfectionism rule.

When an agreed milestone meets its success criteria and is approximately 90% production/demo ready:

**STOP OPTIMIZING IT.**

Test it.

Document known limitations.

Ship/deploy the milestone.

Collect evidence from actual use.

Then determine whether additional work is justified.

Do NOT spend weeks pursuing marginal improvements from ~90% to ~99% while delaying deployment.

When tempted to replace working infrastructure because "we can make it better," first ask:

> Does the current implementation prevent the milestone from succeeding?

If NO:

Do not rewrite it.

Move forward.

---

# 16. Instructions for Coding Agents

Before making significant changes:

1. Read this file.
2. Read `ROADMAP.md`.
3. Read `DECISIONS.md`.
4. Inspect the repository.
5. Inspect tests.
6. Understand the current implementation.
7. Preserve functioning behavior.

Never assume this document perfectly describes current code.

**CODE + TESTS > CONTEXT DOCUMENT**

If documentation and implementation disagree, investigate before modifying either.

Prefer incremental changes.

Do not perform large architectural rewrites without explaining:

* the problem
* why current architecture causes it
* proposed change
* affected components
* migration risk

Never introduce dependencies merely because they are fashionable or architecturally interesting.

---

# 17. Current Priority

The current development priority is:

**Make the existing Arbiter AI MVP reliable and portable enough for real demonstrations and cybersecurity lab work.**

NOT:

* building RedAI
* building autonomous patching
* building the entire self-healing architecture
* enterprise scaling
* perfecting every model
* rewriting working components

Finish Arbiter first.

Then move forward.
