# Arbiter AI — Architecture & Product Decisions

This file records decisions that should not be repeatedly reopened without new evidence.

AI coding agents must read this file before proposing architectural changes.

---

## D001 — Arbiter Is Local First

STATUS: ACCEPTED

Security telemetry should remain local whenever reasonably possible.

Local inference is preferred.

Cloud inference may eventually exist as an optional deployment choice.

REASON:

Privacy, security, independence, cost control, and suitability for security-sensitive environments.

---

## D002 — Deterministic Logic Comes Before LLM Reasoning

STATUS: ACCEPTED

Arbiter should first evaluate events using deterministic mechanisms.

The LLM primarily handles cases requiring additional context or ambiguity resolution.

REASON:

Improves:

* reliability
* latency
* compute efficiency
* explainability
* testing
* security

---

## D003 — The LLM Cannot Override Critical Guardrails

STATUS: ACCEPTED

Certain high-risk conditions must remain non-suppressible.

AI recommendations cannot bypass deterministic security policy.

REASON:

LLMs are probabilistic and susceptible to incorrect classification and adversarial influence.

---

## D004 — Arbiter Must Be Model Agnostic

STATUS: ACCEPTED

The architecture should allow the reasoning model to be replaced.

No fundamental Arbiter capability should unnecessarily depend on a single model vendor/family.

REASON:

Different deployments have different hardware, privacy, latency, and policy requirements.

---

## D005 — Local Models Are a First-Class Deployment Option

STATUS: ACCEPTED

Arbiter is explicitly designed to operate with local inference.

Ollama/local-model infrastructure may be used where appropriate.

---

## D006 — Model Selection Must Be Evidence Driven

STATUS: ACCEPTED

A newer/larger model is not automatically better.

Evaluate using measurable Arbiter performance.

Important measurements include:

* recall
* precision
* accuracy
* false negatives
* false positives
* latency
* hardware requirements
* structured-output reliability

---

## D007 — Arbiter Is Not Just a SIEM

STATUS: ACCEPTED

Arbiter may consume security telemetry similar to SIEM systems, but the product objective is intelligent defensive assistance.

The goal is not to reproduce Splunk.

---

## D008 — Do Not Flood the Operator With Raw Events

STATUS: ACCEPTED

Arbiter should prioritize useful security information.

Raw telemetry may remain accessible, but the primary experience should emphasize:

* important activity
* reasoning
* evidence
* affected assets
* recommended action

---

## D009 — Cross-Platform Is a Long-Term Requirement

STATUS: ACCEPTED

Arbiter should not permanently depend on the Windows ecosystem or another single vendor environment.

Implementation may initially target specific platforms.

Core architecture should avoid unnecessary platform coupling.

---

## D010 — Platform Collection Should Use Adapters

STATUS: ACCEPTED

Different telemetry sources should feed a normalized Arbiter event representation.

Concept:

```
Windows Event Logs ─┐
Sysmon ─────────────┤
Linux Logs ─────────┤
Other Sources ──────┘
         ↓
    Collectors
         ↓
    Normalization
         ↓
   Arbiter Pipeline
```

This keeps detection/reasoning separated from collection.

---

## D011 — Arbiter Must Become Portable

STATUS: ACCEPTED

A current development objective is making Arbiter portable enough for demonstrations and authorized lab work.

Target experience:

```
plug in
   ↓
launch
   ↓
Arbiter
```

Initial portability does NOT need to support every possible computer.

First make it work reliably in known demonstration environments.

---

## D012 — RedAI Is a Separate Agent

STATUS: ACCEPTED

The adversarial/red-team component will not simply be merged into Arbiter's defensive reasoning process.

Logical separation improves:

* safety
* testing
* permissions
* auditability
* architecture clarity

---

## D013 — Healing / Engineering AI Is Also Separate

STATUS: ACCEPTED

System modification and remediation carries substantially different risk from detection.

Therefore remediation should have its own permissions, policies, validation, and architecture.

---

## D014 — Closed-Loop Autonomy Must Be Bounded

STATUS: ACCEPTED

Future RedAI → Arbiter → Engineering interactions cannot run indefinitely.

Required controls include:

* authorization
* scope
* iteration limits
* resource limits
* success criteria
* stop conditions
* audit trail
* rollback strategy

---

## D015 — Human Control Remains Part of High-Risk Actions

STATUS: ACCEPTED

High-impact remediation should initially require human approval.

Autonomy may increase only where actions become sufficiently understood, tested, reversible, and policy constrained.

---

## D016 — Existing Working Code Has Priority Over Architectural Taste

STATUS: ACCEPTED

Do not rewrite working components simply because another design seems cleaner.

Before replacing something, demonstrate a concrete limitation affecting the current milestone.

---

## D017 — Tests and Evaluations Are Part of the Product

STATUS: ACCEPTED

Evaluation is not an optional final step.

Detection behavior and AI behavior must remain measurable as development continues.

CI/CD should protect important behavior.

---

## D018 — Avoid Scope Creep

STATUS: ACCEPTED

Interesting future capabilities belong in the roadmap/backlog unless they directly unblock the current milestone.

Current focus:

**Arbiter MVP + portability.**

Not currently:

* complete RedAI
* autonomous patching
* enterprise-scale orchestration
* universal endpoint support
* perfect model optimization

---

## D019 — 90% Rule

STATUS: ACCEPTED

When a milestone satisfies its agreed requirements and is approximately 90% ready for actual use:

STOP BUILDING.

Deploy/test it.

Record limitations.

Collect feedback.

Do not delay deployment for marginal improvements unless they materially affect:

* security
* reliability
* core functionality
* demonstration readiness

---

# Decision Proposal Format

Future decisions should be recorded as:

```
## DXXX — Decision Name

STATUS:
PROPOSED / ACCEPTED / REJECTED / SUPERSEDED

CONTEXT:
Why was this question raised?

DECISION:
What are we doing?

REASON:
Why?

CONSEQUENCES:
What does this change?

DATE:
YYYY-MM-DD
```

This allows future AI agents and human contributors to understand not only WHAT was chosen but WHY.

---

# Instructions to AI Agents

Do not silently reverse an ACCEPTED decision.

If new technical evidence suggests a decision should change:

1. identify the existing decision
2. explain the new evidence
3. propose the alternative
4. describe migration impact
5. wait for approval when the change is substantial

Then update this file.

The objective is to prevent every new AI coding session from redesigning Arbiter from scratch.
