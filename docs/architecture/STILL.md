# Arbiter architecture — still-diagram edition

These static diagrams contain the same labels as the
[animated walkthrough](../ARCHITECTURE-WALKTHROUGH.md). No motion is required to
understand the system. Follow the linked explanations for the full text equivalent.

## 1. Intake

![Security sources to collectors, validated events, durable queue, priority worker and correlation.](01-intake.svg)

[Read the intake explanation](../ARCHITECTURE-WALKTHROUGH.md#1-intake-preserve-the-evidence).

## 2. Triage

![Guardrails and prefilter decide directly when possible; ambiguous events use local reasoning before a persisted verdict.](02-triage.svg)

[Read the triage explanation](../ARCHITECTURE-WALKTHROUGH.md#2-triage-decide-with-evidence).

## 3. Review and response

![Authenticated UI explains an alert; review and deadlines are separate from explicitly approved typed responses and verified undo.](03-review-response.svg)

[Read the review and response explanation](../ARCHITECTURE-WALKTHROUGH.md#3-review-explain-before-asking-for-action).

## 4. System boundaries

![Optional agent L2 review and policy gate, separate customer/public deployment boundaries, and the planned remote edge target.](04-boundaries.svg)

[Read the boundaries explanation](../ARCHITECTURE-WALKTHROUGH.md#4-boundaries-keep-reasoning-and-authority-separate).
