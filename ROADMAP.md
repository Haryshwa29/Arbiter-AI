# Arbiter AI — Development Roadmap

This roadmap defines development order.

It intentionally prevents future ideas from disrupting the current MVP.

---

# PHASE 1 — ARBITER MVP

STATUS: CURRENT

Primary objective:

> Build a reliable local-first intelligent security triage system.

Core capabilities:

* security event ingestion
* event normalization
* deterministic classification
* severity evaluation
* asset-aware reasoning
* baseline/rule evaluation
* AI analysis for ambiguous cases
* non-suppressible guardrails
* alert generation
* dashboard visibility
* evaluation framework

Success criteria:

Arbiter can receive representative security events, identify important activity reliably, avoid suppressing protected/high-risk detections, use local AI when useful, and present actionable output.

---

# PHASE 1.5 — PORTABLE ARBITER

STATUS: NEXT IMMEDIATE TARGET

Objective:

> Make Arbiter easy to carry and launch in authorized demonstrations and lab environments.

Target experience:

```
Portable Drive
     ↓
  Launch
     ↓
Environment Check
     ↓
Start Dependencies
     ↓
 Start Arbiter
     ↓
  Dashboard
```

Requirements:

* portable directory structure
* environment validation
* dependency detection
* configuration handling
* model availability detection
* startup script
* shutdown script
* logging
* graceful failure
* documentation

Possible launchers:

```
start-arbiter.ps1
start-arbiter.sh
```

Do not require perfect universal portability initially.

First target the environment used for actual demonstrations.

Expand platform support after the portable MVP works.

Success criteria:

> Arbiter can be moved to a supported authorized machine/lab and launched with minimal manual setup.

---

# PHASE 2 — EVENT COLLECTION

Objective:

Reduce dependence on manually supplied test events.

Possible collectors/adapters:

* Windows Event Logs
* Sysmon
* Linux authentication logs
* system logs
* SSH activity
* network/security telemetry

Architecture should favor adapters:

```
Source
  ↓
Collector
  ↓
Normalized Arbiter Event
  ↓
Existing Detection Pipeline
```

Do not couple core reasoning directly to individual log formats.

---

# PHASE 3 — ASSET & RISK CONTEXT

Objective:

Allow Arbiter to reason about the importance of the affected system.

Conceptual relationship:

```
Asset Value
    +
Vulnerability
    +
Threat / Activity
    +
Potential Impact
    ↓
Risk
```

Possible capabilities:

* asset inventory
* criticality
* exposed services
* vulnerabilities
* attack surface
* potential business impact

Output should explain:

* what is vulnerable
* what could exploit it
* potential consequences
* priority

---

# PHASE 4 — INVESTIGATION ASSISTANCE

Objective:

Move beyond individual alert classification.

Potential capabilities:

* correlate related events
* construct timelines
* identify affected users/assets
* explain probable attack paths
* recommend investigation steps
* retain investigation context

This moves Arbiter toward functioning as a genuine defensive assistant.

---

# PHASE 5 — CONTROLLED RESPONSE

Objective:

Introduce carefully constrained defensive actions.

Begin with low-risk operations.

Potential progression:

L1:

* recommendation only
* gather additional evidence
* create investigation package

L2:

* reversible defensive action with approval

L3:

* policy-authorized automation

Every action requires:

* logging
* reason
* affected asset
* rollback where possible
* authorization policy
* validation

No unrestricted autonomous remediation.

---

# PHASE 6 — REDAI

Only begin after Arbiter reaches a stable milestone.

Objective:

Create an authorized adversarial validation agent.

RedAI should:

* identify weaknesses
* perform controlled tests
* validate security controls
* generate reproducible findings

RedAI must operate only within explicitly authorized scope.

RedAI remains logically separate from Arbiter.

---

# PHASE 7 — ENGINEERING / HEALING AI

Objective:

Turn validated findings into controlled remediation.

Potential workflow:

```
Finding
  ↓
Root Cause
  ↓
Proposed Repair
  ↓
Risk Assessment
  ↓
Approval
  ↓
Apply
  ↓
Validate
  ↓
Rollback if necessary
```

Initial capabilities should emphasize recommendations.

Autonomous changes come much later.

---

# PHASE 8 — CLOSED-LOOP SECURITY SYSTEM

Long-term research objective.

Concept:

```
ARBITER
Detect
   ↓
REDAI
Validate weakness
   ↓
ENGINEERING AI
Repair
   ↓
REDAI
Retest
   ↓
ARBITER
Monitor
```

This is NOT an infinite loop.

Every cycle has:

* explicit scope
* maximum iterations
* resource budget
* stop conditions
* success criteria
* audit trail
* authorization boundaries

---

# CROSS-PLATFORM ROADMAP

Do not attempt every platform simultaneously.

Preferred progression:

```
Current development environment
         ↓
Portable Windows/lab deployment
         ↓
      Linux
         ↓
Additional endpoint/server environments
         ↓
Broader infrastructure integrations
```

Keep core reasoning portable.

Use platform-specific adapters where necessary.

---

# MODEL ROADMAP

Arbiter must remain model-agnostic.

Continue evaluating models according to:

* recall
* precision
* false negatives
* false positives
* latency
* VRAM/RAM
* reliability
* structured-output quality

Do NOT replace the current model simply because a newer model appears.

A replacement should demonstrate measurable improvement relevant to Arbiter.

---

# PRODUCT DIRECTION

Near term:

```
Working cybersecurity project
         ↓
Portable demonstration
         ↓
Real lab testing
         ↓
Feedback
```

Medium term:

```
Defensive security agent
         ↓
Real telemetry
         ↓
Investigation
         ↓
Controlled response
```

Long term:

```
Arbiter AI
   +
RedAI
   +
Engineering AI
   ↓
Bounded Autonomous
Security System
```

---

# CURRENT DEVELOPMENT ORDER

When determining what to work on next, use this priority:

1. Fix blockers in existing Arbiter MVP.
2. Preserve/expand tests.
3. Make Arbiter portable.
4. Feed real security events into Arbiter.
5. Improve asset/risk awareness.
6. Improve investigation capability.
7. Introduce controlled response.
8. Build RedAI.
9. Build Engineering AI.
10. Research closed-loop autonomy.

Do not skip ahead because later phases appear more interesting.

---

# STOP CONDITION

For every phase define:

```
MUST HAVE
NICE TO HAVE
FUTURE
```

When MUST HAVE requirements work reliably:

**SHIP THE PHASE.**

Nice-to-have features move to the backlog.

A working system deployed today is more valuable to this project than a theoretically perfect system indefinitely under development.
