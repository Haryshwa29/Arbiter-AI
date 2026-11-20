# Arbiter AI: what our public attack-data test taught us

**New two-brain test:** [Qwen L1 → Gemma L2 results](TWO-BRAIN-PUBLIC-EVAL.md)
explain what happened when Gemma could confirm or suppress Qwen's escalations.
This page preserves the earlier single-brain findings and rule improvements.

**We fixed the missed attack-related alerts found in our first sample. Arbiter also became better at quieting routine-looking alerts, but it still asks people to review too many of them. These results come from a small public laboratory dataset, not from protecting a real company during a breach.**

## What did we test with?

We used the **AIT Alert Data Set (AIT-ADS)** from the Austrian Institute of
Technology. Researchers created eight simulated company networks, generated
normal user activity, and carried out staged attacks. Security tools recorded
alerts during those activities. The collection includes website and network
scanning, password cracking, attempts to gain administrator privileges, remote
commands, web shells, data theft and service interruptions. It also contains
alerts caused by normal activity, including logins and software updates.

The full collection has about 2.66 million alerts from Wazuh, Suricata and
AMiner. We used the Wazuh and Suricata formats that Arbiter supports. AMiner was
excluded because Arbiter does not have a reader for it. We checked the supported
data for correct matching to its published labels, but **we did not run the AI
over all 2.6 million alerts**.

Dataset credit: **Max Landauer, Florian Skopik and Markus Wurzenberger**, AIT
Austrian Institute of Technology. [AIT-ADS version 1, DOI
10.5281/zenodo.8263181](https://zenodo.org/records/8263181), shared under **CC BY
4.0**. The authors' papers are *Introducing a New Alert Data Set for Multi-Step
Attack Analysis* (2024) and *Maintainable Log Datasets for Evaluation of Intrusion
Detection Systems* (2023).

## What was Arbiter being asked to do?

Arbiter was sorting existing security alerts into two outcomes:

- **Flag for review:** show a person why this deserves investigation.
- **Keep as an observation:** quiet the alert with a written reason, while
  keeping the record available for later checks.

This measured whether Arbiter chose the appropriate level of attention. It did
not test whether Arbiter blocked an attacker, stopped ransomware, or prevented a
breach. No firewall changes or other protective actions were carried out.

Three parts of Arbiter can make the decision:

| Part | What it does in everyday terms |
|---|---|
| Safety rules, called guardrails | Require review when particular risky signals are recorded. |
| Quick sorting rules, called the prefilter | Handle clear cases without spending time asking the AI. |
| Qwen3.5, the local AI model | Read unclear alerts and explain a proposed decision. |

All model runs used **`qwen3.5:4b`**, running locally on the same desktop.
We did not retrain it or change its instructions between the original and final
runs. Qwen3.5 can be replaced by another compatible local AI model. That model
would need its own evaluation; compatibility does not establish good judgment.

## What went wrong in the first run?

We selected 214 alerts. The dataset marked 86 as attack-related; the other 128
had no attack annotation.

Arbiter flagged 72 of the 86 attack-related alerts, or **83.7%**. It quieted the
other **14**, which was the main failure we investigated. It quieted only five
of the 128 comparison alerts, or **3.9%**, leaving people with many warnings to
review.

**All 14 missed attack annotations were decisions made by Qwen3.5. The
prefilter did not quiet any of them.** However, the surrounding rules also had a
gap: they let these cases reach the model without a rule preventing an
inappropriate dismissal. There were no connection failures or broken AI replies
behind these misses; the problem was the judgment made from the available
evidence.

The 14 misses were website directory scans. An attacker was trying different
website addresses to discover files or weaknesses. The server answered
**404: file not found**. The model repeatedly treated the missing file as a
reason to call the activity harmless.

A failed request can still be part of someone exploring a website for a way in.
It does not establish that the requester is harmless. Equally, one 404 does not
prove that an attack succeeded. The correct response to an alert already
classified by the security tool as attack-related was to keep it for review.

We also found two other problems:

- **Unnecessary mail-login warnings.** All 43 sampled Dovecot login alerts
  without attack annotations were flagged by the model. Some explanations
  treated the word `PLAIN` in the login method as proof that the connection was
  unencrypted, even though the same record said it used TLS encryption.
- **Important details were lost during handoff.** Some Suricata alerts arrived
  inside Wazuh records. Their underlying priority and network addresses were not
  carried through properly. This was a data-handling defect, separate from the
  14 website-scanning misses.

## What did we improve?

1. **Keep source-classified web attack alerts for review.** A 404 cannot, by
   itself, let the AI dismiss them. This does not mean that every missing web
   page is now called an attack.
2. **Quiet a narrow, well-described kind of routine mail login.** The shortcut
   requires several matching conditions, including recorded TLS encryption, a
   non-administrator account, the same private peer/server address, and no
   related warning or previous human correction. It does not quiet every
   successful login.
3. **Protect important account changes and privileged activity.** Supported
   root/sudo and service-account transitions require review instead of being
   dismissed merely because a login succeeded.
4. **Preserve the security tool's evidence.** Underlying priorities and
   network addresses now survive the Wazuh/Suricata handoff. A separate narrow
   rule recognizes a recorded antivirus-definition update starting; it does not
   claim that the update finished or that the computer is free of malware.
5. **Connect repeated website probes.** A new rule can flag many different
   failed paths from the same source, computer and agent within five minutes.
   Controlled examples test this rule. The public-data runs below tested alerts
   individually, so they do not yet measure this rule across a complete attack.

## What happened when we tested again?

We ran the revised system on the same 214 alerts, then on **202 additional
alerts with no overlap in the selected raw records**.

| Measured result | Original run | Same alerts after changes | Additional alerts |
|---|---:|---:|---:|
| Alerts evaluated | 214 | 214 | 202 |
| Attack-related alerts flagged | 72/86 — **83.7%** | 86/86 — **100%** | 74/74 — **100%** |
| Attack-related alerts quieted | **14** | **0** | **0** |
| Alerts without attack annotations quieted | 5/128 — **3.9%** | 47/128 — **36.7%** | 51/128 — **39.8%** |
| Alerts requiring an AI review | 206 | 103 | 100 |

The improvement came largely from **better rules and better information passed
between components**. The model itself stayed the same. On the additional
sample, safety rules flagged 57 attack-related alerts and Qwen flagged the
remaining 17. Quick rules quieted 45 comparison alerts, and Qwen quieted six
more.

The remaining problem is clear: **77 of the 128 comparison alerts still
required attention** in that additional sample. The system became safer on
these selected records, but it remains noisy.

The original run took about 15 minutes; the revised same-alert run took about
eight. Fewer alerts needed AI review. This does not mean the model itself began
producing answers faster.

## What do these numbers prove, and what do they leave open?

They show an improvement on the selected alerts. **They do not establish a
100% real-world detection rate.**

The original alerts helped us develop the fix, so testing them again checks
that the known failure was addressed. The additional records were different,
but came from the same eight simulated company networks. Related or repeated
activity can still occur in both samples.

The dataset's “no attack annotation” label is a comparison label, not an
independent guarantee that every such event was harmless. We deliberately
included different attack categories, so the mix is also different from the
normal daily workload at a company.

Each alert was assessed with empty historical memory. These runs did not test
how well the whole system follows an attack over time, how soon it raises a
useful warning, or whether it keeps up under heavy traffic. The AI's written
explanations also need separate checks for factual accuracy.

## What are we going to test next?

These are the planned next tests, not work already completed:

1. **Test fresh environments.** Set aside complete, previously unused company
   scenarios or another public dataset before changing the rules again. Keep
   those records out of development so we get a stronger independent check.
2. **Test harmless lookalikes.** Include broken website links, authorized
   security scans, legitimate administrator commands and normal logins. Measure
   whether stronger safety rules create too much extra work for a person.
3. **Replay whole attack stories in order.** Let Arbiter connect the clues
   over time. Measure whether it spots the incident, when it first raises a
   useful warning, what it misses, and whether events pile up or get lost.
4. **Repeat and compare the AI tests.** Run the same fixed test several times
   with Qwen3.5 and other compatible local models. Compare missed attack alerts,
   unnecessary warnings, accuracy of explanations, speed and hardware needs.
   A larger model must earn an improvement through testing.
5. **Reduce noise using verified company context.** Investigate the remaining
   network/protocol warnings and test narrowly scoped, human-approved routine
   patterns. Avoid broad shortcuts such as ignoring all TLS errors or all
   successful logins.

After those checks, an updated build can be tried in observation mode before
relying on it to quiet live alerts. The work described here did **not** upgrade
the installed application or prove live attack blocking.

## Where can someone check the evidence?

The [detailed technical report](PUBLIC-DATA-EVAL-2026-11-17.md) contains the
full measurements, deciding-layer breakdown, model identifier and limitations.
The [change and evidence in PR #7](https://github.com/Haryshwa29/Arbiter-AI/pull/7)
include the fixed input samples, every decision, written reasons and instructions
for repeating the evaluation. The code checks passed **459 tests, with two
skipped**; those checks support software correctness, not a guarantee of security
performance.
