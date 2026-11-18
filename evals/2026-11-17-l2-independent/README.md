# Independent L2 review: results and limits

**Diagnostic limitation:** 11 of the 13 model suppressions lacked an extracted DNS question. Their label agreement does not establish a justified benign judgment. A stricter evidence-gated follow-up is required; this is not a production-readiness claim.

**Qwen is L1. Only its escalations enter L2. Separate L2 rules decide whether Gemma adds useful work; a shared final guardrail checks L1 and L2 decisions.**

On 192 fresh public alert records, L2 called Gemma 13 times, settled 81 records without the model, and quieted 13 warnings through Gemma. Final attack annotations flagged: 64/64 (100.0%).

## Why the earlier second brain was not earning its cost

The earlier 202-record test sent 97 Qwen escalations through Gemma, cleared none and added 50.51 minutes of L2 work. That route lacked the separate noise-oriented L2 pre-filter and complete shared final exit requested by the owner. Gemma also saw Qwen's opinion and had to provide two overlapping classification fields, which could disagree.

Development checks changed several things together, so they do not prove that anchoring alone caused the old result. A less restrictive blind prompt did produce different decisions, but also quieted attack-annotated root-session and encoded-DNS records. Those failures were retained as development findings, not hidden or counted as new independent accuracy.

## What changed

1. **Separate L2 pre-filter.** Known risk stays flagged without spending a model call. Isolated protocol/login alerts that lack the context needed to settle them also stay flagged without paying Gemma to repeat the same evidence. Exact process history can quiet a case only after at least five explicit human false-alarm corrections and no unresolved risk. Broad history and the model's own earlier answers are insufficient.
2. **Independent model judgment.** Gemma receives the original facts without Qwen's rationale or conclusion text. It returns one classification. The compatibility outlook field is derived instead of asking for a contradictory second decision.
3. **Better evidence.** Older text-wrapped IDS source/destination ports and single-question DNS arrays are preserved. Conflicting endpoints and incompletely represented multi-question DNS records retain review.
4. **Separate L2 safety rules.** Explicit sudo/root session activity, source-classified attacks and encoded-looking DNS payloads stay protected. A normal-looking session closing log does not excuse the earlier privileged operation.
5. **One final safety gate.** L1 model decisions, L1 rule shortcuts, L2 pre-filter decisions and Gemma outputs use the shared suppression veto. Written reasons, fact checks, a successful model challenge and the 0.9 model-suppression threshold remain. Classification grants no device-action rights.

## Public dataset and test design

**AIT Alert Data Set (AIT-ADS), version 1**, by Max Landauer, Florian Skopik and Markus Wurzenberger, AIT Austrian Institute of Technology. [Publisher / DOI 10.5281/zenodo.8263181](https://zenodo.org/records/8263181), **CC BY 4.0**. Cite *Introducing a New Alert Data Set for Multi-Step Attack Analysis* (2024) and *Maintainable Log Datasets for Evaluation of Intrusion Detection Systems* (2023).

This is security-tool reporting from eight simulated company networks, containing routine activity and staged scanning, exploitation, password attacks, privilege changes, remote commands and data theft. We use Wazuh and Suricata-via-Wazuh; unsupported AMiner data is excluded.

The new frozen sample has 192 records: 64 attack annotations and 128 without attack annotations. All 416 previously selected raw records, including the development controls, were excluded before sampling. The seed and publisher-label revision are in input-provenance.json. These are different records from the same eight public scenarios, not independent new organizations or campaigns.

The publisher's per-record event_label supplies scoring after inference. No scoring labels reach either model. A missing attack annotation does not certify harmlessness. Each record starts with empty history; therefore the human-feedback shortcut is covered by regression tests, not exercised as a learned company profile in this dataset. This is classification in shadow mode, not live collection or verified attack blocking.

## Measured decisions

| Outcome | L1 rules + fresh Qwen | After L2 and final checks |
|---|---:|---:|
| Attack annotations flagged | 64/64 (100.0%) | 64/64 (100.0%) |
| Attack annotations quieted | 0 | 0 |
| Records without attack annotations quieted | 43/128 (33.6%) | 56/128 (43.8%) |
| Records without attack annotations still flagged | 85 | 72 |
| Total warnings | 149 | 136 |

Compare the two columns on the same new input to measure L2's added effect. Comparing headline percentages with the older sample is not a controlled estimate of improvement, because the selected records differ.

## Which layer did the work?

- Qwen escalations reaching the L2 stage: **94**.
- L2 decisions made without calling Gemma: **81**.
- Records actually sent to Gemma: **13** (13.8% of L2 inputs).
- Gemma inputs with attack annotations: **0**. Do not credit Gemma for attacks retained by rules before it.
- Warnings quieted by Gemma: **13**.
- Invalid/unavailable L2 outcomes: **0**; each retains its warning.
- Device actions: **0**.

| Independent L2 rule | Records |
|---|---:|
| Missing flow/login context: retain without repeating inference (`L2_CONTEXT_REQUIRED`) | 73 |
| Recorded sudo/root session: retain for review (`L2_PRIVILEGED_SESSION`) | 4 |
| Encoded-looking DNS payload: retain for review (`L2_DNS_PAYLOAD`) | 4 |

A context-required outcome is an unresolved warning retained cheaply, not a false positive successfully removed. Checked fact references do not certify every sentence. The challenge is a second pass by Gemma, not a third independent model.

## Where it failed

No attack-annotated record was quieted in this selected run. That does not establish a production detection rate.

There are still **72 warnings without attack annotations**. Retaining them is not evidence that L2 has solved noise. The next work is useful connection/login context and independent checks of the written explanations, not another blanket pass over the same isolated evidence.

## Processing cost

- L1 rules plus Qwen: 7.90 minutes of measured work across 192 records.
- Complete L2 stage: 6.93 minutes across 94 inputs.
- Actual Gemma reviews: half finished within 30.93s, 95% within 47.65s; 6.93 minutes in total.
- Qwen runs first, then eligible L2 reviews. This does not measure concurrent operation, live queue delay or time to detect a breach.
- Gemma settings remain local, internal thinking off, temperature 0.1, 8,192 context tokens and a 1,536-token generation cap per call. An assessment and separate challenge are retained. New prompts, evidence and routing are frozen in run.json and source hashes. Hidden thinking is not stored.

## Small-code review and next steps

The change reuses the local transport, validators, scheduler and SQLite memory. No runtime package, extra model, service or cache was added. The measurable saving comes from avoiding unhelpful model reviews. A separate small fix drains bounded rejected POST bodies so Windows clients receive authentication/CSRF denials instead of intermittent connection resets; the authorization rules are unchanged.

Next: test full chronological attack stories and richer independent context; inspect wrong quieting and unsupported explanations; repeat on fresh complete scenarios or another public dataset; measure live queue load and restart behavior. Test safe lookalikes and attack lookalikes together. A larger model or a successful reply format is not a substitute for these checks.

The terminal event view preserves both stages and their deciding actor. Original ingestion/audit totals retain first-stage evidence. An installed/portable dashboard build was not replaced. Native containment defaults and executor permissions remain separate and unchanged.

## Reproduce and inspect

```text
python tools/two_brain_eval.py --sample evals/2026-11-17-l2-independent/sample.jsonl --out evals/your-new-run
python tools/report_l2_independent_eval.py evals/your-new-run
```

Frozen sample SHA-256: 3b1e515ec09085a1bca5e9fc6154dee2770f2df87b2597a71198b4a0474dbb1a. run.json identifies model digests, source hashes, runner hash and settings. SHA256SUMS.txt covers the archived files. Complete outcomes and readable final.csv preserve L1, L2 route, model proposal, final decision and actor.

Development controls are separately labelled, reuse older Qwen escalations, and are not included in the new scored totals. See development-notes.md for the diagnostic failures and the boundary of what was tested.
