# Arbiter AI: 26,002-record public-data checkpoint

**This is a user-requested partial checkpoint, not the completed 2.6-million-record evaluation.**

**Arbiter kept 42.48% of the records visible for review (11,045/26,002). Its policy is to raise a warning when activity looks suspicious and the available evidence does not justify suppressing it.**

Of the retained warnings, 10,851 (98.24%) were explicitly retained by L2's context-required rule after Qwen raised a concern. The other deciding layers are broken down below. These are requests for investigation; independent evidence is needed to establish whether an attack occurred.

The run stopped after 26,002 saved decisions from Fox (26,002 records). Input was sequential original file order, one scenario at a time, with empty history for each record. It was not randomized or balanced. No live device actions were enabled.

**Time to this checkpoint: 14 hours, 31 minutes, 28 seconds.** The first record attempt started at 2026-11-18 07:44:43 UTC; the stop was confirmed at 2026-11-18 22:16:10 UTC. This elapsed time includes model work and ordinary pauses/overhead during the run, rather than adding up inference durations alone.

## Our safety policy

> raising alerts which look suspicious without proper context is better than suppressing them and getting true negative

**Terminology correction:** suppressing a real attack is a false negative. A true negative is correctly quieting a harmless record and is desirable. The intended policy is: keep suspicious alerts visible when the available evidence does not justify suppression.

That policy is implemented through uncertain/error escalation, L2 context-required routing, known-risk vetoes, suppression-confidence checks and the shared final guardrail. It is a design requirement, not a guarantee that model reasoning never fails. Conservative policy does not turn a benchmark false positive into a successful detection.

## Dataset and raw data

AIT Alert Data Set (AIT-ADS) v1, Max Landauer, Florian Skopik and Markus Wurzenberger, AIT Austrian Institute of Technology. [Publisher / DOI 10.5281/zenodo.8263181](https://zenodo.org/records/8263181), [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Cite *Introducing a New Alert Data Set for Multi-Step Attack Analysis* (2024) and *Maintainable Log Datasets for Evaluation of Intrusion Detection Systems* (2023).

The whole archive has 2,655,821 records from eight simulated networks. The adapter supports 2,600,263 Wazuh/Suricata records and excludes 55,558 AMiner records. This checkpoint covers only its initial prefix.

The simulated networks contain ordinary activity alongside staged attacks, including scanning, password attacks, privilege escalation, remote commands, web shells, data theft and service disruption. A security-tool alert is a warning about an observation; it is not automatically a confirmed attack. The mix in this checkpoint is reported below rather than assumed to match the whole archive.

`checkpoint-data.zip` contains verbatim publisher JSONL records, a source-line/label index, all normalized inputs and L1/L2 outcomes, readable CSV, SQLite snapshot, model/source/input provenance and checksums. Per-line hashes verify the original raw bytes. Scoring labels remained outside the model inputs.

## Measured outcomes

| Outcome | L1 rules + Qwen | After L2 + final checks |
|---|---:|---:|
| Attack-labelled records examined | 0 | 0 |
| Attack-labelled records kept flagged | 0 | 0 |
| Attack-labelled records quieted | 0 | 0 |
| Unannotated records quieted | 14,918 | 14,957 |
| Unannotated records still flagged | 11,084 | 11,045 |
| Agreement with publisher labels | 57.37% | 57.52% |

**No attack-labelled records were processed. Attack-detection recall and missed-attack performance are unmeasured; do not publish the agreement percentage as overall attack accuracy.**

The 11,045 retained unannotated records count as false positives under this label-based scoring convention (42.48% of unannotated records). Missing attack annotations do not independently certify harmlessness. The conservative policy explains why warnings remain visible; they still create review work and retain their benchmark scores.

## What worked, and what remains weak

- Qwen reviews: 11,310; L2 inputs: 10,907; L2 decisions without Gemma: 10,864.
- Actual Gemma reviews with replies: 43; additional warnings quieted by Gemma: 39.
- L2 reduced unannotated warnings by 39 out of 11,084 (0.35%). This is the reduction in label-defined unwanted warnings, not an attack-detection score.
- Qwen errors: 0; L2 errors: 0. Successful completion/format validation is not a semantic-correctness score.
- Both model stages and final vetoes are preserved. Alerts lacking enough context remain visible; no containment permission was granted.
- Many retained warnings still lack useful independent flow/login context. This checkpoint does not establish strong noise reduction by L2.
- Routing limitation: the current L2 prefilter retained context-poor alerts without letting Gemma investigate. This saved model calls but did not follow the requested suppress-or-pass-to-Gemma handoff. The separate upgrade corrects that routing; its prefilter must independently justify routine suppressions, and unresolved cases go to Gemma before the final guardrail. These corrected decisions are not part of this checkpoint.
- The separate context-upgrade development probe found unsupported Gemma suppressions accepted by its critic. Those different synthetic checks are preserved separately and are not mixed into these scores. The upgrade was not installed into this frozen run.

### Where the unwanted alerts came from

The final deciding-layer table below separates who left each warning visible. Qwen can raise a concern, then the L2 prefilter can retain it because supporting context is absent; in that case Gemma never sees it. This is conservative routing, not evidence that Gemma reviewed and agreed with every warning. It also means the current L2 policy often cannot reduce noise on isolated records. More context must support a specific ordinary explanation, rather than simply instructing the model to suppress more.

| L2 rule | Records | Share of L2 inputs |
|---|---:|---:|
| L2_CONTEXT_REQUIRED | 10,851 | 99.49% |
| L2_PRIVILEGED_SESSION | 3 | 0.03% |
| L2_DNS_CONTEXT_MISSING | 10 | 0.09% |

`L2_CONTEXT_REQUIRED` means: keep the warning visible because this isolated record does not explain why the activity is ordinary. It avoids a model call that would only repeat the same incomplete evidence. A guardrail can block an unsupported quiet decision, but passing a check does not prove the model understood the event correctly.

| Most frequent retained, unannotated warning types | Records |
|---|---:|
| IDS event. | 5,175 |
| Suricata: Alert - SURICATA TLS invalid handshake message | 2,642 |
| Suricata: Alert - SURICATA TLS invalid record/traffic | 2,642 |
| PAM: User login failed. | 166 |
| Dovecot Invalid User Login Attempt. | 156 |
| Multiple IDS alerts for same id. | 93 |
| Multiple IDS events from same source ip. | 37 |
| Suricata: Alert - SURICATA HTTP unable to match response to request | 27 |

| Final deciding layer | Unannotated quieted | Unannotated flagged | Attack quieted | Attack flagged |
|---|---:|---:|---:|---:|
| L1 quick rules | 14,515 | 169 | 0 | 0 |
| Qwen, L1 | 403 | 0 | 0 | 0 |
| L2 quick rules | 0 | 10,864 | 0 | 0 |
| L1 safety rules | 0 | 8 | 0 | 0 |
| Gemma, L2 | 39 | 4 | 0 | 0 |

Examples below identify actual scored records, not a separately scored explanation-quality study.

- L1 quick rules, record 1 (fox:1), suppress: Routine FreshClam signature-database update observation: the source decoder, update rule and recorded update-start message agree; no correlated detection. An update start does not prove completion or absence of malware.
- Qwen, L1, record 20 (fox:20), suppress: This alert is a false positive generated by an overly broad rule matching benign package management traffic; the signature history confirms this is the first occurrence, but the internal classification overrides the generic severity score.
- L2 quick rules, record 133 (fox:133), escalate: This isolated protocol/login observation lacks independent flow or login context needed to justify quieting it; retain the warning without repeating the same evidence through Gemma.
- L1 safety rules, record 273 (fox:273), escalate: Security guardrail [NON_SUPPRESSIBLE_PRIVILEGED_SESSION]: a recorded root sudo operation or privileged/service-account identity transition requires review; authentication success alone is not a benign explanation.
- Gemma, L2, record 775 (fox:775), suppress: The log records a single POST request to a login page resulting in a 302 redirect, which is standard behavior for a failed or redirected login attempt without evidence of a brute force or successful compromise.

### What checking Gemma's explanations revealed

Gemma's challenge accepted all 43 completed model reviews with no objections.
That is a software/critic outcome, not an independent correctness score. Reading
the saved explanations exposed limitations in both directions:

- **fox:2244, suppressed:** Gemma described a redirect to the administrator
  dashboard. The source log contains a 302 response and an administrator target
  inside the referring page's `redirect_to` parameter. It does not record the
  response's actual destination or a completed authenticated session. The
  explanation states more than the saved evidence establishes.
- **fox:22015, retained:** Gemma interpreted a request mentioning a payroll
  spreadsheet as a targeted data-exfiltration attempt. The record shows a
  file-sharing API request and a 500 server error. The sensitive filename can
  justify investigation, but it does not establish unauthorized access or data
  transfer. Retaining uncertainty fits the policy; the explanation should label
  the attack interpretation as a possibility rather than treating the filename
  as sufficient attribution.
- **fox:25772, suppressed:** Gemma used a generic 500 error and absence of
  confirmed exploit success to justify quieting the warning. A server error does
  not establish an ordinary root cause or rule out an attack attempt. The saved
  challenge accepted this reasoning without objection, and no final veto fired.

These are illustrative qualitative findings, not an independently adjudicated
semantic error rate. They do not change the saved decisions or publisher-label
scores. None of these records has an attack annotation, so they cannot be called
proven missed attacks. Equally, the 39 label-agreeing Gemma suppressions must not
be described as 39 independently verified safe decisions. The next evaluation
needs ordinary/malicious HTTP lookalikes and independent review of the reasons,
alongside the routing fix and richer evidence.

## Per-record latency: what was actually timed

Mean means average time. Median is the middle record. The 95th percentile is the time within which 95% of records on that measured path finished. These are classification times, not proof that a protective action occurred.

| Measured path | Records | Mean | Median | 95th percentile |
|---|---:|---:|---:|---:|
| All records, including fast rules | 26,002 | 2.0088s | 0.0012s | 6.3292s |
| L1 rules without Qwen | 14,692 | 0.0011s | 0.0010s | 0.0014s |
| Qwen stage on model-reviewed records | 11,310 | 4.4949s | 3.8582s | 6.8229s |
| Gemma assessment + challenge | 43 | 32.0216s | 32.0861s | 39.4047s |
| Complete classification on Gemma-reviewed records | 43 | 36.5124s | 36.8681s | 45.7386s |

**L2 is the expensive path:** if every incoming record required the same average complete Gemma path seen here (36.51s), a sequential worker would classify roughly 1.64 records/minute before additional queue/journal overhead. This is a mix-based estimate, not another measured run or a maximum hardware limit. The overall replay rate must not be advertised as the rate for two full model reviews on every record.

Local hardware snapshot: 13th Gen Intel(R) Core(TM) i7-13700F; 31.8 GiB RAM; GPU, total VRAM in MiB, driver: NVIDIA GeForce RTX 4060 Ti, 16380, 617.42. Models: Qwen3.5:4b (L1), Gemma4:12b (L2), with exact installed digests and requested options in run.json. This is not matched hardware against an enterprise cluster.

Observed checkpoint wall-clock rate: **29.84 saved records/minute** over 14.52 hours from the first journalled attempt to the confirmed stop. The earlier rough 50/minute estimate is not substituted for the final measured rate.

This is one sequential replay worker. On a Gemma case, the next record waits for both its assessment and challenge. The normal source agent has separate L1/L2 queues/workers, but that concurrent mode was not measured here. Timings exclude live collector/network delay and pre-processing queue residence; they are not ingestion-to-containment times. This historical replay executes no response actions. Other desktop/development activity shared the machine.

## Reported corporate workload: daily intake converted to minutes

The supplied 1-3 alerts/minute comparison comes from daily incoming volume divided by 1,440 minutes. That arithmetic describes average demand over a full day. It does not measure maximum processing capacity or how long one investigation takes. These are different surveys and years, not a universal ideal.

| Survey and population | Reported incoming alerts/day | Average incoming alerts/minute |
|---|---:|---:|
| [Prophet Security 2025 survey, all organizations](https://www.prophetsecurity.ai/blog/6-key-takeaways-from-the-ai-in-soc-survey-report) | 960 | 0.67 |
| [Prophet Security 2025 survey, enterprises with 20,000+ employees](https://www.prophetsecurity.ai/blog/6-key-takeaways-from-the-ai-in-soc-survey-report) | 3,181 | 2.21 |
| [Vectra AI 2023 survey of 2,000 SecOps analysts](https://www.vectra.ai/about/news/research-reveals-significant-disconnect-between-security-operations-teams-and-the-effectiveness-of-threat-detection-tools-in-preventing-cyber-attacks) | 4,484 | 3.11 |

Arbiter saved **29.84 records/minute** on this replay. That exceeds these reported average arrival rates for the tested mix, suggesting processing headroom if arrivals and case costs were similar. This is an inference about workload scale, not a demonstrated deployment capacity: real bursts, heavier attack cases, persistent context, device actions and shared queues were not tested.

The 4,484/day figure is also repeated in the supplied D3 article; the primary attribution above is Vectra's 2023 survey. The 28-tool figure belongs to Prophet's large-enterprise survey and is not attached to the older survey. The supplied 960-11,000/day range is not represented here as a verified original SANS result because its original survey table was not established.

## Corporate latency reference points: context, not a matched speed benchmark

No commercial system was run on these same records, hardware, context, quality targets and forced one-record workflow. A claim that enterprise products would be slower one-by-one is therefore untested. The verified daily-intake conversions above are not used as a per-alert latency baseline.

| Published reference | Number and unit | Why it is not our same measurement |
|---|---|---|
| [Published automated per-alert triage claim](https://d3security.com/siem-triage-automation/) | Under 2 minutes for up to 95% of alerts, advertised with L2+ investigation depth. | Vendor claim including cross-stack enrichment/investigation, not our isolated-record classification test; no matched inputs or independently reproduced quality/latency. |
| [Enterprise ingestion processing documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-ingestion-time) | Under 10 seconds after the collection endpoint to query availability; upload buffering and source delays can add time. | Log availability, not per-alert AI classification or containment. |
| [Enterprise near-real-time detection rules](https://learn.microsoft.com/en-us/azure/sentinel/near-real-time-rules) | Queries scheduled once per minute with a documented two-minute delay. | Query cadence and data window, not one alert processed per minute. |
| [Published guided-response architecture, 2024](https://arxiv.org/html/2407.09017v1) | 15-minute inference-job interval; batch latency of a few minutes while handling very large daily incident volumes. | Distributed incident-level recommendation batches, not an isolated single-alert timing on our hardware. |
| [Managed SOC observed workload, reported March 2026](https://investors.n-able.com/news/news-details/2026/N-able-Report-Reveals-Why-AI-Powered-Layered-Cyber-Defense-Is-Essential-for-Business-Resilience/default.aspx) | Average two alerts/minute during March-December 2025, as reported by the provider. | Observed operational volume, not an ideal rate, measured maximum capacity or isolated-alert latency. |
| [Published automated workflow capacity claim](https://d3security.com/resources/event-pipeline-automate-handling-of-hundreds-of-alerts-per-minute/) | Up to 200 alerts/minute advertised for automated tier-one workflows. | Vendor-reported capacity with normalization, deduplication, triage and enrichment; no matched AIT-ADS quality/hardware test or single-alert latency. |

References checked November 18, 2026. A one-minute query schedule is not a one-alert-per-minute throughput ceiling. The reported two-alerts/minute workload is not a processing limit; the 200/minute automation claim also prevents treating 1-3/minute as a universal corporate capacity. An under-two-minute claim is an upper bound, not an exact measured latency from which to invent a speedup factor. Vendor claims are attributed, not independently reproduced here. A distributed batch can process many incidents together; its interval cannot be divided or multiplied into an invented isolated-alert latency. Fast local classification is a measured property of this replay, not proof of faster corporate investigation, ingestion, correlation, or response.

## Upcoming upgrade: estimated performance, not measured improvement

The proposed terminal pipeline has five workers: gateway, L1, L2 prefilter, L2 and final guardrail. Controlled software tests can establish that the stages overlap; they do not establish real-GPU speedup. The checkpoint above remains the original sequential architecture.

With the existing routing and the same stage costs, perfect independent overlap of L1 and L2 would reduce their serial bottleneck enough for at most about **2.71% higher stage-work throughput**. This calculation compares summed stage time with the slower stage, not with an enterprise product. It excludes queue/database overhead and is not a promised wall-clock gain.

The routing fix is a separate change: it sends unresolved Qwen escalations to Gemma instead of treating missing context as a terminal flag. A stronger independent L2 prefilter can quiet supported routine cases, but its suppression rate has not been established. More Gemma reviews can outweigh the benefit of parallel workers.

The upcoming prefilter uses independently checked reasons, including exact human-corrected process context and a narrow native Wazuh resolved-vulnerability notification check. It does not copy Qwen's opinion or promise to suppress most escalations. The final guardrail still protects risky or unsupported exits. These are software-tested rules, not measured improvements on this public checkpoint.

| Assumed share of L1 escalations safely quieted by L2 prefilter | Serial inference scenario, records/min | Ideal independent-stage overlap, records/min |
|---|---:|---:|
| 0% | 3.90 | 4.47 |
| 50% | 6.92 | 8.93 |
| 75% | 11.29 | 17.87 |
| 90% | 18.19 | 30.68 |

These are planning scenarios, not tested outcomes or guaranteed bounds. Each assumes this checkpoint's mean L1 cost, fraction of eligible L1 escalations and mean Gemma review time remain unchanged; every unsuppressed eligible escalation reaches Gemma. The first column is an assumption, not a suppression target. The serial scenario adds average stage costs; the ideal overlap scenario uses the slower stage. Shared-GPU contention, reloads, longer context, extra enrichment, bursts and storage can make real throughput worse than either estimate. Overlapping different records does not by itself shorten one Gemma assessment/challenge. Do not force unsafe suppressions to reach a desired percentage. No estimated accuracy gain is claimed before a separate attack-containing evaluation.

## Next steps

Use a separate frozen, balanced attack/routine comparison or a complete attack-containing timeline; preserve scoring labels outside prompts. Test the actual concurrent agent with persistent scoped context, case grouping and realistic arrival bursts. Compare identical isolated records and quality requirements on both systems if a true one-to-one commercial benchmark is required. Improve independently supported ordinary explanations, inspect unsupported suppressions, and test live queue delay before publishing response-time claims.

The original data and completed decisions were not rewritten or selectively retried. Interrupted attempts at the requested stop: 1; these are not scored as completed results. All 26,002 completed decisions are preserved, including any small overshoot of the 26,000-record target. The dataset and source hashes identify the exact run; the ZIP manifest protects the downloadable bytes.
