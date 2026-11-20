# Attack-inclusive five-worker checkpoint

This separate evaluation runs 26,000 consecutive supported Fox records from
2022-01-18 12:37:00 UTC through 2022-01-19 10:13:35 UTC. Preparation found
17,305 attack-labelled records and 8,695 without an attack annotation:
17,293 directory-scanning records, two online password-cracking records,
three attacker account-change records and seven privileged-command records.
The interval is selected using publisher labels before examining model outputs.
It is heavily dominated by one attack type, not representative of every attack.

Source: [AIT-ADS v1](https://zenodo.org/records/8263181), by Max Landauer,
Florian Skopik and Markus Wurzenberger, with the
[publisher's event labels](https://github.com/ait-aecid/alert-data-set/tree/ce927ddaeaa674f6909e1de676fa7dc293e393bd/alerts_csv).
Both cached archives must match the previously recorded SHA-256 hashes.
Every selected record's description, agent IP and original timestamp is aligned
with its publisher row. Unsupported AMiner input is excluded.

## What this measures

The frozen packaged application uses the real five worker threads: gateway,
Qwen3.5:4b L1, L2 pre-filter, Gemma4:12b L2 and final guardrail. Gemma receives
only eligible L1 escalations. Pre-filters, model validation, independent L2
challenge and shared suppression vetoes are unchanged. The test opens its own
memory, ingestion and audit databases. It starts no collectors or response
executor. Recommendations cannot perform device actions.

Records keep their original security timestamps. Each enters the isolated
queue only after the preceding record has a saved L1 assessment. Qwen can
continue while Gemma reviews earlier records; bounded downstream queues apply
backpressure. This accelerated chronological replay preserves L1 order without
delaying 21 hours to match source arrival times. It is not a live arrival-rate
stress test. Receipt-to-final latency includes this benchmark's actual queue
wait; pipeline latency starts at gateway preparation. Worker occupied time
includes downstream blocking, while per-record work-before-handoff excludes it.
Neither quantity is pure GPU inference time. Separate model-call wall times
include local transport and metadata verification. Interrupted records retain
their attempts and are identified for exclusion from latency comparisons.

Memory starts empty and is preserved across records and resumptions. The fixture
uses the native Wazuh connector in its isolated database so the existing exact
learned-pattern rules can operate. This is a test-only source fixture, not a
claim that file imports are trusted live collectors. Original IDs remain in the
scorer index; opaque benchmark IDs ensure duplicate public rows are each scored.
The models never receive publisher labels or scorer-index fields. No human
feedback or ground-truth training is manufactured. Context uses source time;
the one-hour/25-hit learned-pattern limit uses processing wall time. This clock
difference limits extrapolation to real-time deployments. Embedded timestamps,
addresses and other varying raw fields may prevent exact-pattern cache hits.

The owner authorized pausing the installed dashboard to avoid competing model
requests. Its task is stopped without changing customer databases or collector
settings; an elevated supervisor requests restart when the worker exits,
including on failure. The model server stays available and may already be warm;
initial loaded models, model identities and hardware are recorded. If Windows or
the supervisor itself is terminated, start the existing **Arbiter** task manually.

## Results and limits

Preparation is not a completed benchmark. Results belong in the separate output
directory; they must not overwrite the earlier 26,002-record checkpoint.
`STATUS.txt` is the human-readable live progress file; `progress.json` adds
per-worker queues and timing, `results.db` saves each completed decision
transactionally, and `decisions.jsonl` exports results in source order on exit.
`STOP` requests intake stop and draining. A single-instance OS lock, frozen
runtime/input hashes and repeated local model-identity checks prevent accidental
mixed or duplicate runs. Resume retains completed decisions and recovers pending
work; the supervisor intentionally refuses an automatic unreviewed resume.

Attack recall measures how many publisher-labelled attack records stayed
flagged. FP/TN counters use *unannotated* rows: those rows are not independently
certified benign. Thus label agreement is not a definitive real-world accuracy
measure. Most attacks here are repeated scans; report results per attack type
as well as aggregate counts. Earlier development used AIT-ADS samples, so this
is not an independently held-out validation. This run cannot establish a speed
advantage over corporate products or prove an upcoming improvement in advance.

```powershell
python tools/chronological_public_eval.py prepare --out output/public-eval/ait-ads-five-worker-2026-11-19 --runtime output/dashboard-ready-2026-11-18/arbiter-0.1.0.pyz
# After checks, launch Start-ChronologicalPublicEval.ps1 elevated with the
# absolute prepared RunDirectory and PythonPath. It restores the dashboard.
```

Raw results and a plain-language report require owner review before publication.

## November 19 interruption

The first attempt stopped at 17,467 completed records after an L2 assessment
raised `ValueError`; the affected record, 17,463, stayed flagged. The exact
rejected response was not saved, so a more specific validation cause is unknown.
The original checkpoint, logs and databases are backed up under
`interruptions/2026-11-19T071429Z`. Sixty-four unfinished records retain their
saved L1 outcomes. Completed failures must not be retried until successful.

The dashboard's existing scheduled recovery restarted it at 05:22:28 UTC,
13 seconds after the worker began. Therefore the initial timing segment shared
the GPU and must not be described as an isolated benchmark. The revised
supervisor temporarily disables that recovery task, restores its prior enabled
state on exit, keeps separate attempt logs and requests intake stop if the
dashboard port returns. Its `-Resume` option requires a stopped or paused
checkpoint and preserves the frozen runner, application and input files.
The first Windows administrator prompt for this reviewed resume was cancelled.
The owner requested another attempt; it resumed at 08:10:48 UTC on November 19.
The task-disable command succeeded, all five workers were observed alive and the
previous dashboard process and listening port were absent. Per-attempt logs are
under `attempts/20261119-081038`; continuous supervision watches the port.
Resume must report downtime separately and exclude interrupted records from
clean latency comparisons. Saved L1 outcomes can be reused, but their earlier
model-call durations were not retained for unfinished rows.
