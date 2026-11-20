# Fresh concurrent 26K evaluation

The owner authorized another run after the source fixes, explicitly requested
concurrent Qwen and Gemma work, and requested termination of the installed
dashboard rather than restoring it afterwards. The new run began November 19
at 22:43:43 UTC (17:43:43 Eastern). It is separate from the stopped 17,612-record
checkpoint and the older published 26,002-record checkpoint.

Output: `output/public-eval/ait-ads-26k-parallel-2026-11-19`.

- AIT-ADS v1, Fox scenario, 26,000 consecutive supported records covering
  January 18, 2022 at 12:37 UTC through January 19 at 10:13:35 UTC.
- Publisher labels identify 17,305 attacks: 17,293 directory scans, two online
  password-cracking records, three attacker account changes and seven
  privileged commands. Another 8,695 rows have no attack annotation; they are
  not independently confirmed benign.
- Five independent pipeline workers, Qwen3.5:4b L1 and Gemma4:12b L2. No shared
  inference lock: Qwen can assess later records while Gemma handles eligible
  L1 escalations. This does not mean every record calls either model.
- Empty isolated memory and databases at launch; persistent within this run.
  Original source order, labels excluded from model inputs, no response executor
  or device actions. This is accelerated replay, not original-rate traffic.
- The current fixed core matched all 79 packaged Python/JSON source files.
  Runtime SHA-256: `fa1ca25e942534ff60858f49b00c8892c39dcd932eb0e63fb97ab460b25da0df`.
  `source-provenance.json` records uncommitted fixes, source hashes and launch
  instructions; `frozen-files.json` pins the runtime, runner and inputs.
- Validation: 618 full-suite tests and 25 subtests passed in the optional-SDK
  environment; all 15 chronological/supervisor tests passed after launch-control
  changes. AWS tests use mocked sessions. This run makes no AWS calls.

The elevated supervisor successfully disabled the installed Arbiter recovery
task and terminated its dashboard process. Process 67600 and the listener on
port 8787 were verified absent. `-LeaveDashboardStopped` deliberately leaves
the task disabled and dashboard stopped when this evaluation exits. Restarting
the installed dashboard later requires explicitly enabling/running its existing
task; do not restart it during this benchmark.

Live progress is in `STATUS.txt` and `progress.json`. Completions are saved to
`results.db`, with source-ordered `decisions.jsonl` exported on exit. Per-attempt
logs include `gpu-samples.csv` with GPU memory, utilization, temperature and
driver version sampled about every 15 seconds. Sampling failures are recorded
without terminating the worker. GPU timeout/OOM recurrence remains possible;
concurrent operation has not been proven stable by unit tests. Isolated handled
model failures retain the affected alert; three consecutive model failures or
a structural worker failure stop the run.

The first observed progress check had 157 completed records, zero processing
failures and all five workers alive. This is a launch check, not final quality,
latency or stability evidence. Later status must be read from the live files.
Final findings require analysis of this run's own results; the older reporting
template contains historical assumptions and must not be applied unchanged.
Nothing was published, pushed or deployed to the installed customer application.
