# Finish the checkpoint, then measure ten hours

**Current status:** paused by the owner. The later
[Ponytail source fixes](PONYTAIL-REVIEW-2026-11-19.md) supersede the original
staged candidate described below. The old launcher is disabled; its handoff
plan must be refreshed against the changed source before another activation.
No ten-hour timer has started. The following describes the prepared experiment,
not a currently running job.

The owner requested this sequence on November 19: finish the current
26,000-record AIT-ADS run, explain its failures, apply appropriate fixes and
optional libraries, then run a new experiment for ten hours. The current
checkpoint stays on its frozen application and model configuration.

`tools/after_checkpoint_eval.py` is a local experiment controller. It waits for
all 26,000 results, writes a plain-language report, and checks the staged
candidate against every attack-labelled record the baseline wrongly suppressed.
If a final miss remains unprotected, source files change, tests fail or an
unknown operational error occurs, the handoff stops for review. It does not
publish to GitHub. Completed failed model replies remain saved and flagged;
they are never retried until successful. Known isolated L2 validation failures
or local HTTP errors can resume unfinished baseline work after unchanged model
identities respond to local health probes, preserving failed alerts, checkpoints
and interruptions.
Three consecutive failed L2 reviews or structural worker failures stop recovery.

The staged candidate fixes alternate native web-rule groups and Apache denied
access handling, prevents missing HTTP request evidence from becoming an
unsupported harmless-parser diagnosis, and describes signature history as
unverified prior decisions. It also removes Wazuh's redundant envelope counter
from the copied metadata used for exact-pattern matching. Commands, paths,
identities, log text and risk checks remain in scope. Variable log timestamps
can still prevent cache matches; this is not blanket host/signature suppression.
L2 records useful validation-error details. A retained-alert decision skips a
second model call that cannot change it to suppression; every proposed
suppression still requires the challenge and final checks. No device-action
authority is added. The full final report quantifies extra warnings caused by
the stricter policy; speed and quality improvements are not assumed in advance.

Only after those checks does the controller apply the source patch, install
the pinned optional AWS SDK wheels into a separate benchmark environment and
run the full suite, including the two AWS tests previously skipped. Those AWS
tests use mocked sessions, not a real account. The SDK is connector support,
not a speed improvement for Gemma. No customer credentials or cloud collection
are enabled. See [Boto3](https://docs.aws.amazon.com/boto3/latest/guide/quickstart.html).

## What the clock measures

The next run uses an independent intake loop and a bounded 10,000-record durable
buffer, feeding the same five worker stages with Qwen3.5:4b and Gemma4:12b.
Intake no longer waits for the preceding L1 assessment. Production priority
scheduling and downstream backpressure are enabled. This is a capacity test,
not a replay at original arrival speed or a guarantee of per-alert latency.
Each scenario has separate memory/audit/ingestion databases; a previous
scenario drains before the next begins.

The source is the pinned [AIT-ADS v1](https://zenodo.org/records/8263181)
Wazuh/Suricata archive and publisher event labels. It starts in Fox at
2022-01-18 12:37 UTC, then can continue through the remaining scenarios in
original file order. There are **2,170,969 eligible records** after excluding
the earlier Fox prefix from the **2,600,263 supported records**. The 55,558
AMiner records are unsupported and excluded. There is no label-balanced
sampling, no model access to labels and no independent held-out claim: some
records were used for policy development. The run may finish before ten hours
if the entire eligible source is exhausted; that outcome is stated explicitly.

The 36,000-second monotonic timer starts for the measured run, after preparation
and tests. It stops admission at the cutoff. Only final decisions completed
within that window count as throughput. In-flight model calls are joined for
clean shutdown; that can take approximately three additional minutes. Their
late completions are reported separately. Pending records stay durable and
must not be counted as decisions. Intake count, final count, deadline backlog,
per-brain activity, worker queues/errors, latency and label outcomes are saved.
Three consecutive failures in either brain stop the run; success in the other
brain cannot hide that failure. An individual invalid L2 reply stays flagged
and does not end the entire test.

The installed dashboard's recovery task is disabled while each supervised
benchmark runs and restored on exit. The supervisor watches for its port
returning. A terminated supervisor or Windows shutdown may require manually
re-enabling the existing Arbiter task; the experiments preserve customer data.
Models may already be loaded, and initial model/hardware state is recorded.

## Where to watch

- Baseline: `output/public-eval/ait-ads-five-worker-2026-11-19/STATUS.txt`.
- Handoff: `output/public-eval/after-26k-upgrade/STATUS.txt`.
- Next test: `output/public-eval/ait-ads-10h-after-26k/STATUS.txt`, created when
  the timer actually starts.
- Final baseline findings: `after-26k-upgrade/baseline-report/README.md`.
- Timed findings and counters: `ait-ads-10h-after-26k/README.md`,
  `final-summary.json`, `results.db` and `decisions.jsonl`.

Missing attack labels do not certify benign activity. Priority scheduling
selects which accepted records finish before the deadline, so report outcomes
and backlog by label/type. The interrupted baseline shared GPU use early on
and cannot support an isolated full-run speed comparison. No live device
actions or GitHub publishing are part of this handoff.
