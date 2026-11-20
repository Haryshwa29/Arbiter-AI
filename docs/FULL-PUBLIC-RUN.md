# Running the full public dataset overnight

**Historical sequential comparison protocol.** The stopped 26,002-record
checkpoint used this runner. It retains the legacy L2 routing for comparison;
it does not benchmark the subsequent five-worker live pipeline or warmed pattern
memory. Do not resume its old ledger with changed source. A new chronological
five-worker/learning comparison needs a separate run and frozen protocol. See
[the current pipeline](FIVE-WORKER-PIPELINE.md) and the
[arrival-capacity simulation](../evals/2026-11-18-arrival-simulation/README.md).

The source version can run **Qwen3.5:4b as L1** and **Gemma4:12b as L2**, entirely
on this PC. Gemma receives only successful Qwen escalations, through the separate
L2 rules. It can keep or quiet a warning. A shared final safety check covers
decisions from either stage. The installed/portable dashboard is a separate
build; starting this replay does not upgrade it or enable live collection.

## What this run includes

All **2,600,263 supported records** in AIT Alert Data Set (AIT-ADS) v1 are
included, rather than a sample. The other **55,558 AMiner records** are explicitly
excluded because the adapter does not support them. This leaves no supported
record deliberately sampled out. The archive contains 2,655,821 records overall.

The full input check aligned all 2,600,263 raw records to the publisher's pinned
per-record labels: **1,771,136 have attack annotations and 829,127 do not**.
Both archive checksums, publisher-label revision, exact model identities and
source hashes are checked and recorded. Scoring labels never enter either model.
An absent attack label is not proof that a record is harmless.

The replay uses the same **independent empty history per record** protocol as
the earlier comparisons. It runs the actual existing rules, Qwen and eligible L2
reviews with fresh inference, without reusing old answers, deduplicating inputs
or skipping failures. Records stay in original scenario/file order. This tests
alert classification, not chronological learning, live queues, incident
correlation or the complete operational dashboard. No device actions are enabled.

## Start or resume

From the repository root in PowerShell:

```powershell
.\tools\Start-FullPublicEval.ps1
```

The worker runs in the background and saves results in
`output/public-eval/ait-ads-full-2026-11-18`. Open **STATUS.txt** there for a
plain-language progress update. `worker.json` identifies the process and its
separate logs; `progress.json` contains machine-readable counts.

Keep the PC powered on. On Windows the worker temporarily prevents automatic
system sleep while it runs; the display can turn off. It does not change the
permanent power plan. Shutdown, restart or loss of power still stops it.

Starting the same command after an interruption resumes from the last completed
record. A lock prevents two workers from owning the same output directory. Every
completed result and its counters are committed together in SQLite. Interrupted
attempts remain journalled and unfinished records can run again. Completed model
errors stay counted; they are not retried until an answer passes. Three successive
model failures stop the worker rather than quietly replacing the rest of the
dataset with fallback warnings. Inspect the error log before resuming.

If the model identities, inputs or evaluated source change, resuming refuses to
mix versions. Preserve the original inputs and source, or use a new directory.
The terminal foreground equivalent is:

```text
python -u tools/full_public_eval.py --out output/public-eval/ait-ads-full-2026-11-18
```

## What the results mean

`results.db` stores each completed normalized event, both decisions where
applicable, original evidence packet, guardrail receipt, model replies/call
counts, errors and deciding layer. `primary-audit.jsonl` is the L1 audit trail;
`run.json` fixes the input/model/source identities. Counts distinguish cheap
rules, Qwen, actual Gemma replies and failures. Original public records remain
available by scenario and line number in the checksum-verified archive.

**A running count is not a completed full-dataset result.** STATUS.txt says
COMPLETED only after the final input alignment and total-count checks pass.
The final report must include failures, interrupted attempts, attack labels
quieted, remaining warnings, processing cost and which layer made each decision.
This known public dataset does not establish production detection rates.

One night may process only part of the dataset. Model-heavy records can take
seconds or longer each; there is no promised overnight completion time. No extra
runtime dependency or cloud inference service is introduced.

## Stop at a requested checkpoint and export

The separate stop controller can watch an already running Windows worker without
changing the evaluated source:

```text
python tools/stop_public_eval_at.py --out output/public-eval/ait-ads-full-2026-11-18 --target 26000 --export output/public-eval/ait-ads-stop-26000
```

It verifies the worker's script/output identity and holds its original process
handle. After the committed count first reaches or crosses the target, it takes
the SQLite writer lock and stops that worker. A currently unfinished attempt may
be interrupted; completed records remain intact. Polling can permit a small
overshoot, which the stop receipt reports exactly.

The export includes a readable summary, CSV, complete per-record JSONL, SQLite
snapshot, input/model/source provenance and file checksums in a tested ZIP.
Spreadsheet formula-like text is escaped in CSV; JSONL and SQLite preserve the
original values. A first-record prefix is not a representative full-dataset
test, and attack recall is undefined if that prefix contains no attack labels.

Dataset: [AIT-ADS v1, DOI 10.5281/zenodo.8263181](https://zenodo.org/records/8263181),
Max Landauer, Florian Skopik and Markus Wurzenberger, AIT Austrian Institute of
Technology, CC BY 4.0. Publisher-requested citations: *Introducing a New Alert
Data Set for Multi-Step Attack Analysis* (2024) and *Maintainable Log Datasets
for Evaluation of Intrusion Detection Systems* (2023).
