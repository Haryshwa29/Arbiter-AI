# Reproduced faults and source fixes

The owner asked for a focused code review while keeping the benchmarks stopped.
This pass covered the two-brain pipeline, recovery, local inference transports
and evaluation tools. Tests used temporary databases, local HTTP fixtures and
controlled model replies. No real inference, device actions or live AWS calls
were required. The installed desktop service was not upgraded.

| Reproduced problem | Source fix and regression evidence |
|---|---|
| Recognized web attack alerts escaped the web guard when Wazuh used `appsec/attack` instead of the extra `accesslog` group. Native Apache denied-access findings also escaped it. | Recognize the native decoder and relevant groups; ordinary access-log 404s remain distinct. Three failing cases now pass in `test_checkpoint_upgrade.py`. The explanation requests review without claiming a successful compromise. |
| A missing HTTP request was treated as a harmless parsing fault. | The shared gate retains native “unable to match response to request” findings. A normal informational connection remains a negative control. |
| Repeated native patterns failed to match solely because the duplicated Wazuh repeat counter changed. | Ignore that envelope counter in copied metadata as well as raw metadata. Changed event content still invalidates the match, and original evidence remains intact. Key version 3 prevents old shortcuts from silently acquiring the new scope. |
| A second Gemma call ran even when its outcome could only keep the alert. | Retain-only classification skips that redundant challenge. Every proposed suppression still requires the challenge, confidence/evidence checks and final gate. Tests verify both one-call retention and rejected two-call suppression. |
| One rejected reply or HTTP 500 stopped the entire checkpoint despite the alert being safely retained. | Shared health handling distinguishes handled L2 failures from structural worker failures. Reproduced both faults: the failed alert stays flagged and later records finish. Three consecutive failures still stop; Qwen success cannot reset Gemma's failure streak. |
| Resumed Qwen decisions were undercounted because their earlier call timings were unavailable. | Count preserved assessments separately from captured calls. Read-only recomputation of the stopped checkpoint finds 208 Qwen-reviewed records and 144 captured calls; no new calls or changed outcomes are invented. |
| A completed record disappeared from the pending checkpoint set before a failed ledger write. | Remove it only after the result transaction succeeds. A one-shot SQLite write failure now leaves every completed telemetry row represented in the final saved results. |
| Restart reused the verdict but lost its investigation steps and confidence. | Restore validated saved metadata only when the exact event and immutable verdict fields match. A foreign event's guidance is rejected and the model is not called again. |
| L2 errors recorded only an exception type, hiding which stage failed. | Save a bounded explanation and stage. Tests distinguish L2 pre-filter, Gemma review and final-guardrail failures while retaining the alert. |
| L1 and model discovery followed redirects away from the configured service. | Share the existing redirect rejection between local transports and disable environment proxies for discovery. Two local-server tests failed before the fix and pass afterwards; L2's existing protections remain covered. |
| The Windows supervisor reported success after preparation/launch failures. | Return failure status to its caller and check dashboard restoration command results. Missing preparation and an invalid resume both produce nonzero exits without touching the dashboard. |

The duplicate development regression template was removed after verifying it
matched `tests/test_checkpoint_upgrade.py`. Error-streak and worker-health logic
is shared between the chronological and timed runners. No mandatory runtime
dependency was added. Boto3 and its pinned dependencies were installed only in
`output/ponytail-review-2026-11-19/aws-test-runtime`; the two previously skipped
AWS SDK contract tests passed there using mocked sessions.

Validation: **618 tests passed, no skips, 25 subtests passed** in that validation
environment. The base environment passed 616 with only the two optional AWS
checks skipped. One existing third-party pytest deprecation warning remains.
The source and built zipapp each passed seed plus the 22-event mock CLI run.
The release is under `output/ponytail-review-2026-11-19/release`.

All 23 saved attack-labelled suppressions are now vetoed in a read-only replay
of their original native evidence. This is a seen-record guard regression,
not fresh model accuracy, fewer false positives or a measured speedup. Stricter
retention may also keep more ordinary warnings visible.

The earlier run remains stopped at **17,612 records**. Its input/runtime
checksums and original decisions were preserved. Its frozen runner is a
historical copy and was not silently replaced with the refined source.
The older automatic handoff is paused and needs a fresh plan matching this
source before any later activation. Nothing was pushed or deployed.

The observed CUDA runtime crash has **not** been reproduced or fixed by these
code tests. HTTP 500 was injected to verify safe handling only. A real GPU soak
and real AWS account integration remain untested; neither is implied by the
passing suite. No benchmark or ten-hour timer was restarted.
