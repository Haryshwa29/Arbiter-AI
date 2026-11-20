# Check that the new handoff works

These are small development compatibility checks on **eight already seen records**
from the frozen AIT-ADS Fox checkpoint. No publisher labels were sent to either
model. No device actions or production collectors were started. Both probes used
isolated SQLite state and the real local Qwen3.5:4b and Gemma4:12b models.

The first selection (records 1, 775, 21760, 25772) completed all four through L1;
none needed L2 in this run. The helper's expectation that at least one would
exercise Gemma was not met. A second selection explicitly exercised the handoff
(246, 247, 2996, 2997): all four Qwen escalations reached Gemma, which made eight
generation calls in total, including the separate challenge passes. All five
workers completed without stage errors. The outputs were suppressions; **these
judgments have not been independently established as correct**.

The structured evidence retains both selections, their raw-record hashes,
decisions, stage queues/counters, elapsed times and model usage. The probes ran
against uncommitted development code without a frozen complete source identity;
the later packaged build's hash is identified separately. These checks therefore
confirm local transport/queue/API compatibility, not reproducible benchmark
accuracy, safe broad suppression, learning effectiveness or production latency.
They must not replace or be added to the stopped checkpoint's 26,002 results.

Software verification of the final upgrade: 576 backend tests passed, 2 skipped,
25 subtests passed; 17 frontend checks passed; dashboard type/build and lint
passed (two existing Fast Refresh warnings). The source and packaged 22-event
mock CLI smoke checks passed. The release includes the offline context catalog,
the five-worker pipeline, scoped repeat memory and self-hosted dashboard assets.

Next: a fresh chronological attack-labelled comparison with learning off/on,
matched hardware and model settings, warm/cold latency and independent review
of suppressed attacks. See [repeat-pattern limits and test plan](../../docs/LEARNED-PATTERNS.md).
