# L2 context development checks — not a public-dataset accuracy result

This archive preserves three synthetic development controls evaluated through
fresh local Qwen L1 and eligible Gemma L2 reviews. It also preserves the guard-only
retest on those same controls. The original 2,600,263-record public replay stays
on its original source in a separate working tree.

| Synthetic control | Initial L2 outcome | Problem / interpretation | After guard fix |
|---|---|---|---|
| Unexplained TLS protocol anomaly with conversation details | Gemma quieted it; its challenge accepted | Lack of exploit evidence did not explain the anomaly | Retained by `L2_PROTOCOL_CONTEXT_ONLY`, no model call |
| Native scanner reports active CVE, package and version | Retained by `L2_REPORTED_VULNERABILITY`, no model call | Review the source claim and patch applicability; not proof of exploitation | Still retained by that rule |
| TLS protocol anomaly with only a CVE reference, no affected-version evidence | Gemma quieted it; its challenge accepted | A generic decoding-error explanation was unsupported by a recorded cause | Retained by `L2_PROTOCOL_CONTEXT_ONLY`, no model call |

These controls have no independently established attack/benign ground truth.
There is no accuracy, detection-rate or false-positive improvement percentage
to publish from them. Two model suppressions were rejected as unsupported
reasoning, rather than being silently presented as successful noise removal.
Adding reference information and strengthening a prompt did not resolve this
model/critic weakness.

`prototype-results.jsonl` contains all three original first/second reviews.
`prototype-meta.json` records canonical source/data hashes. The four files
under `prototype-source/arbiter` reproduce the prototype differences from the
final source; each byte sequence was checked against the original hash. Other
runtime files and the offline index match the final source.

`guard-retest.jsonl` reuses the frozen successful Qwen escalations and
renormalizes the same synthetic inputs through the final native extractor. It reruns
the corrected deterministic L2/final checks, makes no new model calls, and
retains all three warnings. `guard-retest-meta.json` identifies that exact
source/data state. It is a policy retest on seen controls, not a fresh benchmark.

The original full-data replay shared the local inference runner/GPU during the
development probes. Timings are retained as observations, not an isolated
performance or speedup claim. Model identities were separately captured after
the checks; metadata verification in each actual inference call enforces local
models, but no per-call digest snapshot was recorded in this diagnostic probe.

Software verification covers same-host/account/peer and five-minute boundaries,
future-event exclusion, native source evidence, CVE references versus active
scanner findings, future KEV listings, both model passes, protocol-context
vetoes and offline release/zipapp packaging. The full suite passed 527 tests,
with 2 skipped and 25 passing subtests; the CLI sample and policy-export check
also passed. See `validation.json`.

Next: evaluate freshly normalized raw public records with genuinely available
surrounding evidence in a separate frozen comparison. A missing source field
must remain missing. No installed deployment or public accuracy gain is claimed.
See [the plain-language context guide](../../docs/L2-CONTEXT.md).
