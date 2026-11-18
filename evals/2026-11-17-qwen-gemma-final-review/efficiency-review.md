# Efficiency review

The expensive part is the model review, not Python bookkeeping.

| Measured item | Value |
|---|---:|
| Records that reached Gemma | 97/202 (48.0%) |
| Records that bypassed Gemma | 105/202 (52.0%) |
| Gemma requests, including the challenge | 194 |
| Generated tokens | 55,625 |
| Measured Gemma review time | 3,030.49 seconds |
| Model loading reported by the runner | 11.40 seconds |
| Prompt processing reported by the runner | 283.51 seconds |
| Text generation reported by the runner | 2,649.73 seconds |
| Sum of those model-work counters | 2,944.63 seconds (97.2% of review time) |
| New runtime packages | 0 |

The duration fields are documented by the [local runner's API](https://docs.ollama.com/api/generate).
The calculation sums counters retained in `secondary.jsonl`; `efficiency.json`
keeps the inputs. This is an accounting comparison, not an operating-system
profiler or a concurrency/load test. The remainder is not attributed entirely
to Python: it can include request handling, validation, serialization and other
server/client work.

The review covered the agent entry point, event/status views, CLI and launcher,
L2 routing and exact-event binding, local transport, validators, policy fixture,
tests and report exports. It retains the existing scheduler, local transport and
validation flow. No extra service, dependency, cache or worker pool was added.

No source rewrite was justified by these measurements. Removing checks or
rearranging small Python functions would not solve the measured inference cost.
The scored source and model settings remain unchanged and hash-verified. The
non-trivial classification and routing logic has regression tests; the report
independently checks input identity, routing and the final decision counts.

The useful next speed experiment is to reduce unnecessary model work while
checking missed attacks and warning counts on a fresh frozen test. Compare
shorter evidence/explanations or other compatible local model/settings choices.
Treat each change as a new configuration, rather than editing this completed
run. Keep the trust-boundary checks and error handling.

Skipped: a scheduler rewrite, new runtime packages and speculative caching.
Not measured: a live queue, concurrent throughput or deployed dashboard behavior.
