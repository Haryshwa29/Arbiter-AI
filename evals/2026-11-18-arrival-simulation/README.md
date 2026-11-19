# One hour of arrivals can require more than one hour of work

The owner's burst-load calculation is reproduced from the frozen
`decisions.jsonl` in the [26,002-record checkpoint](../2026-11-18-26k-checkpoint/README.md).
This is a **simulation using measured per-record costs**, not an observed live
queue, a new model evaluation, or a measurement of the upgraded five-worker app.

The source records span **57 hours and 50 seconds**: 2022-01-15 02:32:32 UTC to
2022-01-17 11:33:22 UTC. Running the stopped evaluation took 14h31m28s of wall
time. Original dataset time and evaluation wall time describe different clocks.

| Finding | Result |
|---|---:|
| Records arriving on 2022-01-16, 17:00–17:59 UTC | 1,683 |
| Qwen reviews in that arrival hour | 1,402 |
| Gemma reviews in that arrival hour | 0 |
| Total measured work for that arrival hour | 7,549.85 seconds = 125.83 minutes = 2.10 hours |
| Longest measured individual processing cost in the stopped checkpoint | 57.07 seconds |
| Maximum simulated FIFO wait before processing starts, over all 26,002 arrivals | 6,217.73 seconds = 103.63 minutes (about 104) |
| Maximum simulated arrival-to-completion time | 6,223.76 seconds = 103.73 minutes |

The simulated worst case is **Fox record 20,495**, arriving at
2022-01-16 17:48:16.307192 UTC. Its simulated start is 19:31:54.034503 UTC and
completion 19:32:00.067204 UTC. Its own measured service cost was 6.03 seconds.
The large delay comes from earlier work waiting ahead of it. The original replay
read the file as fast as it could and did not observe this live-arrival queue.

This reproduces the owner's result: record order is already chronological, so
stable timestamp ordering produces the same maximum. The model assumes one FIFO
worker, an empty queue at the first arrival and unchanged recorded `elapsed_s`
costs. It ignores collection/network delay, priorities, batching, changing model
costs and learned reuse. Subsequent arrivals after record 26,002 are excluded.
L2 rule/housekeeping work in the highlighted hour is under one second; Gemma had
no inference work. The bottleneck was overwhelmingly L1.

## What this means for the upgrade

The overall mean of 29.84 saved records/minute hides bursts. A 2.10-hour workload
cannot fit into one hour on the same sequential worker. Under fixed costs, that
hour needs about **2.10 times the processing capacity**, or **52.3% less service
work**, just to keep up. These are capacity requirements, not achieved speedups
or targets for suppressing 52.3% of alerts regardless of evidence.

Five stages let L1 and L2 overlap different records. They do not create five
Qwen workers. Because this burst had no Gemma reviews, L1/L2 overlap alone would
provide essentially no relief for it. Safe L1 repeat filtering, cheaper supported
rules or genuinely higher measured L1 capacity are the direct levers. The new
exact-pattern memory may miss records whose free-form timestamps, process IDs or
other details change; its actual reuse rate needs measurement.

Better host identity and security context aim to reduce mistaken cross-machine
reasoning and unsupported decisions. Sending formerly bypassed cases to Gemma
adds work and can slow a cold run. More context, correct routing and extra workers
therefore do not establish faster throughput or better attack accuracy. The next
test must report cold/warm model calls, throughput, median/p95/max queue and
end-to-end latency, false warnings and missed attack labels on matched inputs.

## Reproduce without model calls

```text
python tools/simulate_checkpoint_queue.py --out output/arrival-simulation
```

`simulation.json` records assumptions, hourly work and worst-case identity;
`simulated-queue.csv` provides all 26,002 virtual arrival/start/finish times.
`SHA256SUMS.txt` protects both artifacts. Input ZIP SHA-256:
`9e3483bf725f6125454e130c846d8161238ff3f0379718c2aa6793c1b62f502a`.
AIT-ADS v1, AIT Landauer/Skopik/Wurzenberger, DOI
[10.5281/zenodo.8263181](https://zenodo.org/records/8263181), CC BY 4.0.
