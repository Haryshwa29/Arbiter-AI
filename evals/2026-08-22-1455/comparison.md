# Local model comparison — Arbiter triage

Run 2026-08-22T18:55:27+00:00 on Panther_29 (Windows 11), arbiter @ `8da38d0`, 3 run(s) per suite, guardrails **on**.

## Models served

| model | digest | params | quant | size |
|---|---|---|---|---|
| `qwen3.5:4b` | `2a654d98e6fb` | 4.7B | Q4_K_M | 3.4 GB |
| `gemma4:12b` | `4eb23ef187e2` | 11.9B | Q4_K_M | 7.6 GB |

## Suites

| suite | cases | sha256 |
|---|---|---|
| `samples/model_gauntlet.jsonl` | 22 | `62c2fa4db56160ba` |

## Model-only subset — the comparison that counts

Guardrail-decided cases are excluded: they escalate without the model and would score identically with no model at all.

| suite | model | recall | precision | missed | flaky | gate | s/case |
|---|---|---|---|---|---|---|---|
| `model_gauntlet` | `qwen3.5:4b` | 100% | 92% | 0 hard / 0 latent | 0 | PASS | 4.35 |
| `model_gauntlet` | `gemma4:12b` | 100% | 80% | 0 hard / 0 latent | 0 | PASS | 7.10 |

## Full suite (guardrails included)

| suite | model | recall | precision | accuracy | rail-decided |
|---|---|---|---|---|---|
| `model_gauntlet` | `qwen3.5:4b` | 100% | 92% | 95% | 0 |
| `model_gauntlet` | `gemma4:12b` | 100% | 80% | 86% | 0 |

## Where they disagree — `model_gauntlet`

2 case(s) decided differently. A model that wins on aggregate but loses here is not clearly better.

| category | expected | `qwen3.5:4b` | `gemma4:12b` | event |
|---|---|---|---|---|
| precision_pentest | suppress | suppress (OK) | escalate (WRONG) | netflow_anomaly on web-prod-01 |
| precision_dba_cron | suppress | suppress (OK) | escalate (WRONG) | cron_change on db-prod-01 |

## Hard misses by model

Missed in every run. Per invariant #1 these are the only failures that are actually expensive.

_None._
