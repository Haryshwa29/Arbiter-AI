# Local model comparison — Arbiter triage

Run 2026-08-22T19:36:03+00:00 on Panther_29 (Windows 11), arbiter @ `8da38d0`, 3 run(s) per suite, guardrails **on**.

## Models served

| model | digest | params | quant | size |
|---|---|---|---|---|
| `qwen3.5:4b` | `2a654d98e6fb` | 4.7B | Q4_K_M | 3.4 GB |
| `gemma4:12b` | `4eb23ef187e2` | 11.9B | Q4_K_M | 7.6 GB |

## Suites

| suite | cases | sha256 |
|---|---|---|
| `samples/realistic_suite.jsonl` | 101 | `c4c9b01dec4f5eec` |
| `samples/redteam_suite.jsonl` | 20 | `48d07c898bceb047` |

## Model-only subset — the comparison that counts

Guardrail-decided cases are excluded: they escalate without the model and would score identically with no model at all.

| suite | model | recall | precision | missed | flaky | gate | s/case |
|---|---|---|---|---|---|---|---|
| `realistic_suite` | `qwen3.5:4b` | 100% | 54% | 0 hard / 0 latent | 2 | PASS | 4.74 |
| `realistic_suite` | `gemma4:12b` | 100% | 62% | 0 hard / 0 latent | 0 | PASS | 5.95 |
| `redteam_suite` | `qwen3.5:4b` | 100% | 100% | 0 hard / 0 latent | 0 | PASS | 4.29 |
| `redteam_suite` | `gemma4:12b` | 60% | 100% | 2 hard / 0 latent | 0 | FAIL | 5.98 |

## Full suite (guardrails included)

| suite | model | recall | precision | accuracy | rail-decided |
|---|---|---|---|---|---|
| `realistic_suite` | `qwen3.5:4b` | 100% | 72% | 83% | 23 |
| `realistic_suite` | `gemma4:12b` | 100% | 78% | 88% | 23 |
| `redteam_suite` | `qwen3.5:4b` | 100% | 100% | 100% | 12 |
| `redteam_suite` | `gemma4:12b` | 88% | 100% | 90% | 12 |

## Where they disagree — `realistic_suite`

9 case(s) decided differently. A model that wins on aggregate but loses here is not clearly better.

| category | expected | `qwen3.5:4b` | `gemma4:12b` | event |
|---|---|---|---|---|
| benign_deploy | suppress | escalate (WRONG) | suppress (OK) | service_restart on api-prod-01 |
| benign_backup | suppress | suppress (OK) | escalate (WRONG) | data_transfer on nas-01 |
| benign_auth | suppress | escalate (WRONG) | suppress (OK) | mfa_success on mail-01 |
| benign_deploy | suppress | escalate (WRONG) | suppress (OK) | service_restart on web-prod-01 |
| benign_deploy | suppress | escalate (WRONG) | suppress (OK) | service_restart on web-prod-01 |
| benign_deploy | suppress | escalate (WRONG) | suppress (OK) | service_restart on web-prod-02 |
| factrap_backup | suppress | suppress (OK) | escalate (WRONG) | io_anomaly on db-prod-01 |
| benign_deploy | suppress | escalate (WRONG) | suppress (OK) | service_restart on web-prod-02 |
| benign_deploy | suppress | escalate (WRONG) | suppress (OK) | service_restart on web-prod-01 |

## Where they disagree — `redteam_suite`

2 case(s) decided differently. A model that wins on aggregate but loses here is not clearly better.

| category | expected | `qwen3.5:4b` | `gemma4:12b` | event |
|---|---|---|---|---|
| correlation_distributed_bf | escalate | escalate (OK) | suppress (WRONG) | auth_failure on web-prod-01 |
| correlation_slow_scan | escalate | escalate (OK) | suppress (WRONG) | port_probe on api-prod-01 |

## Hard misses by model

Missed in every run. Per invariant #1 these are the only failures that are actually expensive.

- `gemma4:12b` / `redteam_suite` — **correlation_distributed_bf** (auth_failure on web-prod-01): distributed brute force; each event benign alone — Arbiter triages per-event, can't correlate
- `gemma4:12b` / `redteam_suite` — **correlation_slow_scan** (port_probe on api-prod-01): slow scan below any threshold; only visible in aggregate
