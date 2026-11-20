# GPU crash investigation — November 19

Read-only investigation while the benchmark remains stopped at 17,612 saved
records. No model inference, driver change, deployment or restart was performed
for this investigation. Times below are local Eastern time (UTC minus five).

## AWS SDK status

Arbiter has an optional Boto3 integration for CloudTrail and GuardDuty in
`arbiter/ingestion/collectors/aws.py`, declared by the `aws` package extra.
Boto3 and Botocore 1.44.6 are installed in the separate validation environment
`output/ponytail-review-2026-11-19/aws-test-runtime`. Both AWS SDK contract tests
pass there with mocked sessions. This verifies client construction and configuration,
not a real AWS account, permissions or collection.

The default Python interpreter does not have Boto3 installed. The installed
desktop runtime was not upgraded. The optional AWS SDK does not manage CUDA,
GPU memory or local model execution and cannot repair this GPU failure.

## What the saved evidence shows

| Local time | Evidence | Meaning |
|---|---|---|
| 04:11:24.413 | Windows System event 40113, NVIDIA `nvlddmkm`, event 13: `Graphics FECS Exception: Logging error 0x2`. Event 40114 follows with NVIDIA event 153. | The NVIDIA driver recorded a GPU exception before the request failed. This text alone does not identify the faulty instruction or its cause. |
| Around 04:11:34 | Ollama `server.log` lines 2936524–2936527: `unspecified launch failure` in the CUDA 13 backend, reported by `cudaStreamSynchronize`. HTTP 500 follows at line 2936536. | The model runner encountered a GPU execution failure. A synchronization call can report an error from earlier asynchronous GPU work; it does not identify the original failing kernel. |
| 04:11:34.465–34.467 | Windows System events 40115 and 40116, NVIDIA event 153. | Further GPU errors coincide with the failed request. |
| 04:11:36 and 04:11:54 | Windows Application/WER event 1001: `LiveKernelEvent` 141, bucket `LKD_0x141_Tdr:C_AppFault_IMAGE_nvlddmkm.sys_Ada`. | Windows detected a GPU engine that did not respond in time. The two reports refer to the same report ID and dump, not two proven separate hangs. |
| 04:11:35 | Ollama logs `llama-server terminated`, exit `0xc0000409`. | The runner terminated. The generic Windows status wording about a stack buffer does not establish a separate exploitable buffer defect. |
| 14:53–14:54 | Windows `C:\Windows\INF\setupapi.dev.log` records installation of NVIDIA package `oem117.inf`, version `32.0.16.2124` (621.24). | The current driver was installed hours after the benchmark crash. The benchmark's saved hardware snapshot reports 617.42. No driver update was made by this investigation. |
| Around 16:42 | Ollama lines 3309701–3309706: `MUL_MAT failed`, `CUDA error: out of memory`, scheduler `runtime OOM detected`, HTTP 500 and runner termination. WER records a matching application failure. | A later, separate failure explicitly exhausted GPU memory after the driver update. It is not evidence that the earlier 04:11 timeout was also an out-of-memory failure. The benchmark remained stopped. |

Windows event timestamps and Ollama output are not a perfectly ordered execution
trace; application crash reporting can precede buffered log output. The records
establish the common failure interval, not instruction-by-instruction ordering.

## Why this is different from the earlier long run

The failed checkpoint used parallel pipeline stages and much more Gemma work:
194 L2 review attempts versus 43 in the older 26,002-record run. Saved Ollama
output near the failure interleaves the Qwen and Gemma processing profiles.
The dashboard was properly paused during this resumed segment, so its earlier
automatic restart does not explain the 04:11 failure.

Overlapping model work and GPU resource pressure are reasonable hypotheses to
test. The later explicit out-of-memory failure makes capacity a concrete concern.
Neither observation proves that overlap caused the earlier GPU timeout. A CUDA
backend/driver defect or a hardware stability problem remains possible.
Prompt-cache sizes printed in the log are not a measurement of free VRAM at the
crash, and no crash-time memory/temperature trace was retained. There is no basis
to claim overheating or exact memory exhaustion for the 04:11 event.

## What is fixed and what still needs testing

The source refinement handles an isolated model failure by retaining the alert
and continuing; three consecutive failures for one brain still stop the run.
That fixes the evaluation's premature shutdown policy. It does not repair a
GPU kernel or guarantee the model runner stays alive.

The smallest useful next experiment is a controlled comparison of one model
at a time, then both with serialized GPU calls, then overlapping calls, using
the same saved inputs and crash-time GPU memory/utilization sampling. The five
pipeline workers can remain independent while a shared GPU admission limit
controls how many model calls execute together. This is a proposed experiment,
not an installed change or a measured speed improvement. Context and prompt
batch size should be changed separately only if capacity testing requires it.
Do not raise Windows' GPU timeout as a substitute for establishing the cause.

The referenced kernel dump is protected: access to `LiveKernelReports` and
the archived kernel report was denied. No administrator launch was attempted.
The exact failing kernel, reason for the engine hang and hardware-versus-software
cause remain unresolved without dump analysis or a controlled reproduction.

## Primary references

- [Microsoft: live dump 0x141 means a GPU engine failed to respond in time](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x141---video-engine-timeout-detected).
- [Microsoft: Windows timeout detection and recovery](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/timeout-detection-and-recovery).
- [NVIDIA: asynchronous execution and when GPU errors surface](https://docs.nvidia.com/cuda/cuda-programming-guide/02-basics/asynchronous-execution.html).
- [NVIDIA: CUDA launch-failure semantics](https://docs.nvidia.com/cuda/cuda-runtime-api/cuda_runtime_api/group__CUDART__TYPES.html).

These references interpret the local evidence; they do not prove a specific
upstream bug is responsible. No public report or Git push was made.
