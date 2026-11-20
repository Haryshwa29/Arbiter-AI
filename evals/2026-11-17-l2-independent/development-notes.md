# Development findings, kept separate from the scored test

These are diagnostic checks on previously seen public records. They reused the
older Qwen escalations and re-read the original AIT-ADS records through the updated
adapter. They are not a new accuracy benchmark. All four control records and the
other 412 previously sampled records were excluded from the new scored sample.

Several changes were developed together: the evidence presentation, the prompt,
the order of requested fields and the removal of Qwen's opinion text. This does
not isolate anchoring as the sole cause of the earlier all-escalate behavior.

Early blind-prompt checks produced ordinary-looking suppressions, but also
unsafe proposals for attack-annotated root-session and encoded-DNS records.
Another reply used invalid hypothesis references. Later replies contradicted
themselves by returning `decision=suppress` and `outlook=suspicious`. These were
failures during development, not successful results omitted from a score.

The resulting corrections were:

- Preserve older IDS endpoint tuples and DNS question arrays before analysis.
- Keep explicit sudo/root activity protected, including session closures.
- Retain encoded-looking DNS payloads, source-classified attacks, conflicting
  endpoint evidence and incompletely represented query sets.
- Ask for one classification, with a derived compatibility outlook. Keep the
  confidence, citation, challenge and shared final risk checks.
- Avoid another model call for isolated protocol/login records whose missing
  context prevents a justified resolution. This retains the warning cheaply;
  it does not claim that warning is an attack or that its noise was removed.

The final four controls are retained in `development-controls.jsonl`:

| Record | Publisher comparison | Final L2 result | Gemma called? |
|---|---|---|---|
| wheeler:2913 | No attack annotation | Quieted by an actual Gemma assessment and challenge | Yes |
| fox:12977 | No attack annotation | Retained because useful flow context is missing | No |
| harrison:12719 | DNS-theft annotation | Retained by the encoded-DNS evidence rule | No |
| russellmitchell:33193 | Privileged-command annotation | Retained by the sudo/root session rule | No |

This proves the requested routing can make a different real-model decision and
can protect the two diagnostic attack cases without paying for an LLM review.
It does not measure generalization, and the attack controls do not measure
Gemma's independent attack-recognition accuracy: rules retained them first.

Exact human-corrected history is tested separately with controlled software
fixtures. The public replay starts with empty history and does not demonstrate
that a company-specific learned profile reduces noise.

The updated source and model settings were frozen before scoring the new 192
records. No scored failures are retried until successful, and no rules are
changed in response to the scored outcomes.
