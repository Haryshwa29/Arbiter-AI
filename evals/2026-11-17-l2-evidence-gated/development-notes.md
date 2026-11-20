# Why this is a follow-up, not a fresh accuracy benchmark

The original 192-record experiment is frozen in
`evals/2026-11-17-l2-independent`, source checkpoint
`c0f3f4a6da849a8428b3b02ad036341171732f11`. It excluded all 416 earlier
selected records. Its development failures and four selected controls remain
there and are not added to these scored totals.

That experiment appeared to quiet 13 warnings. Qualitative inspection found
11 lacked the DNS question itself. Gemma's assessment and its separate challenge
both accepted insufficient evidence: no demonstrated attack is not a demonstrated
benign explanation. Dataset label agreement alone did not validate those decisions.

The only subsequent runtime change is `L2_DNS_CONTEXT_MISSING`, applied through
the shared final gate and the L2 pre-filter. It retains DNS-query warnings when
the original data omits the actual queried name. A regression test verifies
the L1/shared veto and that L2 does not call Gemma for this case.

This run reused the complete frozen L1 decisions and audit bytes, checked their
input/model identities and checked every L1 decision against the current shared
gate. It made no new Qwen calls. The stricter L2 route ran again, with two real
Gemma assessments and their separate challenges. All 11 incomplete-query cases
now retain without inference; two records with complete queries were quieted.

These are already inspected records, not a new holdout. No attack-labelled
record reached Gemma. Zero missed attack labels is combined rule coverage on
this selected replay, not measured Gemma attack discrimination or production
readiness. The next independent evaluation must freeze richer evidence and new
scenarios before scoring, including malicious and ordinary lookalikes.
