# Remember routine repeats without exempting a computer

When Qwen safely suppresses an event at confidence at least 0.9, Arbiter can
remember that exact pattern for the L1 pre-filter. When Gemma independently
suppresses an escalation, passes its separate challenge and the final checks,
Arbiter can remember it for the L2 pre-filter. A matching later event stays
auditable but avoids that stage's model calls. Gemma's memory never teaches L1
to skip Qwen; only eligible Qwen escalations enter L2.

This is local SQLite memory, not model training. It begins empty. It does not
retroactively treat earlier unannotated public records as verified benign.
Native Sysmon process execution keeps its existing stricter path: five real
model assessments and the exact process/hash/user/parent/environment scope.
The new shortcut does not reduce that requirement at either level.

| Match requirement | Everyday meaning |
|---|---|
| Model, source and real agent identity | One model or computer cannot silently approve another. |
| Signature plus event content | Same broad category alone is insufficient. |
| Recorded command, user, paths, endpoints, rule and raw details | A changed observation needs normal review. |
| Asset importance and environment facts | Changed environment context invalidates the shortcut. |
| No correlation or related-login evidence | Newly connected risk needs investigation. |
| Safety checks before and after the shortcut | Protected findings cannot inherit a suppression. |

Only envelope times/IDs and Wazuh's repeat counter are ignored; log text is not
rewritten into broad templates. A timestamp inside free-form log text therefore
prevents a match. This conservative first version may find fewer repeats than a
human would group together. It does not batch unrelated events, generalize URLs,
ignore changed process IDs, or suppress every alert under a shared host label.

A shortcut lasts **one hour or 25 matches**, whichever comes first. Hits do not
renew it or teach another shortcut. Afterwards the ordinary rules/model route
decides again. Only a fresh qualifying model decision can renew it. Original
decision, reason, origin event and match number are recorded. Memory survives
restart, but old entries expire by wall-clock time. Models with the same tag
should have memory cleared/revoked when their underlying weights are replaced.

Human-overruled signature feedback revokes its saved shortcuts. Rejecting an L2
suppression revokes that exact L2 pattern and keeps the warning visible; an
automatic model decision cannot reactivate the rejected key. Changed risk that
passes through the model and is escalated also revokes a matching existing key.
Uploaded files, API submissions, demo and replay connectors cannot teach or use
these live shortcuts. Context is evidence to check, not authorization.

Data Sources lists active pattern counts and repeat matches separately for L1
and L2. Events still enter the durable queue individually: this is repeated-model
work avoidance, not bulk log deletion or a new containment permission.

## What the stopped public run can tell us

The frozen 26,002 records have four normalized signatures under the shared host
label `wazuh-client`: 13,959 authentication successes, 6,186 other security
findings, 5,517 network alerts and 340 authentication failures. The raw data has
**11 distinct agent IDs/IPs and 22 native rule IDs**. Several underlying machine
names also appear in source log headers. One normalized label is not proof of
one monitored computer. Raw agent identity remains part of every learned match.

That run created empty history for each record, so it did not measure learning,
grouping or five-worker throughput. Existing raw hashes and decisions stay frozen.
A faster time per repeat is plausible because a SQLite lookup avoids inference,
but we have no measured percentage improvement or new attack-accuracy claim.

## Next test

Measure cold-start and warmed memory separately on a chronological stream with
attack annotations and multiple real agent identities. Learn only from earlier
records; never use future records or labels as context. Compare identical
hardware/model settings with learning disabled and enabled. Report model calls
avoided, patterns/hits/expiry, throughput, median/p95 end-to-end latency, benign
warning rate and missed attack labels. Include changed-user/command/destination,
cross-host, repeated-login attack, model-error and human-revocation lookalikes.

Model confidence is not a verified probability. A wrong high-confidence
suppression can be repeated within the bounded window. Exact matching, expiry,
revocation and guardrails limit that risk; they do not establish production safety.
