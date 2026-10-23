# Brief Arbiter

The authenticated dashboard has a **Brief Arbiter** navigation item at `/brief`
(or `/app/brief` in the public build). Administrators can write environment
context, review it, save it, and remove it. Analysts can read saved briefings.
The public landing makes no briefing requests.

This is an operator briefing form, not a model chat. Notes are saved verbatim;
the form does not infer assets, interpret instructions, or execute commands.
Choose one exact host identifier as reported in events. Wildcards and CIDRs are
rejected. Source-scoped legacy facts remain supported, but an operator briefing
cannot accidentally match another host through its event source name.

Optional asset role and priority updates are explicit. The default preserves
existing values. A note describing a VM does not lower its priority. Priority
choices use existing criticality multipliers: standard 1.3, important 1.6,
critical 2.0. Role and priority changes persist after a note expires or is removed;
the interface explains this before saving and removing.

Optional expiry is entered in the operator's local time and stored in UTC.
Expired notes remain visible for review but are excluded by `Memory.facts_for`.
Active notes enter the existing triage context path for future matching events.
Earlier verdicts are not recomputed. Briefings do not create response authority,
disable detection, or bypass deterministic guardrails.

The API adds three authenticated, CSRF-protected, admin-only POST routes:

- `/api/briefing/preview`: validates and returns a normalized draft without writes.
- `/api/briefing/save`: revalidates and atomically saves the note and optional asset changes.
- `/api/briefing/remove`: removes an operator-created note by integer ID.

Saved notes, authors, timestamps and expirations are returned by `/api/estate`.
Save/remove operations are recorded in the IAM audit trail. Existing memory
databases migrate in place; seeded/legacy notes cannot be removed through the
briefing endpoint. No runtime dependencies or external services were added.

UI tooling: the required `/ui` invocation was attempted, but the installed CLI
reported the command unavailable; a direct Magic generation attempt then failed
because the CLI OAuth session had expired. The view reuses existing dashboard
control/layout patterns. UI/UX Pro Max was read and its design-system, UX and
React searches were run; the refinement applied labels, focus indicators,
44px targets, announced feedback, review focus, and responsive layout. The
repository's restrained design takes precedence over its generic style output.

Validation: full Python suite (379 passed, 2 skipped, 25 subtests passed),
frontend production build, lint (two existing auth-module warnings), sample
seed/triage run, browser review/save/persistence checks, and a 375px layout check.
Vite reports its existing large-bundle advisory. No network scanner or model
conversation feature is included in this change.
