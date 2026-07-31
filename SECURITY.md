# Security policy

Arbiter is a security tool that runs inside customer networks with read access to
their logs and, when response is enabled, the ability to block addresses and lock
accounts. A vulnerability here is not academic. Reports are welcome and will be
taken seriously.

## Reporting a vulnerability

**Do not open a public issue for a security bug.**

Use GitHub's private vulnerability reporting — the **Security** tab of this
repository, then **Report a vulnerability**. That opens a private thread visible
only to the maintainers.

If that is unavailable to you, email **haryshwanair29@gmail.com** with `ARBITER
SECURITY` in the subject line.

Please include:

- what an attacker can achieve, not just what is technically wrong
- the version or commit you tested (`python -m arbiter --version`)
- steps to reproduce, ideally against a fresh `python -m arbiter seed`
- whether the issue requires an authenticated session, and at which role

## What to expect

Arbiter is a solo pre-release project, so response times are best-effort rather
than contractual:

| Stage | Target |
|---|---|
| Acknowledgement of your report | 3 working days |
| Initial assessment and severity | 10 working days |
| Fix or documented mitigation | depends on severity, discussed with you |

You will be credited in the release notes unless you would rather not be. There
is no bounty program.

## Scope

In scope — anything that breaks one of the project's stated guarantees:

- **Data leaving the network.** Any path by which event content, log data, or
  customer identifiers reach a third party. This is the product's central promise.
- **Authentication and session handling** in `arbiter/iam.py` and
  `arbiter/api/server.py`: session forgery, CSRF, privilege escalation from
  `analyst` to `admin`, lockout bypass, secret disclosure.
- **Verdict suppression.** Any input that causes a real attack to be silently
  suppressed — including prompt injection through event fields that defeats the
  guardrails in `arbiter/guardrails.py`. Missing a breach is the fatal failure
  mode; treat this as high severity.
- **Response actuator abuse.** Anything that induces an action outside the
  surgical, TTL-limited, dry-run-by-default policy in `arbiter/respond.py`, or
  that escalates an LLM-tier recommendation into an automatic execution.
- **The install and release path**: `packaging/install.sh`, `packaging/install.ps1`,
  `tools/build_release.py`, checksum verification bypass, or anything that lets a
  modified artifact pass as genuine.

Out of scope:

- Findings that require `--dev-accounts`, which resets passwords to known weak
  values and prints a warning saying so. It is a development flag and is never
  passed by the installed service.
- Findings that require `--demo-feed`, likewise development-only.
- Exposing the dashboard to the public internet. Arbiter is designed to be
  reachable only from inside the network it protects.
- Weaknesses of the local model itself (hallucination, poor judgement on a hard
  case) absent a concrete bypass. The guardrail layer exists precisely because
  the model is not trusted; a report showing it can be *bypassed* is in scope,
  a report that the model was merely wrong is a bug, not a vulnerability.
- Denial of service through sheer event volume. Known and documented — see the
  flood benchmark notes on queue behaviour.

## Supported versions

Pre-1.0. Only the latest release receives fixes. Upgrade with
`python arbiter-x.y.z.pyz --upgrade`, which preserves all databases.
