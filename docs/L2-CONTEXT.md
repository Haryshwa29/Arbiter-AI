# Giving the second reviewer useful security context

This upgrade is developed separately from the ongoing 2.6-million-record replay.
That replay keeps its original source and model settings. The changes here have
not been deployed to the installed dashboard or mixed into its results.

## What L2 can now read

- **The security tool's actual details:** reported CVE identifiers, MITRE ATT&CK
  technique identifiers, affected-package claims, version and vulnerability
  status, plus recorded flow counters, HTTP details and TLS details. A CVE
  mentioned in arbitrary log prose does not become a scanner finding.
- **Nearby login evidence:** up to eight native events from the same host,
  exact account and source address within the preceding five minutes. Future,
  unrelated, duplicate and replay/demo events are excluded. L1 opinions and
  dataset scoring labels do not supply this evidence.
- **A local security reference:** seven short guides for password attacks,
  account misuse, service discovery, web exploitation, DNS tunneling, sudo abuse
  and web shells, plus 1,782 factual entries from CISA's Known Exploited
  Vulnerabilities catalog, snapshot 2026.11.17.

Only relevant reference entries enter a review. The CVE index contains IDs,
vendor/product names and listing dates, not executable instructions or an entire
encyclopedia copied into every prompt. References and native observations remain
separate. No customer data leaves the machine and no online lookup runs during
triage. The snapshot's version, source URL and hash remain available for audit.

This is **not all known CVEs**, an installed-software inventory, or an automatic
affected-version matcher. A reported package/version is a source claim. CISA
membership does not prove this host is vulnerable or exploited; no CISA match
does not prove safety. Historical records do not receive a positive
known-exploited-as-of-event claim from a later KEV listing. The index is a current
snapshot, not a complete historical vulnerability feed.

## How the checks use it

Five matching native authentication failures remain protected even when a
subsequent login succeeds. A source-reported active CVE with a named package and
version stays visible for applicability/patch review, without asserting that an
attack succeeded. A CVE reference alone does not trigger that vulnerability rule.

Additional connection details do not, by themselves, explain a protocol
anomaly. The shared final guardrail retains an anomaly whose extra evidence
merely establishes that packets went both ways over TLS/HTTP. It covers L1 and
L2 suppression paths. Missing evidence, known risk and model failures continue
to retain warnings.

Matching login history and richer observations can inform eligible Gemma
reviews. They never automatically establish permission or harmlessness. Gemma
still needs a recorded ordinary explanation, checked facts, confidence at least
0.9, an accepted separate challenge and no shared final veto to quiet an alert.
The challenge is a second pass by Gemma, not an independent third model.

Only Qwen's successful model escalations enter the second-review route. L2
cannot repair an event that L1 already quieted. No device-action rights change.
The native containment mode keeps its existing evidence sources and policy.

## What the separate checks found

The first real-model development probe used three **synthetic controls**, with
fresh Qwen decisions. They are not public-dataset accuracy measurements. The
ongoing public replay shared the local model runner/GPU, so their timings are
not an isolated speed comparison.

Gemma quieted both an unexplained TLS anomaly and the same kind of anomaly with
a bare CVE reference. Its challenge accepted both. In each case its written
reason relied on a lack of exploit evidence instead of explaining the anomaly.
That is an unsupported suppression, even though these controls do not establish
that an attack occurred. Extra cybersecurity facts and a stronger prompt did
not cure this reasoning weakness.

The active-CVE/package/version control was retained by a deterministic rule.
After adding the protocol-context veto, a follow-up on the same three controls
retained all three without Gemma calls. It reused the frozen Qwen decisions and
tested the new guard; it was not another fresh model benchmark.

Software regression checks cover source-field extraction, exact matching and
time boundaries, future KEV listings, bare CVE references, both model passes,
final vetoes, and offline release/zipapp packaging. Full-suite results and the
original failed model proposals are recorded in
`evals/2026-11-18-l2-context-development`.

**No improvement percentage on public attack data is claimed for this upgrade.**
Next, re-read original raw public records through the new adapter, freeze a
separate comparison with genuinely available surrounding evidence, and test
malicious and ordinary lookalikes together. Old normalized samples cannot
recover source fields they previously discarded. If the original source lacks
the needed detail, it remains missing.

## Updating the reference without runtime network access

An operator can obtain a public CISA catalog on a connected preparation machine,
inspect it, and import a local file:

```text
python tools/build_security_knowledge.py --kev-file /path/to/kev.json --source-url https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json --out arbiter/data/kev.json
```

This importer reads a file; it does not download anything. Updates require a
new source/snapshot version and process restart. Evaluation manifests now include
the JSON reference data as well as Python sources, so resume refuses to combine
different knowledge snapshots.

The bundled source is CISA's [official GitHub mirror](https://github.com/cisagov/kev-data),
pinned to commit `2b7b13557a4f585212ef3c4725cd2d8f7281d61a`. The index preserves
factual fields only. Technique guides reference
[MITRE ATT&CK](https://attack.mitre.org/) as background, not incident attribution.
Native field handling follows the
[Suricata EVE specification](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)
and [Wazuh rule documentation](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html).
