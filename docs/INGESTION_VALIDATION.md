# Ingestion validation — 2026-10-09

Local environment: Windows, Python 3.14. Existing baseline: 152 unittest tests.

- 194 pytest tests passed; 3 subtests passed. This includes fixture normalization,
  all existing datasets, queue capacity/atomic import/restart recovery, routine
  filtering/guardrail compatibility, correlation, SDK credential-chain contracts,
  fake CloudTrail/GuardDuty pagination, syslog parsing and loopback acquisition,
  file cursor behavior and authenticated HTTP ingestion.
- 191 stdlib unittest checks completed in the normal runtime (189 passed,
  2 optional AWS SDK tests skipped because the base runtime has no boto3). Those passed in the
  isolated optional-SDK test environment used for pytest.
- Frontend TypeScript build, self-hosted build and public client/SSR/prerender
  build passed. Lint had no errors; three existing Fast Refresh warnings remain
  in auth/TransitField. No new frontend dependency was added.
- Headless Edge walkthrough passed login, empty Data Sources, upload preview and
  import, observation/alert details, real Windows System/Application collector
  enable/disable and local-only browser requests. Screenshots of all three new
  views and a narrower viewport were reviewed. Magic/ui-ux pro max were unavailable
  and not used; views reuse the existing design and StatTile.
- Two actual latest System/Application records normalized, queued and completed
  analysis as routine observations; zero processing failures. Their raw telemetry
  was confined to a temporary directory and removed by the test.
- Sysmon operational log could not be read on this machine; installation or
  permission/configuration verification remains a developer setup step. No
  privileged software was installed and no audit policy was changed.
- Existing CLI seed/run smoke passed (22 sample events, 14 escalations and
  8 suppressions with the mock backend), preserving history and guardrails.
- Release archive builds with the self-hosted dashboard and 8 prepared datasets;
  the packaged ingestion worker processed all 22 events from events.jsonl with
  zero failed analysis and no remaining queue depth.
- CI now covers both unittest and pytest, plus an optional SDK fixture-only job.
  No AWS credentials or external model service is required by CI.

AWS account retrieval, actual osquery installation, a real Suricata sensor and
clean-machine installer/portable live-collection validation have not been run
against provisioned infrastructure. Those connectors have working transport code
and fixture tests; these results do not claim a live account/sensor test. Zeek,
Azure/GCP and future AWS transports remain explicitly Coming Soon.

Source changes are local working-tree changes, with a matching source copy in
`C:\Users\harys\OneDrive\Documents\ChatGPT\Arbiter AI`. Both preserve the existing
local installer commit that is ahead of GitHub's current main. No customer DBs,
session secrets, cloud credentials or dependency runtimes are copied. See
INGESTION_ARCHITECTURE.md for at-least-once delivery, UDP syslog and correlation
window limitations.
