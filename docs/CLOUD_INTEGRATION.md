# Cloud integration: AWS MVP, Azure/GCP foundations

AWS retrieval is explicitly opt-in. It contacts AWS over the SDK's HTTPS APIs
to retrieve your security data, then keeps normalization, storage and triage
local. It never sends telemetry to external AI APIs. Disabling a connector stops
polling; existing local records remain subject to retention.

## AWS setup

For a source/virtual-environment install:

```powershell
python -m pip install -e ".[aws]"
```

The dependency-free release zipapp and embedded portable Python do not bundle
boto3. Use the source/venv deployment for this optional integration, or supply a
reviewed compatible SDK in your deployment runtime. Missing SDK produces a
connector Error; Arbiter does not auto-download dependencies.

Configure credentials outside Arbiter. The [standard SDK credential chain](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html)
supports environment credentials, shared AWS profiles and IAM roles. For an
existing named profile, set **Data Sources → AWS CloudTrail/GuardDuty → AWS
profile**, and select its region. An empty profile uses the default chain.
Credentials in a desktop session may not be available to a service account;
configure the account running Arbiter rather than pasting secrets in its UI.
The SDK also supports role/profile refreshing where configured. Connector
configuration accepts only region/profile/detector settings; access keys and
arbitrary SDK endpoint URLs are rejected. `.env.example` contains profile/region
names only; Arbiter does not load .env itself.

## CloudTrail behavior

This MVP polls [LookupEvents](https://docs.aws.amazon.com/boto3/latest/reference/services/cloudtrail/client/lookup_events.html)
for regional management-event history, starting with the last 15 minutes. It
paginates at no more than two calls per second, overlaps five minutes for delayed
delivery, deduplicates by eventID and checkpoints only after durable enqueue of
the completed window. Poll interval is 60 seconds, with a 200-page safety bound.
Lookup history is limited to 90 days and is not an S3 trail archive reader or
CloudTrail Lake query. It does not retrieve S3 object data events. To read another
region, configure another deployment/source extension; the present catalog has
one CloudTrail and one GuardDuty instance per Arbiter service.

ConsoleLogin success/failure, IAM modifications, role assumptions, logging
changes, security group changes, instance actions and S3 policy/configuration
changes normalize with action, account, region, identity, IP and request context.
CloudTrail often reports a service hostname instead of an IP; that stays in raw
data rather than being fabricated as an address. CreateUser is not proof of an
attack. Guardrails inspect request content and the brain applies criticality,
history, correlation and local-model judgment when needed.
Successful explicitly read-only Describe/List records are routine cloud context,
so high-volume inventory reads do not each invoke AI. Secret-value retrieval and
denied calls do not qualify for this profile; correlations revoke routine handling.

Least-privilege CloudTrail policy (this API does not support per-trail resource
scoping; constrain the allowed region):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "cloudtrail:LookupEvents",
    "Resource": "*",
    "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
  }]
}
```

## GuardDuty behavior

Arbiter reads [ListFindings](https://docs.aws.amazon.com/boto3/latest/reference/services/guardduty/client/list_findings.html)
and [GetFindings](https://docs.aws.amazon.com/boto3/latest/reference/services/guardduty/client/get_findings.html),
filtered by updatedAt with the same five-minute overlap. Source severity stays
0–10; finding type/title/description/resource/service remain available. Dedup
uses finding ID plus UpdatedAt, allowing later finding updates. An existing
detector is required. If you supply its ID, ListDetectors is unnecessary; with
an empty ID Arbiter discovers the region's detector. Arbiter does not enable
GuardDuty, change findings, create samples or incur detection setup on your behalf.

Use your actual account, region and detector ID in this read-only policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["guardduty:ListFindings", "guardduty:GetFindings"],
    "Resource": "arn:aws:guardduty:us-east-1:123456789012:detector/REPLACE_WITH_DETECTOR_ID"
  }]
}
```

Only if automatic detector discovery is needed, add a separate statement for
`guardduty:ListDetectors` on `*`, restricted by `aws:RequestedRegion`. Do not
grant write permissions, account-wide administrative access or AWS-managed full
access policies merely to run this reader. Review permissions for your AWS
partition and organization's boundary/SCP rules.

Findings are inputs, not blindly mirrored final alerts. High-severity findings
may escalate deterministically; lower-priority ones may enter local AI/context
review. Related CloudTrail activity can share a correlated incident. Five-minute
and record-count windows are an MVP foundation, not exhaustive cloud investigation.

## Offline testing and real account validation

Fixture tests and sample upload require no SDK or account. Upload a CloudTrail
object, `{"Records": [...]}` export, SDK CloudTrailEvent wrapper, GuardDuty object
or `{"Findings": [...]}` export, selecting its adapter if autodetection is unclear.
For actual account testing, choose approved read-only credentials, generate
ordinary authorized management activity or use existing findings, enable the
connector and inspect status/Live Events. This iteration's automated checks mock
AWS; they do not claim validation against a live AWS account.

## Deferred integrations

Registered Coming Soon sources are explicit scaffolding:

- AWS VPC Flow Logs: future parsed network-flow observations; no S3/CloudWatch
  retrieval transport implemented.
- AWS Security Hub: future ASFF findings adapter; no polling implemented.
- AWS CloudWatch Logs: future stream cursors and log normalization.
- Azure: Activity Logs, Defender for Cloud, Entra ID sign-in logs and NSG flow
  logs. Future identity uses Azure SDK/managed identity; no credentials/UI/API
  transport is currently implemented.
- GCP: Cloud Audit Logs, Security Command Center and VPC flow logs. Future
  identity uses application default credentials/service identities; no transport
  is currently implemented.

Each future adapter will normalize into SecurityEvent and enqueue, rather than
forking the analysis engine. Vendor-specific fields belong in metadata/raw_event.
