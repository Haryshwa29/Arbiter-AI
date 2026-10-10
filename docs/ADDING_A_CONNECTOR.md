# Adding a connector without changing the brain

1. Create an adapter module under `arbiter/ingestion/collectors`. Extend
   `Collector` and implement `collect()` plus `normalize()` (or register a
   normalizer used by the default implementation). Accept config and checkpoint
   in the constructor. Optional SDK imports belong inside enabled code paths.
2. Yield raw records from `collect()`. Advance each cursor **after** its yield:
   the service durably enqueues before resuming your generator. A queue-full
   exception must leave the unaccepted record available on the next poll. After
   a complete page/window, update checkpoint. Duplicate delivery is acceptable;
   use stable identities to deduplicate. Do not swallow BufferFull in your
   transport or advance past it.
3. Convert source records to `SecurityEvent`. Use UTC timestamp conversion,
   source severity in 0–10, useful host/account/user/process/network fields,
   `raw_event` and source-specific metadata. Never treat an event ID alone as
   malicious. Missing optional fields are allowed. Model context should be a
   bounded normalized summary, not a giant raw record. Stable source event IDs
   should be namespaced with `normalization.identity`; updates to findings need
   an updated-at component. Do not construct a triage engine in your collector.
4. Register a `ConnectorSpec` in `default_registry()` (or pass a custom Registry
   to IngestionService). Supply a name, label, category, factory, adapter name,
   reviewed default configuration and honest description. Add config validation
   for your new source to Registry.validate. Unknown config keys are rejected;
   never add secrets to the UI/config schema. For a future transport set
   `implemented=False` and use FutureCollector; it will show Coming Soon and
   reject enable requests.
5. Write fixture mapping/malformed-input tests and mock acquisition/pagination,
   retry/checkpoint/stop tests. Add a pipeline test proving routine observations
   and noteworthy activity take the common path. Keep CI credential-free and
   platform-independent. Make errors generic; no request/credential exception
   text. Observe timeouts and check stop_event between batches.
6. Document setup, access scope, data flow, security assumptions and limitations
   in CONNECTORS.md. Register minimal optional dependencies in pyproject only if
   necessary; do not introduce a mandatory vendor dependency to the core.

Minimal shape:

```python
from arbiter.ingestion.base import Collector
from arbiter.ingestion.schema import SecurityEvent
from arbiter.ingestion.normalization import identity

class ExampleCollector(Collector):
    interval = 10

    def collect(self):
        # read_page is your bounded, timed transport implementation.
        for raw in self.read_page(self.checkpoint.get("cursor")):
            yield raw
            self.checkpoint["cursor"] = raw["cursor"]

    def normalize(self, raw):
        return SecurityEvent(
            source_type="example", hostname=raw["host"],
            event_type="network_context", event_category="network",
            message=raw["summary"], severity=raw["severity"],
            event_id=identity("example", raw["id"]),
            timestamp=raw["timestamp"], raw_event=raw,
            metadata={"normalized_by": "example"},
        )
```

No change to `TriageEngine`, `AuditStore`, existing datasets, response actuator,
or vendor-specific analysis branch is necessary. A new well-justified routine
profile can be added to the deterministic prefilter with safety tests; it must
respect guardrails and correlation. Unknown profiles conservatively use existing
triage rather than claiming to filter safely. More sources such as Wazuh, Elastic,
Sentinel, EDR, firewalls and honeypots fit this same contract.
