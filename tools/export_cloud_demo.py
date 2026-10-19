"""Export synthetic website datasets, shared policy constants and Python parity cases.

No model calls or expected labels are exported. Run --check in CI to catch drift.
"""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from arbiter import guardrails
from arbiter.facts import render_all
from arbiter.ingestion.files import parse_upload
from arbiter.memory import Memory
from arbiter.prefilter import prefilter


def artifacts():
    assets = {"db-prod-01": 2, "web-prod-01": 1.6, "ci-runner-01": .8, "dev-laptop-42": .5}
    facts = [
        {"text": "backups run at 02:00 — nightly IO spike is normal", "host": "db-prod-01", "event_types": ["io_anomaly"]},
        {"text": "CI runner process churn is expected", "host": "ci-runner-01", "event_types": ["process_anomaly", "process_burst", "process_exec"]},
    ]
    names = ["_SENSITIVE_PORTS", "_SENSITIVE_SVC", "_BROAD_SCOPE", "_INTERNAL", "_EXTERNAL_SINKS", "_LOLBINS", "_LOLBIN_CTX", "_PRIV_MARKER_GROUPS"]
    config = {"assets": assets, "facts": facts, "constants": {name: getattr(guardrails, name) for name in names},
              "rules": [{"code": code, "name": name, "reason": reason} for code, name, reason, _ in guardrails.RULES]}
    memory = Memory(":memory:")
    try:
        for host, criticality in assets.items():
            memory.upsert_asset(host, criticality, "demo", True)
        for fact in facts:
            memory.add_fact(fact["text"], scope=fact["host"], event_types=fact["event_types"])
        datasets, parity = {}, []
        paths = [*sorted((ROOT / "samples").glob("*.jsonl")), *sorted((ROOT / "samples/demo_cases/Active").glob("*.json"))]
        for path in paths:
            parsed = parse_upload(path.name, path.read_text(encoding="utf-8"))
            if parsed.invalid_events:
                raise ValueError(f"Invalid sample records in {path.name}")
            name = ("case:" if path.suffix == ".json" else "") + path.name
            events = []
            for telemetry in parsed.events:
                event = telemetry.to_event()
                raw = telemetry.raw_event
                if not isinstance(raw, dict) or not raw.get("timestamp"):
                    event.timestamp = "2026-01-01T00:00:00+00:00"
                data = {"source_type": event.source, "hostname": event.host, "event_type": event.event_type,
                        "message": event.message, "severity": event.severity, "timestamp": event.timestamp, "fields": event.fields}
                events.append(data)
                hit = guardrails.guardrail_check(event)
                pre = prefilter(event, memory)
                parity.append({"event": data, "guardrail": asdict(hit) if hit else None, "score": pre.score,
                               "decision": pre.decision.value, "facts": render_all(memory.facts_for(event.host, event.source), event)})
            datasets[name] = events
        encode = lambda value: json.dumps(value, ensure_ascii=False, indent=2)
        return {
            "frontend/server/demoPolicyConfig.js": "export default " + encode(config) + ";\n",
            "frontend/src/lib/cloudDemoSamples.ts": "export const sampleDatasets: Record<string, unknown[]> = " + encode(datasets) + ";\n",
            "frontend/scripts/fixtures/policy-parity.json": encode(parity),
        }
    finally:
        memory.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for name, content in artifacts().items():
        path = ROOT / name
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8-sig") != content:
                raise SystemExit(f"Regenerate hosted demo exports: python tools/export_cloud_demo.py ({name})")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content.encode("utf-8"))
    print("Hosted demo exports match Python policy" if args.check else "Exported hosted demo datasets and policy fixtures")


if __name__ == "__main__":
    main()
