import json
import sqlite3
from unittest.mock import Mock

from arbiter.ingestion.schema import SecurityEvent
from arbiter.ingestion.service import IngestionService
from arbiter.ingestion.store import EventBuffer, SCHEMA
from arbiter.memory import Memory
from arbiter.store import AuditStore


def test_lightweight_health_never_runs_dashboard_scans(tmp_path):
    memory = Memory(tmp_path / "memory.db")
    audit = AuditStore(tmp_path / "audit.db")
    service = IngestionService(tmp_path / "events.db", memory, audit)
    try:
        service.buffer.metrics = Mock(side_effect=AssertionError("health must not scan history"))
        service.buffer.connector_stats = Mock(side_effect=AssertionError("health must not scan sources"))
        state = service.status(include_metrics=False)
        assert state["backend"] == "mock"
        assert state["connectors"]
    finally:
        service.stop()
        memory.close()
        audit.close()


def test_materialized_backend_migration_and_metrics_without_analysis_reads(tmp_path):
    path = tmp_path / "old.db"
    connection = sqlite3.connect(path)
    connection.executescript(SCHEMA.replace(", analysis_backend TEXT", ""))
    for index, backend in enumerate(("rules-only-policy", "ollama", "")):
        event = SecurityEvent("test", "pc", "test", "owned fixture")
        connection.execute("INSERT INTO telemetry(event_id,received_at,timestamp,source,host,severity,category,username,src_ip,dst_ip,connector,cloud_account,payload,state,due_at,analysis,decision,tier,priority) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event.event_id, event.received_at, event.timestamp, "test", "pc", 1, "test", "", "", "", "api", "", event.to_json(), "done", event.timestamp,
             json.dumps({"decision": "escalate", "tier": "llm", "backend": backend}), "escalate", "llm", 1))
    connection.commit()
    connection.close()
    buffer = EventBuffer(path)
    try:
        # Reject reading large analysis payloads during status aggregation.
        def authorize(action, table, column, database, trigger):
            if action == sqlite3.SQLITE_READ and table == "telemetry" and column in {"analysis", "payload"}:
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        buffer.conn.set_authorizer(authorize)
        metrics = buffer.metrics("live")
        assert metrics["events_escalated_to_ai"] == 2
        assert metrics["events_handled_deterministically"] == 1
        assert metrics["alerts_created"] == 3
        buffer.conn.set_authorizer(None)
        event = SecurityEvent("test", "pc", "new", "new owned fixture")
        buffer.enqueue(event)
        row = buffer.claim()
        buffer.finish(row["id"], {"decision": "suppress", "tier": "llm", "backend": "rules-only-policy"}, [], 1)
        assert buffer.metrics()["events_handled_deterministically"] == 2
    finally:
        buffer.close()
