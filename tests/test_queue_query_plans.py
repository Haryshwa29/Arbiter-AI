from datetime import datetime, timedelta, timezone
from arbiter.ingestion.schema import SecurityEvent
from arbiter.ingestion.store import EventBuffer
from arbiter.ingestion.response_workflow import ResponseWorkflow
from arbiter.store import AuditStore


def test_claim_uses_ordered_identity_lookup_and_keeps_fifo_fairness(tmp_path):
    buffer = EventBuffer(tmp_path / "events.db")
    try:
        older = SecurityEvent(source_type="sysmon", hostname="host", event_type="process_exec", message="older")
        urgent = SecurityEvent(source_type="sysmon", hostname="host", event_type="process_exec", message="urgent", severity=10)
        future = SecurityEvent(source_type="sysmon", hostname="host", event_type="process_exec", message="future", severity=10)
        buffer.enqueue(older)
        buffer.enqueue(urgent)
        buffer.enqueue(future, due_at=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat())
        statements = []
        buffer.conn.set_trace_callback(statements.append)
        assert buffer.claim()["event_id"] == urgent.event_id
        candidate = next(sql for sql in statements if sql.startswith("SELECT id FROM telemetry"))
        plan = str(buffer.conn.execute("EXPLAIN QUERY PLAN " + candidate).fetchall())
        details = [r[3] for r in buffer.conn.execute("EXPLAIN QUERY PLAN " + candidate)]
        assert not any("TEMP B-TREE" in detail for detail in details), plan
        buffer._claims = 99
        assert buffer.claim()["event_id"] == older.event_id
        assert buffer.claim() is None  # future work must not run early
    finally:
        buffer.close()


def test_scheduler_scan_does_not_need_payload_pages(tmp_path):
    buffer = EventBuffer(tmp_path / "events.db")
    audit = AuditStore(tmp_path / "audit.db")
    workflow = ResponseWorkflow(buffer, audit)
    try:
        statements = []
        buffer.conn.set_trace_callback(statements.append)
        workflow.tick()
        query = next(sql for sql in statements if sql.startswith("SELECT event_id FROM telemetry"))
        details = [r[3] for r in buffer.conn.execute("EXPLAIN QUERY PLAN " + query)]
        assert any("idx_l1_response_scan_cover" in detail for detail in details)
        assert not any("TEMP B-TREE" in detail for detail in details)
    finally:
        workflow.close()
        buffer.close()
        audit.close()
