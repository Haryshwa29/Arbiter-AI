from arbiter.store import AuditStore


def test_dashboard_aggregates_use_covering_index(tmp_path):
    store = AuditStore(tmp_path / "audit.db")
    try:
        queries = [
            ("SELECT COUNT(*),SUM(decision='suppress'),SUM(decision='escalate') FROM audit WHERE kind='verdict'", ()),
            ("SELECT COUNT(*),SUM(decision='escalate'),SUM(tier='prefilter') FROM audit WHERE kind='verdict' AND ts>=?", ("2026-01-01",)),
        ]
        for sql, parameters in queries:
            plan = store.conn.execute("EXPLAIN QUERY PLAN " + sql, parameters).fetchall()
            assert any("COVERING INDEX" in row[3] for row in plan)
    finally:
        store.close()


def test_recent_feed_uses_id_range_without_sorting_history(tmp_path):
    store = AuditStore(tmp_path / "audit.db")
    try:
        for sql in (
            "SELECT * FROM audit WHERE kind='verdict' ORDER BY id DESC LIMIT 15",
            "SELECT * FROM audit WHERE kind='verdict' AND id>100 ORDER BY id ASC LIMIT 200",
        ):
            plan = [row[3] for row in store.conn.execute("EXPLAIN QUERY PLAN " + sql)]
            assert not any("TEMP B-TREE" in step for step in plan)
            assert any("idx_audit_kind_id" in step for step in plan)
    finally:
        store.close()
