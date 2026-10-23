"""Operator context stays durable, scoped and revocable."""
import sqlite3
from datetime import datetime, timedelta, timezone

from arbiter.briefing import validate_briefing
from arbiter.memory import Memory


def test_briefing_persists_without_implicit_priority_change(tmp_path):
    path = tmp_path / "memory.db"
    memory = Memory(path)
    memory.upsert_asset("vm", 1.8, "production", True)
    draft = validate_briefing({"host": "vm", "fact": "This is a VM"})
    fact_id = memory.save_briefing(draft, "owner")
    memory.close()
    memory = Memory(path)
    try:
        assert memory.asset_criticality("vm") == 1.8
        assert memory.list_assets()[0]["role"] == "production"
        assert memory.facts_for("vm", "sysmon")[0].text == "This is a VM"
        assert memory.remove_briefing(fact_id)
        assert not memory.facts_for("vm", "sysmon")
    finally:
        memory.close()


def test_expired_context_never_reaches_analysis(tmp_path):
    memory = Memory(tmp_path / "memory.db")
    try:
        draft = validate_briefing({"host": "vm", "fact": "Temporary maintenance",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()})
        memory.save_briefing(draft, "owner")
        assert memory.facts_for("vm", "sysmon")
        memory.conn.execute("UPDATE facts SET expires_at='2000-01-01T00:00:00+00:00'")
        memory.conn.commit()
        assert not memory.facts_for("vm", "sysmon")
        assert memory.list_facts()[0]["fact"] == "Temporary maintenance"
    finally:
        memory.close()


def test_existing_database_migrates_without_losing_facts(tmp_path):
    path = tmp_path / "old.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE facts(id INTEGER PRIMARY KEY,scope TEXT,fact TEXT)")
    connection.execute("INSERT INTO facts(scope,fact) VALUES('*','Existing context')")
    connection.commit()
    connection.close()
    memory = Memory(path)
    try:
        assert memory.facts_for("vm", "sysmon")[0].text == "Existing context"
        assert memory.list_facts()[0]["created_by"] == ""
    finally:
        memory.close()
