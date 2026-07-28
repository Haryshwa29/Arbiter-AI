from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .schema import Event, Verdict

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'verdict',
    event_id TEXT, host TEXT, signature TEXT,
    decision TEXT, score REAL, tier TEXT,
    rationale TEXT, evidence TEXT, actor TEXT, detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit(decision);
CREATE INDEX IF NOT EXISTS idx_audit_host ON audit(host);
"""


class AuditStore:
    def __init__(self, db_path="arbiter_audit.db"):
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._lock = threading.Lock()

    def record_verdict(self, event, verdict):
        detail = {"source": event.source, "message": event.message,
                  "severity": event.severity, "fields": event.fields}
        row = {"ts": verdict.timestamp, "kind": "verdict", "event_id": event.id,
               "host": event.host, "signature": event.signature,
               "decision": verdict.decision.value, "score": verdict.score,
               "tier": verdict.tier.value, "rationale": verdict.rationale,
               "evidence": verdict.evidence, "actor": None,
               "detail": json.dumps(detail)}
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO audit (ts,kind,event_id,host,signature,decision,"
                "score,tier,rationale,evidence,actor,detail) VALUES "
                "(:ts,:kind,:event_id,:host,:signature,:decision,:score,:tier,"
                ":rationale,:evidence,:actor,:detail)", row)
            self.conn.commit()
        row["id"] = cur.lastrowid
        return row

    def record_iam(self, actor, action, detail=""):
        from datetime import datetime, timezone
        with self._lock:
            self.conn.execute(
                "INSERT INTO audit (ts,kind,actor,rationale,detail) VALUES (?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), "iam", actor, action, detail))
            self.conn.commit()

    def query(self, decision=None, host=None, tier=None, limit=100, offset=0):
        sql = "SELECT * FROM audit WHERE kind='verdict'"
        args = []
        if decision: sql += " AND decision=?"; args.append(decision)
        if host: sql += " AND host=?"; args.append(host)
        if tier: sql += " AND tier=?"; args.append(tier)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"; args += [limit, offset]
        with self._lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def lifetime_counts(self):
        with self._lock:
            r = self.conn.execute(
                "SELECT COUNT(*) t, SUM(decision='suppress') s, "
                "SUM(decision='escalate') e FROM audit WHERE kind='verdict'").fetchone()
        return {"triaged": r["t"] or 0, "suppressed": r["s"] or 0, "escalated": r["e"] or 0}

    def today_counts(self):
        from datetime import datetime, timezone
        day = datetime.now(timezone.utc).date().isoformat()
        with self._lock:
            r = self.conn.execute(
                "SELECT COUNT(*) t, SUM(decision='escalate') e, SUM(tier='prefilter') p "
                "FROM audit WHERE kind='verdict' AND ts >= ?", (day,)).fetchone()
        return {"today": r["t"] or 0, "escalated": r["e"] or 0, "prefilter": r["p"] or 0}

    def max_id(self):
        with self._lock:
            row = self.conn.execute("SELECT COALESCE(MAX(id), 0) FROM audit").fetchone()
        return row[0]

    def rows_since(self, last_id, limit=200):
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM audit WHERE kind='verdict' AND id>? "
                "ORDER BY id ASC LIMIT ?", (last_id, limit)).fetchall()
        return [dict(r) for r in rows]

    def acknowledge(self, row_id, actor):
        """Mark a verdict reviewed by `actor`. Returns False if no such row.

        Repurposes the `actor` column, which `record_verdict` always leaves
        NULL — a non-null actor on a verdict row means "reviewed by"."""
        with self._lock:
            cur = self.conn.execute(
                "UPDATE audit SET actor=? WHERE id=? AND kind='verdict'",
                (actor, row_id))
            self.conn.commit()
        if not cur.rowcount:
            return False
        self.record_iam(actor, "acknowledge", detail=f"audit id {row_id}")
        return True

    def day_buckets(self, hours=24):
        """Hourly verdict volume for the last `hours` hours, oldest first.

        Every hour in range is present (zero-filled) so a chart never has
        gaps just because nothing happened that hour."""
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        start = now - timedelta(hours=hours - 1)
        buckets = {start + timedelta(hours=i): {"escalated": 0, "suppressed": 0}
                  for i in range(hours)}
        with self._lock:
            rows = self.conn.execute(
                "SELECT ts, decision FROM audit WHERE kind='verdict' AND ts >= ?",
                (start.isoformat(),)).fetchall()
        for ts, decision in rows:
            try:
                dt = datetime.fromisoformat(ts).astimezone(timezone.utc)
            except ValueError:
                continue
            bucket = dt.replace(minute=0, second=0, microsecond=0)
            if bucket in buckets:
                key = "escalated" if decision == "escalate" else "suppressed"
                buckets[bucket][key] += 1
        return [{"bucket": k.isoformat(), **v} for k, v in sorted(buckets.items())]

    def prune(self, days=30):
        from datetime import datetime, timezone, timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            cur = self.conn.execute("DELETE FROM audit WHERE ts < ?", (cutoff,))
            n = cur.rowcount
            self.conn.commit()
        self.record_iam("system", "retention_prune", f"deleted {n} rows older than {days}d")
        return n

    def close(self):
        self.conn.close()
