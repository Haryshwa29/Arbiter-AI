"""Per-company memory layer — local, private, human-readable.

Adaptation through context, not weights (see CONCEPT.md §2). SQLite so the
customer can literally open the file and see why Arbiter believes what it
believes: asset criticality, historical verdicts per alert signature, and
learned environment facts.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from datetime import datetime, timezone

from .facts import ScopedFact
from .schema import Verdict

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    host        TEXT PRIMARY KEY,
    criticality REAL NOT NULL DEFAULT 1.0,   -- 0.1 (lab box) – 2.0 (crown jewels)
    role        TEXT DEFAULT '',             -- e.g. "prod db", "ci runner"
    confirmed   INTEGER DEFAULT 0            -- human-confirmed criticality?
);

CREATE TABLE IF NOT EXISTS verdict_history (
    signature   TEXT NOT NULL,
    decision    TEXT NOT NULL,               -- escalate | suppress
    human_label TEXT DEFAULT '',             -- confirmed | overruled | ''
    ts          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_sig ON verdict_history (signature);
CREATE INDEX IF NOT EXISTS idx_history_counts ON verdict_history(signature,decision,human_label);

CREATE TABLE IF NOT EXISTS facts (
    id      INTEGER PRIMARY KEY,
    scope   TEXT NOT NULL DEFAULT '*',       -- host, source, or '*'
    fact    TEXT NOT NULL,                   -- "backups run at 02:00 — IO spike is normal"
    -- Optional scope constraints (the fact-overreach fix): a fact covers
    -- ONLY the behavior these name. Discrete columns, not a JSON blob, so
    -- the customer can read their own facts straight out of the table.
    f_user      TEXT DEFAULT '',             -- acting user the fact covers
    f_path      TEXT DEFAULT '',             -- path prefix the fact covers
    f_process   TEXT DEFAULT '',             -- tool/process the fact covers
    f_events    TEXT DEFAULT '',             -- comma-separated event types
    f_window    TEXT DEFAULT ''              -- "HH:MM-HH:MM" time-of-day
);
"""

# Columns added after the first release; applied to pre-existing DBs.
_FACT_SCOPE_COLUMNS = ("f_user", "f_path", "f_process", "f_events", "f_window",
                       "created_by", "created_at", "expires_at")


@dataclass
class SignatureHistory:
    total: int = 0
    suppressed: int = 0
    escalated: int = 0
    # Direction of a human overrule matters (feedback-loop fix):
    overruled: int = 0      # overruled SUPPRESSIONS — missed attacks; boost
    false_alarms: int = 0   # overruled ESCALATIONS — benign; decay, not boost

    @property
    def false_positive_rate(self) -> float:
        """Fraction of this signature judged benign: suppressions plus
        escalations a human overruled as false alarms."""
        return ((self.suppressed + self.false_alarms) / self.total
                if self.total else 0.0)


class Memory:
    def __init__(self, db_path: str | Path = "arbiter_memory.db") -> None:
        # check_same_thread=False + a lock around every use, matching
        # store.py: ThreadingHTTPServer serves each request on its own
        # thread, and the demo feeder / triage engine can write from yet
        # another. A bare check_same_thread=False without the lock would
        # trade a loud cross-thread crash for a silent interleaved-write
        # race — worse, since this is the layer the analyst's judgment
        # accumulates in.
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._lock = threading.Lock()
        self._history_cache = {}
        with self._lock:
            self.conn.executescript(_SCHEMA)
            self._migrate()
            self.conn.commit()
            self._history_version = self.conn.execute("PRAGMA data_version").fetchone()[0]

    def _migrate(self) -> None:
        # Caller already holds self._lock.
        have = {row[1] for row in
                self.conn.execute("PRAGMA table_info(facts)").fetchall()}
        for col in _FACT_SCOPE_COLUMNS:
            if col not in have:
                self.conn.execute(
                    f"ALTER TABLE facts ADD COLUMN {col} TEXT DEFAULT ''")

    # -- assets ------------------------------------------------------------
    def upsert_asset(self, host: str, criticality: float, role: str = "",
                     confirmed: bool = False) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO assets (host, criticality, role, confirmed) VALUES (?,?,?,?) "
                "ON CONFLICT(host) DO UPDATE SET criticality=?, role=?, confirmed=?",
                (host, criticality, role, int(confirmed),
                 criticality, role, int(confirmed)),
            )
            self.conn.commit()

    def asset_criticality(self, host: str) -> float:
        """Unknown assets get 1.3, not 1.0 — an unrecognized machine emitting
        alerts is itself suspicious (triggers a micro-rescan in the full product)."""
        with self._lock:
            row = self.conn.execute(
                "SELECT criticality FROM assets WHERE host=?", (host,)
            ).fetchone()
        return row[0] if row else 1.3

    def is_known_asset(self, host: str) -> bool:
        with self._lock:
            row = self.conn.execute(
                "SELECT 1 FROM assets WHERE host=?", (host,)
            ).fetchone()
        return row is not None

    def list_assets(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT host, criticality, role, confirmed FROM assets ORDER BY host"
            ).fetchall()
        return [{"host": h, "criticality": c, "role": r, "confirmed": bool(cf)}
                for h, c, r, cf in rows]

    # -- verdict history ---------------------------------------------------
    def record_verdict(self, verdict: Verdict, context_signature=None) -> None:
        with self._lock:
            self._refresh_history_cache()
            signatures = [verdict.signature]
            if isinstance(context_signature, str) and context_signature.startswith(verdict.signature + ":ctx:"):
                signatures.append(context_signature)
            self.conn.executemany(
                "INSERT INTO verdict_history (signature, decision, ts) VALUES (?,?,?)",
                [(signature, verdict.decision.value, verdict.timestamp) for signature in signatures],
            )
            self.conn.commit()
            for signature in signatures:
                cached = self._history_cache.get(signature)
                if cached:
                    cached.total += 1
                    if verdict.decision.value == "suppress": cached.suppressed += 1
                    else: cached.escalated += 1

    def _refresh_history_cache(self):
        version = self.conn.execute("PRAGMA data_version").fetchone()[0]
        if version != self._history_version:
            self._history_cache.clear()
            self._history_version = version

    def history(self, signature: str) -> SignatureHistory:
        with self._lock:
            self._refresh_history_cache()
            if signature not in self._history_cache:
                row = self.conn.execute("SELECT COUNT(*),SUM(decision='suppress'),SUM(decision!='suppress'),"
                    "SUM(decision='suppress' AND human_label='overruled'),SUM(decision!='suppress' AND human_label='overruled') "
                    "FROM verdict_history WHERE signature=?", (signature,)).fetchone()
                if len(self._history_cache) >= 4096: self._history_cache.clear()
                self._history_cache[signature] = SignatureHistory(*(value or 0 for value in row))
            return replace(self._history_cache[signature])

    def label_verdicts(self, signature: str, label: str) -> None:
        """Human feedback loop: mark past verdicts confirmed/overruled."""
        with self._lock:
            self.conn.execute(
                "UPDATE verdict_history SET human_label=? WHERE signature=? OR substr(signature,1,?)=?",
                (label, signature, len(signature + ":ctx:"), signature + ":ctx:"),
            )
            self.conn.commit()
            self._history_cache.clear()

    # -- environment facts ---------------------------------------------------
    def add_fact(self, fact: str, scope: str = "*", *, user: str = "",
                 path: str = "", process: str = "",
                 event_types: tuple[str, ...] | list[str] = (),
                 window: str = "") -> None:
        """Record a fact, optionally with the scope it actually covers.

        Unscoped facts behave as before. Scoped facts get code-side scope
        checking before the LLM sees them (see facts.py) — a fact only
        excuses the exact behavior it names.
        """
        with self._lock:
            self.conn.execute(
                "INSERT INTO facts (scope, fact, f_user, f_path, f_process, "
                "f_events, f_window) VALUES (?,?,?,?,?,?,?)",
                (scope, fact, user, path, process, ",".join(event_types), window),
            )
            self.conn.commit()

    def facts_for(self, host: str, source: str) -> list[ScopedFact]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT fact, scope, f_user, f_path, f_process, f_events, f_window "
                "FROM facts WHERE (scope=? OR (created_by='' AND scope IN (?,'*'))) AND "
                "(expires_at='' OR expires_at>?)",
                (host, source, datetime.now(timezone.utc).isoformat())
            ).fetchall()
        return [ScopedFact(text=r[0], host=r[1], user=r[2] or "",
                           path=r[3] or "", process=r[4] or "",
                           event_types=tuple(t for t in (r[5] or "").split(",")
                                             if t),
                           window=r[6] or "")
                for r in rows]

    def list_facts(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, scope, fact, f_user, f_path, f_process, f_events, "
                "f_window, created_by, created_at, expires_at FROM facts ORDER BY id"
            ).fetchall()
        return [{"id": i, "scope": s, "fact": f, "user": u, "path": p,
                 "process": pr, "event_types": [t for t in ev.split(",") if t],
                 "window": w, "created_by": author, "created_at": created,
                 "expires_at": expires}
                for i, s, f, u, p, pr, ev, w, author, created, expires in rows]

    def save_briefing(self, briefing: dict, actor: str) -> int:
        """Atomically save reviewed context and optional explicit asset changes."""
        host = briefing["host"]
        with self._lock, self.conn:
            current = self.conn.execute(
                "SELECT criticality, role, confirmed FROM assets WHERE host=?", (host,)
            ).fetchone()
            priority = briefing["priority"]
            if briefing["role"] or priority != "unchanged":
                criticality = {"standard": 1.3, "important": 1.6, "critical": 2.0}.get(
                    priority, current[0] if current else 1.3)
                role = briefing["role"] or (current[1] if current else "")
                self.conn.execute(
                    "INSERT INTO assets(host,criticality,role,confirmed) VALUES(?,?,?,1) "
                    "ON CONFLICT(host) DO UPDATE SET criticality=excluded.criticality, "
                    "role=excluded.role, confirmed=1", (host, criticality, role))
            cursor = self.conn.execute(
                "INSERT INTO facts(scope,fact,created_by,created_at,expires_at) VALUES(?,?,?,?,?)",
                (host, briefing["fact"], actor, datetime.now(timezone.utc).isoformat(),
                 briefing["expires_at"]))
            return cursor.lastrowid

    def remove_briefing(self, fact_id: int) -> bool:
        with self._lock, self.conn:
            # Legacy/seed facts are managed separately; only operator briefings here.
            return self.conn.execute(
                "DELETE FROM facts WHERE id=? AND created_by!=''", (fact_id,)
            ).rowcount == 1

    def close(self) -> None:
        with self._lock:
            self.conn.close()
