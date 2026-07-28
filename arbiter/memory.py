"""Per-company memory layer — local, private, human-readable.

Adaptation through context, not weights (see CONCEPT.md §2). SQLite so the
customer can literally open the file and see why Arbiter believes what it
believes: asset criticality, historical verdicts per alert signature, and
learned environment facts.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path

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
_FACT_SCOPE_COLUMNS = ("f_user", "f_path", "f_process", "f_events", "f_window")


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
        with self._lock:
            self.conn.executescript(_SCHEMA)
            self._migrate()
            self.conn.commit()

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
    def record_verdict(self, verdict: Verdict) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO verdict_history (signature, decision, ts) VALUES (?,?,?)",
                (verdict.signature, verdict.decision.value, verdict.timestamp),
            )
            self.conn.commit()

    def history(self, signature: str) -> SignatureHistory:
        with self._lock:
            rows = self.conn.execute(
                "SELECT decision, human_label FROM verdict_history WHERE signature=?",
                (signature,),
            ).fetchall()
        h = SignatureHistory(total=len(rows))
        for decision, label in rows:
            if decision == "suppress":
                h.suppressed += 1
                if label == "overruled":
                    h.overruled += 1        # we suppressed a real attack
            else:
                h.escalated += 1
                if label == "overruled":
                    h.false_alarms += 1     # we cried wolf on benign activity
        return h

    def label_verdicts(self, signature: str, label: str) -> None:
        """Human feedback loop: mark past verdicts confirmed/overruled."""
        with self._lock:
            self.conn.execute(
                "UPDATE verdict_history SET human_label=? WHERE signature=?",
                (label, signature),
            )
            self.conn.commit()

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
                "FROM facts WHERE scope IN (?,?,'*')", (host, source)
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
                "f_window FROM facts ORDER BY id"
            ).fetchall()
        return [{"id": i, "scope": s, "fact": f, "user": u, "path": p,
                 "process": pr, "event_types": [t for t in ev.split(",") if t],
                 "window": w}
                for i, s, f, u, p, pr, ev, w in rows]

    def close(self) -> None:
        with self._lock:
            self.conn.close()
