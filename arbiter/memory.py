"""Per-company memory layer — local, private, human-readable.

Adaptation through context, not weights (see CONCEPT.md §2). SQLite so the
customer can literally open the file and see why Arbiter believes what it
believes: asset criticality, historical verdicts per alert signature, and
learned environment facts.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

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
    fact    TEXT NOT NULL                    -- "backups run at 02:00 — IO spike is normal"
);
"""


@dataclass
class SignatureHistory:
    total: int = 0
    suppressed: int = 0
    escalated: int = 0
    overruled: int = 0   # times a human overruled Arbiter — trust penalty

    @property
    def false_positive_rate(self) -> float:
        return self.suppressed / self.total if self.total else 0.0


class Memory:
    def __init__(self, db_path: str | Path = "arbiter_memory.db") -> None:
        self.conn = sqlite3.connect(str(db_path))
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # -- assets ------------------------------------------------------------
    def upsert_asset(self, host: str, criticality: float, role: str = "",
                     confirmed: bool = False) -> None:
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
        row = self.conn.execute(
            "SELECT criticality FROM assets WHERE host=?", (host,)
        ).fetchone()
        return row[0] if row else 1.3

    def is_known_asset(self, host: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM assets WHERE host=?", (host,)
        ).fetchone() is not None

    # -- verdict history ---------------------------------------------------
    def record_verdict(self, verdict: Verdict) -> None:
        self.conn.execute(
            "INSERT INTO verdict_history (signature, decision, ts) VALUES (?,?,?)",
            (verdict.signature, verdict.decision.value, verdict.timestamp),
        )
        self.conn.commit()

    def history(self, signature: str) -> SignatureHistory:
        rows = self.conn.execute(
            "SELECT decision, human_label FROM verdict_history WHERE signature=?",
            (signature,),
        ).fetchall()
        h = SignatureHistory(total=len(rows))
        for decision, label in rows:
            if decision == "suppress":
                h.suppressed += 1
            else:
                h.escalated += 1
            if label == "overruled":
                h.overruled += 1
        return h

    def label_verdicts(self, signature: str, label: str) -> None:
        """Human feedback loop: mark past verdicts confirmed/overruled."""
        self.conn.execute(
            "UPDATE verdict_history SET human_label=? WHERE signature=?",
            (label, signature),
        )
        self.conn.commit()

    # -- environment facts ---------------------------------------------------
    def add_fact(self, fact: str, scope: str = "*") -> None:
        self.conn.execute(
            "INSERT INTO facts (scope, fact) VALUES (?,?)", (scope, fact)
        )
        self.conn.commit()

    def facts_for(self, host: str, source: str) -> list[str]:
        rows = self.conn.execute(
            "SELECT fact FROM facts WHERE scope IN (?,?,'*')", (host, source)
        ).fetchall()
        return [r[0] for r in rows]

    def close(self) -> None:
        self.conn.close()
