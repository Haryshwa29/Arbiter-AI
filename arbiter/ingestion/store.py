"""Durable bounded SQLite buffer and event read model, single worker per DB."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from .schema import SecurityEvent, now, safe_json


class BufferFull(RuntimeError):
    pass


def event_priority(event, connector=None):
    from ..guardrails import guardrail_check
    from ..prefilter import routine_telemetry
    legacy = event.to_event()
    from .evidence import own_log_query
    if own_log_query(event, connector): legacy.fields["_collector_activity"] = True
    if guardrail_check(legacy): return max(event.severity, 9)
    # Drain cheap context between inference calls; correlation still runs later.
    return max(event.severity, 6.5 if routine_telemetry(legacy) else 0)


SCHEMA = """
CREATE TABLE IF NOT EXISTS telemetry (
 id INTEGER PRIMARY KEY, event_id TEXT UNIQUE NOT NULL,
 received_at TEXT NOT NULL, timestamp TEXT NOT NULL, source TEXT NOT NULL,
 host TEXT NOT NULL, severity REAL NOT NULL, category TEXT NOT NULL,
 username TEXT NOT NULL, src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL,
 connector TEXT NOT NULL, cloud_account TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
 due_at TEXT NOT NULL, analysis TEXT, related TEXT NOT NULL DEFAULT '[]',
 latency_ms REAL, error TEXT NOT NULL DEFAULT '', attempts INTEGER NOT NULL DEFAULT 0,
 decision TEXT, tier TEXT, priority REAL
);
CREATE INDEX IF NOT EXISTS idx_telemetry_due ON telemetry(state, due_at, id);
CREATE INDEX IF NOT EXISTS idx_telemetry_received ON telemetry(received_at);
CREATE INDEX IF NOT EXISTS idx_telemetry_source ON telemetry(source, host);
CREATE INDEX IF NOT EXISTS idx_telemetry_recent ON telemetry(state, timestamp, id);
CREATE INDEX IF NOT EXISTS idx_telemetry_connector_received ON telemetry(connector, received_at);
CREATE TABLE IF NOT EXISTS connectors (
 name TEXT PRIMARY KEY, enabled INTEGER NOT NULL, config TEXT NOT NULL,
 checkpoint TEXT NOT NULL DEFAULT '{}', errors INTEGER NOT NULL DEFAULT 0,
 error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS inventory (
 asset_id TEXT PRIMARY KEY, host TEXT NOT NULL, last_seen TEXT NOT NULL,
 context TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS ingestion_metrics (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS ingestion_settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incidents (
 incident_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 rule_name TEXT NOT NULL, event_ids TEXT NOT NULL
);
"""


class EventBuffer:
    def __init__(self, path, capacity=10000, retention_days=30):
        self.conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.capacity = capacity
        self.retention_days = retention_days
        self._claims = 0
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(SCHEMA)
            columns = {r[1] for r in self.conn.execute("PRAGMA table_info(telemetry)")}
            for name in ("decision", "tier", "priority"):
                if name not in columns:
                    self.conn.execute(f"ALTER TABLE telemetry ADD COLUMN {name} {'REAL' if name == 'priority' else 'TEXT'}")
            self.conn.execute("UPDATE telemetry SET decision=json_extract(analysis,'$.decision'), "
                              "tier=json_extract(analysis,'$.tier') WHERE state='done' AND analysis IS NOT NULL AND decision IS NULL")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_metrics ON telemetry(connector,state,decision,tier,latency_ms)")
            self.conn.execute("UPDATE telemetry SET priority=severity WHERE priority IS NULL")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_priority ON telemetry(state,priority DESC,due_at,id)")
            policy = self.conn.execute("SELECT value FROM ingestion_settings WHERE name='queue_priority_policy'").fetchone()
            if not policy or policy[0] != '4':
                last_id = 0
                while True:
                    rows = self.conn.execute("SELECT id,payload,connector FROM telemetry NOT INDEXED WHERE id>? AND state IN ('pending','processing') ORDER BY id LIMIT 100", (last_id,)).fetchall()
                    if not rows: break
                    for row in rows:
                        self.conn.execute("UPDATE telemetry SET priority=? WHERE id=?", (event_priority(SecurityEvent(**safe_json(row[1])), row[2]), row[0]))
                    last_id = rows[-1][0]
                self.conn.execute("INSERT OR REPLACE INTO ingestion_settings VALUES ('queue_priority_policy','4')")
            self.conn.execute("UPDATE telemetry SET state='pending' WHERE state='processing'")
            self.conn.commit()

    def bump(self, name, amount=1):
        with self.lock, self.conn:
            self.conn.execute("INSERT INTO ingestion_metrics VALUES (?,?) ON CONFLICT(name) "
                              "DO UPDATE SET value=value+excluded.value", (name, amount))

    def enqueue(self, event: SecurityEvent, connector="api", due_at=None) -> bool:
        priority = event_priority(event, connector)
        with self.lock, self.conn:
            if self.conn.execute("SELECT 1 FROM telemetry WHERE event_id=?", (event.event_id,)).fetchone():
                return False
            count = self.conn.execute("SELECT COUNT(*) FROM telemetry WHERE state IN ('pending','processing')").fetchone()[0]
            if count >= self.capacity:
                raise BufferFull("event buffer full")
            self.conn.execute("INSERT INTO telemetry (event_id,received_at,timestamp,source,host,severity,"
                "category,username,src_ip,dst_ip,connector,cloud_account,payload,due_at,priority) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (event.event_id, event.received_at, event.timestamp, event.source_type, event.hostname,
                 event.severity, event.event_category, event.username, event.src_ip, event.dst_ip,
                 connector, event.cloud_account, event.to_json(), due_at or now(), priority))
        return True

    def enqueue_many(self, scheduled, connector):
        with self.lock, self.conn:
            depth = self.conn.execute("SELECT COUNT(*) FROM telemetry WHERE state IN ('pending','processing')").fetchone()[0]
            if depth + len(scheduled) > self.capacity:
                raise BufferFull("not enough buffer capacity for this import")
            self.conn.executemany("INSERT INTO telemetry (event_id,received_at,timestamp,source,host,severity,"
                "category,username,src_ip,dst_ip,connector,cloud_account,payload,due_at,priority) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(e.event_id, e.received_at, e.timestamp, e.source_type, e.hostname, e.severity,
                  e.event_category, e.username, e.src_ip, e.dst_ip, connector, e.cloud_account, e.to_json(), due,
                  event_priority(e, connector))
                 for e, due in scheduled])

    def claim(self):
        with self.lock, self.conn:
            # Urgent findings first; one in 100 claims preserves FIFO progress
            # without one slow inference blocking every small context batch.
            order = "due_at,id" if self._claims % 100 == 99 else "priority DESC,due_at,id"
            row = self.conn.execute("SELECT * FROM telemetry WHERE state='pending' AND due_at<=? "
                                    f"ORDER BY {order} LIMIT 1", (now(),)).fetchone()
            if row:
                self._claims += 1
                self.conn.execute("UPDATE telemetry SET state='processing',attempts=attempts+1 WHERE id=?", (row["id"],))
                return dict(row)
        return None

    def finish(self, row_id, analysis, related, latency_ms):
        analysis = {**analysis, "completed_at": analysis.get("completed_at") or now()}
        with self.lock, self.conn:
            self.conn.execute("UPDATE telemetry SET state='done',analysis=?,related=?,latency_ms=?,error='',decision=?,tier=? WHERE id=?",
                              (json.dumps(analysis), json.dumps(related), latency_ms, analysis.get("decision"), analysis.get("tier"), row_id))

    def fail(self, row_id):
        with self.lock, self.conn:
            self.conn.execute("UPDATE telemetry SET state='failed',error='Analysis failed; administrator review required' WHERE id=?", (row_id,))

    def query(self, filters=None, limit=100, offset=0):
        filters = filters or {}
        sql, params = "SELECT * FROM telemetry WHERE 1=1", []
        if filters.get("completed"):
            sql += " AND state IN ('done','failed')"
        if filters.get("scope") == "live":
            sql += " AND connector NOT IN ('file','replay','demo')"
        for key, column in {"source": "source", "host": "host", "category": "category", "username": "username"}.items():
            if filters.get(key):
                sql += f" AND {column}=?"
                params.append(filters[key])
        if filters.get("severity"):
            sql += " AND severity>=?"
            params.append(float(filters["severity"]))
        if filters.get("since"):
            sql += " AND received_at>=?"
            params.append(filters["since"])
        if filters.get("ip"):
            sql += " AND (src_ip=? OR dst_ip=?)"
            params.extend([filters["ip"], filters["ip"]])
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([max(1, min(int(limit), 500)), max(0, int(offset))])
        with self.lock:
            return [self._decode(dict(r)) for r in self.conn.execute(sql, params)]

    @staticmethod
    def _decode(row):
        row["event"] = safe_json(row.pop("payload"))
        row["analysis"] = safe_json(row["analysis"]) if row["analysis"] else None
        row["related"] = safe_json(row["related"])
        return row

    def detail(self, event_id):
        with self.lock:
            row = self.conn.execute("SELECT * FROM telemetry WHERE event_id=?", (event_id,)).fetchone()
            return self._decode(dict(row)) if row else None

    def recent(self, event, window=300, limit=300, scope=None, sources=None):
        cutoff = (datetime.fromisoformat(event.timestamp) - timedelta(seconds=window)).isoformat()
        with self.lock:
            source_clause = " AND source IN (" + ",".join("?" for _ in sources) + ")" if sources else ""
            rows = self.conn.execute("SELECT payload,connector FROM telemetry WHERE state='done' AND timestamp>=? AND timestamp<=? "
                "AND event_id!=? AND (host=? OR (src_ip!='' AND (src_ip=? OR dst_ip=?)) OR "
                "(cloud_account!='' AND cloud_account=?))" + source_clause + " ORDER BY timestamp DESC,id DESC LIMIT ?",
                (cutoff, event.timestamp, event.event_id, event.hostname, event.src_ip,
                 event.src_ip, event.cloud_account, *(sources or ()), limit)).fetchall()
        # Keep earlier imported demo records out of live correlation.
        events = []
        for row in rows:
            previous = SecurityEvent(**safe_json(row[0]))
            # Server-owned transport provenance, never an uploaded metadata claim.
            previous.metadata["_collector_origin"] = row[1]
            events.append(previous)
        return [e for e in events if scope != "live" or not {"replay", "demo"}.intersection(e.tags)]

    def metrics(self, scope=None):
        condition = "connector NOT IN ('file','replay','demo')" if scope == "live" else "1=1"
        with self.lock:
            r = self.conn.execute("SELECT COUNT(*) events_ingested, SUM(state IN ('pending','processing')) queue_depth, "
                "SUM(state='failed') processing_failures, AVG(latency_ms) processing_latency_ms FROM telemetry WHERE " + condition).fetchone()
            result = dict(r)
            counts = self.conn.execute("SELECT SUM(decision='escalate') alerts_created, "
                "SUM(decision='suppress') events_filtered, "
                "SUM(tier='llm') events_escalated_to_ai, "
                "SUM(tier!='llm') events_handled_deterministically "
                "FROM telemetry WHERE state='done' AND " + condition).fetchone()
            extras = {r[0]: r[1] for r in self.conn.execute("SELECT * FROM ingestion_metrics")}
        result.update(dict(counts))
        result.update(extras)
        return {k: v or 0 for k, v in result.items()}

    def connector_stats(self, name):
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        with self.lock:
            return dict(self.conn.execute("SELECT COUNT(*) events_received, MAX(received_at) last_event_received, "
                "SUM(received_at>=?) events_per_minute FROM telemetry WHERE connector=?", (cutoff, name)).fetchone())

    def configs(self):
        with self.lock:
            return [dict(r) for r in self.conn.execute("SELECT * FROM connectors")]

    def configure(self, name, enabled, config):
        with self.lock, self.conn:
            old = self.conn.execute("SELECT config FROM connectors WHERE name=?", (name,)).fetchone()
            reset = bool(old and old[0] != json.dumps(config, sort_keys=True))
            self.conn.execute("INSERT INTO connectors(name,enabled,config) VALUES (?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET enabled=excluded.enabled, config=excluded.config",
                (name, int(enabled), json.dumps(config, sort_keys=True)))
            if reset:
                self.conn.execute("UPDATE connectors SET checkpoint='{}' WHERE name=?", (name,))

    def checkpoint(self, name, checkpoint, health):
        with self.lock, self.conn:
            self.conn.execute("UPDATE connectors SET checkpoint=?,errors=?,error=? WHERE name=?",
                (json.dumps(checkpoint), health["errors"], health["error"], name))

    def asset(self, event):
        asset_id = event.resource_id or event.device_id or event.hostname
        if (event.event_type != "asset_snapshot" and event.source_type != "windows_security"
                and not event.cloud_provider and not event.cloud_account):
            with self.lock, self.conn:
                self.conn.execute("INSERT INTO inventory VALUES (?,?,?,'{}') ON CONFLICT(asset_id) DO UPDATE "
                    "SET last_seen=MAX(inventory.last_seen,excluded.last_seen),host=excluded.host",
                    (asset_id, event.hostname, event.received_at))
            return
        with self.lock, self.conn:
            row = self.conn.execute("SELECT last_seen,context FROM inventory WHERE asset_id=?", (asset_id,)).fetchone()
            context = safe_json(row["context"]) if row else {}
            context.update(cloud_provider=event.cloud_provider or context.get("cloud_provider", ""),
                           cloud_account=event.cloud_account or context.get("cloud_account", ""))
            prior_posture = context.get("protection_status", {})
            if not isinstance(prior_posture, dict): prior_posture = {}
            if (event.source_type == "windows_security" and event.event_type == "security_posture"
                    and event.received_at >= prior_posture.get("observed_at", "")):
                context["protection_status"] = {"observed_at": event.received_at,
                    **event.metadata.get("protection_status", {}), "gaps": event.metadata.get("protection_gaps", [])}
            ips = set(context.get("ip_addresses", []))
            if event.event_type == "asset_snapshot":
                table = event.metadata["table"]
                if table in {"protection_status", "ip_addresses", "cloud_provider", "cloud_account", "_table_observed_at"}:
                    raise ValueError("reserved inventory field")
                observed = context.setdefault("_table_observed_at", {})
                fresh = event.received_at >= observed.get(table, "")
                if fresh:
                    context[table] = event.metadata["rows"]
                    observed[table] = event.received_at
                if table == "interface_addresses" and fresh:
                    import ipaddress
                    for interface in event.metadata["rows"]:
                        try:
                            ips.add(str(ipaddress.ip_address(interface.get("address", ""))))
                        except (ValueError, AttributeError):
                            pass
            # A remote login source IP belongs to the client, not the asset.
            context["ip_addresses"] = sorted(ips)[:100]
            self.conn.execute("INSERT INTO inventory VALUES (?,?,?,?) ON CONFLICT(asset_id) DO UPDATE "
                "SET last_seen=MAX(inventory.last_seen,excluded.last_seen),context=excluded.context,host=excluded.host",
                (asset_id, event.hostname, event.received_at, json.dumps(context)))

    def assets(self):
        with self.lock:
            return [{**dict(r), "context": safe_json(r["context"])} for r in self.conn.execute("SELECT * FROM inventory ORDER BY last_seen DESC LIMIT 500")]

    def asset_summary(self, event):
        asset_id = event.resource_id or event.device_id or event.hostname
        with self.lock:
            row = self.conn.execute("SELECT last_seen,context FROM inventory WHERE asset_id=?", (asset_id,)).fetchone()
        if not row:
            return {}
        context = safe_json(row["context"])
        return {"last_seen": row["last_seen"], "ip_addresses": context.get("ip_addresses", []),
                "os": context.get("os_version", [])[:1], "system": context.get("system_info", [])[:1],
                "listening_ports": [r.get("port") for r in context.get("listening_ports", [])[:30] if isinstance(r, dict)],
                "installed_software_observed": len(context.get("programs", [])),
                "cloud_provider": context.get("cloud_provider", ""), "cloud_account": context.get("cloud_account", ""),
                "protection_status": context.get("protection_status", {})}

    def incident(self, event, related, rule_name):
        """Group correlated escalations, without response or analyst state changes."""
        from .normalization import identity
        with self.lock, self.conn:
            existing = None
            for event_id in related:
                row = self.conn.execute("SELECT analysis FROM telemetry WHERE event_id=?", (event_id,)).fetchone()
                analysis = safe_json(row[0]) if row and row[0] else {}
                if analysis.get("incident_id"):
                    existing = analysis["incident_id"]
                    break
            incident_id = existing or identity("incident", sorted(related + [event.event_id]))
            prior = self.conn.execute("SELECT event_ids FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
            event_ids = list(dict.fromkeys((safe_json(prior[0]) if prior else []) + related + [event.event_id]))
            self.conn.execute("INSERT INTO incidents VALUES (?,?,?,?,?) ON CONFLICT(incident_id) DO UPDATE "
                              "SET updated_at=excluded.updated_at,event_ids=excluded.event_ids",
                (incident_id, now(), now(), rule_name, json.dumps(event_ids)))
        return incident_id

    def prune(self):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).isoformat()
        with self.lock, self.conn:
            self.conn.execute("DELETE FROM telemetry WHERE received_at<? AND state IN ('done','failed')", (cutoff,))
            self.conn.execute("DELETE FROM incidents WHERE updated_at<?", (cutoff,))

    def close(self):
        self.conn.close()
