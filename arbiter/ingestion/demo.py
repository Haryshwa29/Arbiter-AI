"""Paced simulation with isolated databases; never calls an actuator."""
from __future__ import annotations

import json

from dataclasses import replace
import random
import tempfile
import threading
import time
import uuid
from pathlib import Path

from ..memory import Memory
from ..store import AuditStore
from .schema import now
from .service import IngestionService


class DemoSession:
    def __init__(self, events, interval, backend, model, ollama_url, traffic="steady", seed=0):
        self.id = uuid.uuid4().hex
        self.temp = tempfile.TemporaryDirectory(prefix="arbiter-demo-")
        root = Path(self.temp.name)
        self.memory = Memory(root / "memory.db")
        # Explicit synthetic context belongs only to this simulation.
        for host, criticality, role in (("db-prod-01", 2, "demo database"),
                ("web-prod-01", 1.6, "demo web server"), ("ci-runner-01", .8, "demo CI"),
                ("dev-laptop-42", .5, "demo laptop")):
            self.memory.upsert_asset(host, criticality, role, True)
        self.memory.add_fact("backups run at 02:00 — nightly IO spike is normal",
                             scope="db-prod-01", event_types=("io_anomaly",))
        self.memory.add_fact("CI runner process churn is expected",
                             scope="ci-runner-01", event_types=("process_anomaly", "process_burst", "process_exec"))
        self.audit = AuditStore(root / "audit.db")
        self.service = IngestionService(root / "events.db", self.memory, self.audit, backend, model, ollama_url)
        self.service.pipeline.simulation = True
        self.service.start()
        self.events, self.interval = events, interval
        self.traffic, self.rng = traffic, random.Random(seed)
        self.sent = 0
        self.state = "running"
        self.error = ""
        self.lock = threading.RLock()
        self.shutdown = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def tick(self):
        with self.lock:
            if self.state != "running" or self.sent == len(self.events):
                return False
            original = self.events[self.sent]
            event = replace(original, event_id=uuid.uuid4().hex, received_at=now(),
                            tags=[*original.tags, "demo"], metadata={**original.metadata, "demo_session": self.id})
            self.service.buffer.enqueue(event, "demo")
            self.sent += 1
            return True

    def run(self):
        next_event = time.monotonic() + self.interval
        while not self.shutdown.wait(.05):
            try:
                with self.lock:
                    if self.state != "running":
                        next_event = time.monotonic() + self.interval
                        continue
                    if self.sent == len(self.events):
                        if not self.service.buffer.metrics()["queue_depth"]:
                            self.state = "completed"
                        continue
                    if time.monotonic() >= next_event:
                        self.tick()
                        delay = self.interval if self.traffic == "steady" else self.interval * (4 if self.sent % 5 == 0 else .25) if self.traffic == "bursts" else self.interval * self.rng.uniform(.5, 3)
                        next_event = time.monotonic() + max(.1, delay)
            except Exception:
                with self.lock:
                    self.state = "failed"
                    self.error = "Simulation stopped; review the session or start a new one."

    def control(self, action):
        with self.lock:
            if action == "pause" and self.state == "running": self.state = "paused"
            elif action == "resume" and self.state == "paused": self.state = "running"
            elif action == "stop": self.state = "stopped"
            else: raise ValueError("invalid simulation transition")
        return self.status()

    def status(self):
        with self.lock:
            metrics = self.service.buffer.metrics()
            return {"session_id": self.id, "state": self.state, "total": len(self.events),
                    "delivered": self.sent, "completed": metrics["events_ingested"] - metrics["queue_depth"],
                    "interval_seconds": self.interval, "metrics": metrics, "error": self.error,
                    "events": self.service.buffer.query(limit=100)}

    def close(self):
        self.shutdown.set()
        self.thread.join(2)
        self.service.stop()
        self.memory.close()
        self.audit.close()
        self.temp.cleanup()


class DemoManager:
    def __init__(self, backend="mock", model="qwen3.5:4b", ollama_url="http://localhost:11434"):
        self.backend, self.model, self.ollama_url = backend, model, ollama_url
        self.session = None
        self.lock = threading.RLock()

    def start(self, groups, speed="1x", order="mixed", seed=0, traffic="steady"):
        speeds = {"1x": 1, "2x": 2, "5x": 5, "10x": 10}
        if speed not in speeds or order not in {"mixed", "random"} or traffic not in {"steady", "bursts", "delayed"}:
            raise ValueError("invalid playback settings")
        if not isinstance(seed, int) or isinstance(seed, bool) or not 0 <= seed <= 2**32:
            raise ValueError("invalid random seed")
        if not groups or not 1 <= sum(len(g) for g in groups) <= 5000:
            raise ValueError("select between 1 and 5000 valid events")
        rng = random.Random(seed)
        groups = [list(group) for group in groups if group]
        events = []
        while groups:
            index = rng.randrange(len(groups))
            events.append(groups[index].pop(0))
            if not groups[index]: groups.pop(index)
        if order == "random": rng.shuffle(events)
        with self.lock:
            if self.session and self.session.state in {"running", "paused"}:
                raise ValueError("stop the current simulation before starting another")
            if self.session: self.session.close()
            self.session = DemoSession(events, 3 / speeds[speed], self.backend, self.model, self.ollama_url, traffic, seed)
            return self.session.status()

    def status(self):
        with self.lock:
            return self.session.status() if self.session else {"state": "ready", "events": [], "total": 0, "delivered": 0, "completed": 0}

    def control(self, action):
        with self.lock:
            if not self.session: raise ValueError("no simulation session")
            return self.session.control(action)

    def history(self, offset=0, filters=None):
        filters = filters or {}
        with self.lock:
            rows = []
            if self.session:
                for page in range(0, 5000, 500):
                    batch = self.session.service.buffer.query(limit=500, offset=page)
                    rows.extend(batch)
                    if len(batch) < 500: break
            def matches(row):
                event, analysis = row["event"], row["analysis"] or {}
                decision = "failed" if row["state"] == "failed" else analysis.get("decision", "pending")
                if filters.get("decision") and filters["decision"] != decision: return False
                for key, field in (("event_type", "event_type"), ("host", "hostname"), ("source", "source_type")):
                    if filters.get(key, "").casefold() not in str(event.get(field, "")).casefold(): return False
                response = "selected" if analysis.get("responses") else "none" if analysis else "pending"
                if filters.get("response") and filters["response"] != response: return False
                text = json.dumps([event, analysis], ensure_ascii=False).casefold()
                return filters.get("search", "").casefold() in text
            rows = [row for row in rows if matches(row)]
            return {"events": rows[offset:offset + 100], "total": len(rows)}

    def detail(self, event_id):
        with self.lock:
            return self.session.service.buffer.detail(event_id) if self.session else None

    def close(self):
        with self.lock:
            if self.session: self.session.close()
