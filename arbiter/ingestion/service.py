"""Lifecycle owner shared by installed, source and portable runtimes."""
from __future__ import annotations

import os
import socket
from .permissions import is_elevated
from .models import available_models
from pathlib import Path
import threading

from ..llm import LLMBackend, OllamaBackend, get_backend
from ..triage import TriageEngine
from .files import parse_upload, schedule
from .normalization import normalize
from .pipeline import Pipeline
from .registry import default_registry
from .schema import safe_json
from .store import BufferFull, EventBuffer


class IngestionService:
    def __init__(self, path, memory, audit, backend="mock", model="qwen3.5:4b",
                 ollama_url="http://localhost:11434", registry=None, capacity=10000):
        self.backend, self.model = backend, model
        self.buffer = EventBuffer(path, capacity=capacity)
        self.ollama_url = ollama_url
        with self.buffer.lock, self.buffer.conn:
            self.buffer.conn.execute("CREATE TABLE IF NOT EXISTS analysis_configuration (id INTEGER PRIMARY KEY CHECK(id=1), backend TEXT NOT NULL, model TEXT NOT NULL)")
            saved = self.buffer.conn.execute("SELECT backend,model FROM analysis_configuration WHERE id=1").fetchone()
        if saved and backend == "mock":
            backend, model = saved["backend"], saved["model"]
            self.backend, self.model = backend, model
        self.registry = registry or default_registry()
        self.collectors = {}
        self.lock = threading.RLock()
        self.discovery_stop = threading.Event()
        self.discovery_thread = None
        # Explicit dependency injection for the isolated website simulator;
        # runtime/API backend names still resolve only to local or mock models.
        llm = backend if isinstance(backend, LLMBackend) else OllamaBackend(model, ollama_url) if backend == "ollama" else get_backend(backend, model)
        self.pipeline = Pipeline(self.buffer, TriageEngine(memory, llm, os.devnull, shadow=True), audit)

    def connect_model(self, model):
        if not isinstance(model, str) or model not in available_models(self.ollama_url)["models"]:
            raise ValueError("model is not installed on the local inference service")
        with self.lock:
            self.pipeline.stop()
            old = self.pipeline.engine
            self.pipeline = Pipeline(self.buffer, TriageEngine(old.memory, OllamaBackend(model, self.ollama_url), os.devnull, shadow=True), self.pipeline.audit)
            self.backend, self.model = "ollama", model
            with self.buffer.lock, self.buffer.conn:
                self.buffer.conn.execute("INSERT OR REPLACE INTO analysis_configuration VALUES (1,?,?)", (self.backend, model))
            self.pipeline.start()

    def start(self, discover=False):
        self.pipeline.start()
        for row in self.buffer.configs():
            if row["enabled"]:
                try:
                    self._start(row["name"], safe_json(row["config"]), safe_json(row["checkpoint"]))
                except (ValueError, OSError):
                    self.buffer.checkpoint(row["name"], safe_json(row["checkpoint"]),
                        {"errors": row["errors"] + 1, "error": "Configuration unavailable; reconfigure this source"})
        if discover:
            self.discovery_stop.clear()
            self.discovery_thread = threading.Thread(target=self._discover, daemon=True)
            self.discovery_thread.start()

    def _discover(self):
        from .discovery import discover_local
        while not self.discovery_stop.is_set():
            try:
                detected = discover_local()
                with self.lock:
                    configured = {row["name"] for row in self.buffer.configs()}
                    for name, config in detected.items():
                        if self.discovery_stop.is_set():
                            return
                        if name not in configured:
                            self.configure(name, True, config)
            except (OSError, ValueError):
                pass  # collector health reports unavailable sources separately
            self.discovery_stop.wait(30)

    def _start(self, name, config, checkpoint):
        collector = self.registry.create(name, config, checkpoint)
        previous = next((r for r in self.buffer.configs() if r["name"] == name), None)
        if previous:
            collector.errors = previous["errors"]
        collector.on_normalization_error = lambda: self.buffer.bump("normalization_failures")
        self.collectors[name] = collector
        collector.start(lambda event: self.buffer.enqueue(event, name),
                        lambda cursor: self.buffer.checkpoint(name, cursor, collector.health()))

    def configure(self, name, enabled, config):
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be boolean")
        config = self.registry.validate(name, config)
        with self.lock:
            old = self.collectors.get(name)
            if old:
                old.stop()
                del self.collectors[name]
            self.buffer.configure(name, enabled, config)
            if enabled:
                row = next(r for r in self.buffer.configs() if r["name"] == name)
                self._start(name, config, safe_json(row["checkpoint"]))

    def status(self, include_metrics=True):
        rows = {r["name"]: r for r in self.buffer.configs()}
        connectors = []
        with self.lock:
            for name, spec in self.registry.specs.items():
                row = rows.get(name)
                state = "Coming Soon" if not spec.implemented else "Configured" if row else "Available"
                if row and not row["enabled"]:
                    state = "Disabled"
                health = self.collectors[name].health() if name in self.collectors else {
                    "status": "Error" if row and row["enabled"] and row["error"] else state,
                    "errors": row["errors"] if row else 0, "error": row["error"] if row else ""}
                connectors.append({"name": name, "label": spec.label, "category": spec.category,
                    "implemented": spec.implemented, "enabled": bool(row and row["enabled"]),
                    "description": spec.description, "configuration": safe_json(row["config"]) if row else spec.defaults,
                    **health, **(self.buffer.connector_stats(name) if include_metrics else {})})
        for name, label, category in (("api", "Authenticated API", "Other"), ("file", "File Upload", "Demo"), ("replay", "Event Replay", "Demo")):
            connectors.append({"name": name, "label": label, "category": category, "implemented": True,
                "enabled": True, "status": "Enabled" if name == "api" else "Available", "errors": 0,
                "error": "", "configuration": {}, "description": "Uses the common event buffer",
                **(self.buffer.connector_stats(name) if include_metrics else {})})
        metrics = self.buffer.metrics("live") if include_metrics else {}
        metrics["connector_errors"] = sum(c["errors"] for c in connectors)
        return {"device": socket.gethostname(), "backend": self.backend, "model": self.model,
                "elevated": is_elevated(), "protection_enabled": False,
                "coverage": "This device and explicitly configured sources; other network devices require sensors",
                "connectors": connectors, "metrics": metrics,
                "worker_alive": bool(self.pipeline.thread and self.pipeline.thread.is_alive())}

    def submit(self, data, source="auto", connector="api"):
        try:
            event = normalize(data, source)
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            self.buffer.bump("normalization_failures")
            raise ValueError("invalid or unsupported event") from None
        return self.buffer.enqueue(event, connector)

    def import_file(self, filename, content, source="auto", speed="instant", preview=False):
        result = parse_upload(filename, content, source)
        summary = result.summary()
        if preview:
            return {**summary, "import_status": "Preview", "accepted_events": 0}
        # Validate the entire replay schedule before reserving queue capacity.
        scheduled = list(schedule(result.events, speed))
        self.buffer.enqueue_many(scheduled, "file" if speed == "instant" else "replay")
        self.buffer.bump("normalization_failures", result.invalid_events)
        return {**summary, "import_status": "Queued" if result.events else "No valid events", "accepted_events": len(result.events)}

    def stop(self):
        self.discovery_stop.set()
        if self.discovery_thread:
            self.discovery_thread.join()  # finish probing before closing the store
        with self.lock:
            for collector in self.collectors.values():
                collector.stop()
        self.pipeline.stop()
        self.buffer.close()


def ingestion_path(audit_path):
    path = Path(audit_path)
    return path.with_name(path.stem + "_ingestion.db")
