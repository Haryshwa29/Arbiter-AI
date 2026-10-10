import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from arbiter.ingestion.service import IngestionService
from arbiter.memory import Memory
from arbiter.store import AuditStore


class LocalModelTests(unittest.TestCase):
    def test_connection_is_persisted_without_changing_event_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            memory, audit = Memory(root / "memory.db"), AuditStore(root / "audit.db")
            service = IngestionService(root / "events.db", memory, audit)
            try:
                service.start()
                with patch("arbiter.ingestion.service.available_models", return_value={"models": ["installed-model"]}):
                    service.connect_model("installed-model")
                self.assertEqual(service.status()["backend"], "ollama")
                self.assertTrue(service.status()["worker_alive"])
                self.assertEqual(audit.lifetime_counts()["triaged"], 0)
                service.stop()
                service = IngestionService(root / "events.db", memory, audit)
                self.assertEqual(service.model, "installed-model")
                self.assertEqual(service.backend, "ollama")
            finally:
                service.stop(); memory.close(); audit.close()

    def test_missing_model_does_not_disable_current_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            memory, audit = Memory(root / "memory.db"), AuditStore(root / "audit.db")
            service = IngestionService(root / "events.db", memory, audit)
            try:
                service.start()
                with patch("arbiter.ingestion.service.available_models", return_value={"models": []}):
                    with self.assertRaises(ValueError): service.connect_model("missing-model")
                self.assertEqual(service.backend, "mock")
                self.assertTrue(service.status()["worker_alive"])
            finally:
                service.stop(); memory.close(); audit.close()
