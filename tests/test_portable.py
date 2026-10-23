import hashlib
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import threading
import unittest
from unittest.mock import MagicMock, patch

from arbiter.memory import Memory
from arbiter.portable import (OwnedJob, model_files, ollama_environment,
                              seed_demo_memory, device_data_dir)
from arbiter.store import AuditStore
from arbiter.ingestion.store import EventBuffer
from arbiter.ingestion.service import ingestion_path
from tests import test_api


class PortableFilesTests(unittest.TestCase):
    def test_device_profiles_isolate_history_context_and_collector_state(self):
        registry = MagicMock()
        with tempfile.TemporaryDirectory() as tmp, patch.dict("sys.modules", {"winreg": registry}):
            root = Path(tmp)
            legacy = root / "data" / "arbiter_memory.db"
            legacy.parent.mkdir()
            legacy.write_bytes(b"legacy mixed history must not be opened")
            registry.QueryValueEx.return_value = ("11111111-1111-1111-1111-111111111111", 1)
            first = device_data_dir(root)
            first.mkdir(parents=True)
            memory = Memory(first / "arbiter_memory.db")
            memory.upsert_asset("previous-pc", 2, "private previous PC", True)
            memory.add_fact("Previous PC maintenance", scope="previous-pc")
            memory.close()
            audit = AuditStore(first / "arbiter_audit.db")
            audit.record_verdict(*test_api._verdict(host="previous-pc"))
            audit.close()
            buffer = EventBuffer(ingestion_path(first / "arbiter_audit.db"))
            buffer.configure("previous-source", True, {"path": "previous-pc.log"})
            buffer.close()
            # Even when a computer has the same hostname, OS identity separates it.
            registry.QueryValueEx.return_value = ("22222222-2222-2222-2222-222222222222", 1)
            second = device_data_dir(root)
            self.assertNotEqual(first, second)
            second.mkdir(parents=True)
            memory = Memory(second / "arbiter_memory.db")
            self.assertEqual(memory.list_assets(), [])
            self.assertEqual(memory.list_facts(), [])
            memory.close()
            audit = AuditStore(second / "arbiter_audit.db")
            self.assertEqual(audit.query(), [])
            self.assertEqual(audit.lifetime_counts()["triaged"], 0)
            audit.close()
            buffer = EventBuffer(ingestion_path(second / "arbiter_audit.db"))
            self.assertEqual(buffer.configs(), [])
            buffer.close()
            registry.QueryValueEx.return_value = ("11111111-1111-1111-1111-111111111111", 1)
            self.assertEqual(device_data_dir(root), first)
            memory = Memory(first / "arbiter_memory.db")
            self.assertEqual(memory.list_assets()[0]["host"], "previous-pc")
            memory.close()
            self.assertEqual(legacy.read_bytes(), b"legacy mixed history must not be opened")
            env = ollama_environment(root, 12345, second)
            self.assertEqual(env["TEMP"], str(second / "temp"))
            self.assertEqual(env["HOME"], str(second / "runtime-home"))

    def test_missing_device_identity_never_falls_back_to_shared_history(self):
        registry = MagicMock()
        with patch.dict("sys.modules", {"winreg": registry}):
            registry.OpenKey.side_effect = OSError("unavailable")
            with self.assertRaisesRegex(ValueError, "refusing to open shared"):
                device_data_dir(Path("portable"))
            registry.OpenKey.side_effect = None
            registry.QueryValueEx.return_value = ("", 1)
            with self.assertRaises(ValueError):
                device_data_dir(Path("portable"))

    def test_demo_memory_adds_only_missing_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            memory = Memory(Path(tmp) / "memory.db")
            memory.upsert_asset("db-prod-01", 0.4, "presenter override", True)
            seed_demo_memory(memory)
            seed_demo_memory(memory)
            assets = {asset["host"]: asset for asset in memory.list_assets()}
            self.assertEqual(len(assets), 4)
            self.assertEqual(assets["db-prod-01"]["criticality"], 0.4)
            self.assertEqual(len(memory.list_facts()), 2)
            memory.close()

    @unittest.skipUnless(sys.platform == "win32", "Windows process ownership")
    def test_job_closes_owned_process_only(self):
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        job = OwnedJob()
        try:
            job.assign(process)
            job.close()
            process.wait(timeout=5)
            self.assertIsNotNone(process.returncode)
        finally:
            job.close()
            if process.poll() is None:
                process.terminate(); process.wait(timeout=5)

    def test_model_requires_complete_local_weights(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            blob = b"test weights"
            digest = hashlib.sha256(blob).hexdigest()
            (root / "blobs").mkdir()
            path = root / "blobs" / ("sha256-" + digest)
            path.write_bytes(blob)
            entry = {"digest": "sha256:" + digest, "size": len(blob),
                     "mediaType": "application/vnd.ollama.image.model"}
            manifest = root / "manifests/registry.ollama.ai/library/qwen/4b"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({"config": entry, "layers": [entry]}))
            self.assertEqual(len(model_files(root, "qwen:4b")), 2)
            path.write_bytes(b"incomplete")
            with self.assertRaises(ValueError): model_files(root, "qwen:4b")
            for name in ("qwen:cloud", "../../other:4b", "qwen:../secret"):
                with self.assertRaises(ValueError): model_files(root, name)

    def test_runtime_uses_usb_paths_without_mutating_host_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.dict("os.environ", {"OLLAMA_MODELS": "host-models", "OLLAMA_HOST": "0.0.0.0:11434", "HTTPS_PROXY": "http://proxy"}):
                env = ollama_environment(root, 12345)
                self.assertEqual(env["OLLAMA_MODELS"], str(root / "models"))
                self.assertEqual(env["OLLAMA_HOST"], "127.0.0.1:12345")
                self.assertEqual(env["OLLAMA_NO_CLOUD"], "1")
                self.assertNotIn("HTTPS_PROXY", env)
                import os
                self.assertEqual(os.environ["OLLAMA_MODELS"], "host-models")


class PortableApiTests(unittest.TestCase):
    setUp = test_api.ApiTestCase.setUp
    tearDown = test_api.ApiTestCase.tearDown
    _login = test_api.ApiTestCase._login

    def test_demo_banner_state_survives_login_and_refresh(self):
        self.ctx.demo = True
        client, status, body = self._login()
        self.assertEqual(status, 200)
        self.assertTrue(body["demo"])
        self.assertTrue(client.get("/api/me")[1]["demo"])

    def test_portable_logout_requests_shutdown_after_response(self):
        stopped = threading.Event()
        self.ctx.demo = True
        self.ctx.shutdown = stopped.set
        client, status, _ = self._login()
        self.assertEqual(status, 200)
        status, body = client.post("/api/logout", {})
        self.assertEqual((status, body), (200, {"ok": True}))
        self.assertTrue(stopped.wait(1))
