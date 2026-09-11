import hashlib
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from arbiter.memory import Memory
from arbiter.portable import (OwnedJob, model_files, ollama_environment,
                              seed_demo_memory)
from tests import test_api


class PortableFilesTests(unittest.TestCase):
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
