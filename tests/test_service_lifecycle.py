import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from arbiter.install.lifecycle import instance_lock, operational_logs, write_health
from arbiter.install.runtime import run
from arbiter.install.cli import seed_databases, write_config
from arbiter.install.plan import layout_for
from arbiter.memory import Memory


class InstalledLifecycleTests(unittest.TestCase):
    def test_second_process_is_rejected_and_lock_recovers_after_exit(self):
        with tempfile.TemporaryDirectory() as td:
            command = [sys.executable, "-c", "from arbiter.install.lifecycle import instance_lock; "
                       "from pathlib import Path; import sys; "
                       "\nwith instance_lock(Path(sys.argv[1])): print('acquired')", td]
            with instance_lock(Path(td)):
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("already running", result.stderr)
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)

    def test_health_and_logs_persist_without_redirecting_callers_after_stop(self):
        with tempfile.TemporaryDirectory() as td:
            original = sys.stdout
            with operational_logs(Path(td)):
                print("operational test")
            self.assertIs(sys.stdout, original)
            self.assertIn("operational test", (Path(td) / "service.log").read_text())
            write_health(Path(td), "running", worker_alive=True)
            state = json.loads((Path(td) / "service-health.json").read_text())
            self.assertEqual(state["pid"], os.getpid())
            self.assertTrue(state["worker_alive"])

    def test_runtime_failure_is_logged_and_clean_stop_has_separate_health(self):
        with tempfile.TemporaryDirectory() as td:
            layout = layout_for("user", td)
            for directory in layout.dirs(): directory.mkdir(parents=True, exist_ok=True)
            write_config(layout, "127.0.0.1", 8787, "mock", "unused", "")
            with patch("arbiter.install.runtime._run", side_effect=RuntimeError("test failure")):
                with self.assertRaises(RuntimeError): run(layout.config_path)
            self.assertEqual(json.loads((layout.data_dir / "service-health.json").read_text())["state"], "failed")
            with patch("arbiter.install.runtime._run"):
                run(layout.config_path)
            self.assertEqual(json.loads((layout.data_dir / "service-health.json").read_text())["state"], "stopped")

    def test_installed_memory_has_no_demo_asset_or_fact_seeds(self):
        with tempfile.TemporaryDirectory() as td:
            layout = layout_for("user", td)
            layout.data_dir.mkdir(parents=True)
            seed_databases(layout)
            memory = Memory(layout.memory_db)
            try:
                self.assertEqual(memory.conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0], 0)
                self.assertEqual(memory.conn.execute("SELECT COUNT(*) FROM facts").fetchone()[0], 0)
            finally:
                memory.close()
