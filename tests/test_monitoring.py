from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from arbiter.ingestion.collectors.defender import CHANNEL, DefenderCollector
from arbiter.ingestion.collectors.windows import WindowsCollector
from arbiter.ingestion.discovery import discover_local
from arbiter.ingestion.normalization import normalize
from arbiter.ingestion.service import IngestionService
from arbiter.memory import Memory
from arbiter.store import AuditStore


class MonitoringTests(unittest.TestCase):
    def test_defender_action_preserves_result_without_claiming_remediation(self):
        raw = {"System": {"EventID": "1117", "EventRecordID": "7", "Computer": "pc",
               "Channel": CHANNEL, "TimeCreated": "2026-10-11T12:00:00Z"},
               "EventData": {"Threat Name": "Test finding", "Action Name": "Allow", "Path": "test.exe"}}
        event = normalize(raw)
        self.assertEqual(event.source_type, "defender")
        self.assertEqual(event.event_type, "antivirus_action")
        self.assertEqual(event.action, "Allow")
        self.assertEqual(event.raw_event, raw)
        self.assertEqual(event.event_id, DefenderCollector({"adapter": "defender"}).normalize(raw).event_id)
        raw["System"]["EventID"] = "1116"
        self.assertEqual(normalize(raw).severity, 8)

    def test_discovery_only_local_tools_and_readable_channels(self):
        def query(channel, **kwargs):
            if channel == "Security": raise OSError("denied")
            return []
        with patch("arbiter.ingestion.discovery.os.name", "nt"), \
             patch("arbiter.ingestion.permissions.is_elevated", return_value=False), \
             patch("arbiter.ingestion.discovery.WindowsCollector") as windows, \
             patch("arbiter.ingestion.discovery.Path.is_file", return_value=False):
            windows.return_value._query.side_effect = query
            found = discover_local()
        self.assertEqual(found["windows"]["channels"], ["System", "Application"])
        self.assertIn("sysmon", found)
        self.assertIn("defender", found)
        self.assertNotIn("osquery", found)
        self.assertNotIn("cloudtrail", found)

    def test_discovery_respects_disabled_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mem, audit = Memory(root / "memory.db"), AuditStore(root / "audit.db")
            service = IngestionService(root / "events.db", mem, audit)
            try:
                service.configure("sysmon", False, {})
                service._start = Mock()
                service.discovery_stop.wait = Mock(side_effect=lambda _: service.discovery_stop.set())
                with patch("arbiter.ingestion.discovery.discover_local", return_value={
                    "sysmon": {"read_existing": False}, "defender": {"read_existing": False}}):
                    service._discover()
                configs = {row["name"]: row for row in service.buffer.configs()}
                self.assertFalse(configs["sysmon"]["enabled"])
                self.assertTrue(configs["defender"]["enabled"])
                service._start.assert_called_once_with("defender", {"read_existing": False}, {})
                self.assertIsNone(service.discovery_thread)
            finally:
                service.stop(); mem.close(); audit.close()

    def test_registered_sysmon_with_unreadable_logger_is_visible(self):
        with patch("arbiter.ingestion.discovery.os.name", "nt"), \
             patch("arbiter.ingestion.permissions.is_elevated", return_value=False), \
             patch("arbiter.ingestion.discovery.WindowsCollector") as windows, \
             patch("arbiter.ingestion.discovery.channel_installed", return_value=True), \
             patch("arbiter.ingestion.discovery.Path.is_file", return_value=False):
            windows.return_value._query.side_effect = OSError("Windows logger unavailable")
            self.assertIn("sysmon", discover_local())
        collector = WindowsCollector({"adapter": "sysmon"})
        with patch.object(collector, "_query", side_effect=OSError("unavailable")), \
             patch("arbiter.ingestion.collectors.windows.channel_installed", return_value=True):
            self.assertEqual(list(collector.collect()), [])
        self.assertEqual(collector.status, "Error")
