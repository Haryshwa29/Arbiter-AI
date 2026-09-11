"""Exercise bundled dashboard serving without exposing project files."""
import tempfile
import unittest
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch

from arbiter.api.static import dashboard_resource
from tools.build_release import check_frontend
from tests import test_api


class DashboardTests(unittest.TestCase):
    def test_routes_and_file_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "index.html").write_bytes(b"dashboard")
            (root / "app.js").write_bytes(b"script")
            (root / "secret.db").write_bytes(b"private")
            for route in ("/", "/login", "/audit", "/assets"):
                self.assertEqual(dashboard_resource(route, root)[0], b"dashboard")
            self.assertEqual(dashboard_resource("/app.js", root)[0], b"script")
            for route in ("/../index.html", "/%2e%2e/index.html", "/secret.db",
                          "/missing.js", "/unknown", "/C:/index.html", "/a\\index.html"):
                self.assertIsNone(dashboard_resource(route, root), route)

    def test_release_rejects_missing_or_public_dashboard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(SystemExit):
                check_frontend(root)
            (root / "index.html").write_text("dashboard")
            (root / "arbiter-build.json").write_text('{"target":"public"}')
            with self.assertRaises(SystemExit):
                check_frontend(root)
            (root / "arbiter-build.json").write_text('{"target":"self-hosted"}')
            check_frontend(root)


class DashboardHttpTests(unittest.TestCase):
    setUp = test_api.ApiTestCase.setUp
    tearDown = test_api.ApiTestCase.tearDown

    def test_login_shell_public_but_data_stays_authenticated(self):
        with patch("arbiter.api.server.dashboard_resource", return_value=(b"shell", "text/html")):
            conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
            conn.request("GET", "/login")
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b"shell")
            self.assertIn("script-src 'self'", response.getheader("Content-Security-Policy"))
            conn.close()
            conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
            conn.request("GET", "/api/summary")
            response = conn.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
            conn.close()
