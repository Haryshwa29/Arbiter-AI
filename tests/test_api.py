"""Tests for the JSON API layer (arbiter/api/server.py).

Spins up a real ThreadingHTTPServer on an ephemeral port per test and talks
to it with http.client, so these exercise the actual routing, session
cookie, and CSRF double-submit logic — not mocks of them.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection
from pathlib import Path

from arbiter.api.server import (Ctx, Hub, build_httpd, demo_feed_loop,
                                load_feed_events, require_admin, tail_poller)
from arbiter.iam import IAM
from arbiter.memory import Memory
from arbiter.schema import Decision, Event, Tier, Verdict
from arbiter.store import AuditStore


def _verdict(host="web-prod-01", decision=Decision.ESCALATE):
    ev = Event(source="sshd", host=host, event_type="auth_bruteforce",
               message="48 failed root logins", severity=8.5,
               fields={"src_ip": "185.220.101.7"})
    v = Verdict(event_id=ev.id, signature=ev.signature, decision=decision,
                score=9.0, tier=Tier.PREFILTER, rationale="test", evidence="e")
    return ev, v


class Client:
    """Minimal cookie-jar HTTP client for exercising the API by hand."""

    def __init__(self, port: int):
        self.port = port
        self.cookies: dict[str, str] = {}

    def _headers(self, extra=None):
        h = dict(extra or {})
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        return h

    def _absorb(self, resp):
        for raw in resp.msg.get_all("Set-Cookie") or []:
            kv = raw.split(";", 1)[0]
            k, _, v = kv.partition("=")
            self.cookies[k] = v

    def get(self, path: str, headers=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", path, headers=self._headers(headers))
        resp = conn.getresponse()
        body = json.loads(resp.read() or b"{}")
        self._absorb(resp)
        conn.close()
        return resp.status, body

    def post(self, path: str, payload: dict, csrf: bool = True):
        headers = self._headers({"Content-Type": "application/json"})
        if csrf and "arb_csrf" in self.cookies:
            headers["X-CSRF-Token"] = self.cookies["arb_csrf"]
        body = json.dumps(payload).encode()
        headers["Content-Length"] = str(len(body))
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        data = json.loads(resp.read() or b"{}")
        self._absorb(resp)
        conn.close()
        return resp.status, data


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = AuditStore(root / "audit.db")
        self.iam = IAM(root / "iam.db", secret=b"0" * 32)
        self.iam.create_user("priya", "correct horse", "analyst")
        self.mem = Memory(root / "mem.db")
        self.mem.upsert_asset("db-prod-01", 2.0, "prod db", True)
        self.mem.add_fact("backups run at 02:00", scope="db-prod-01")
        self.ctx = Ctx(store=self.store, iam=self.iam, memory=self.mem, hub=Hub())
        self.httpd = build_httpd(self.ctx, "127.0.0.1", 0)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        # Release sqlite handles before rmtree, or cleanup fails on Windows.
        self.store.close()
        self.iam.close()
        self.mem.close()
        self.tmp.cleanup()

    def _login(self, username="priya", password="correct horse"):
        c = Client(self.port)
        c.get("/api/me")  # bootstraps the arb_csrf cookie
        status, body = c.post("/api/login", {"username": username, "password": password})
        return c, status, body

    # -- auth / session / csrf -------------------------------------------------
    def test_unauthenticated_get_is_401(self):
        status, _ = Client(self.port).get("/api/me")
        self.assertEqual(status, 401)

    def test_login_without_csrf_token_is_rejected(self):
        c = Client(self.port)
        c.get("/api/me")
        status, _ = c.post("/api/login",
                           {"username": "priya", "password": "correct horse"},
                           csrf=False)
        self.assertEqual(status, 403)

    def test_login_then_me_roundtrip(self):
        c, status, body = self._login()
        self.assertEqual(status, 200)
        self.assertEqual(body, {"username": "priya", "role": "analyst"})
        status, me = c.get("/api/me")
        self.assertEqual(status, 200)
        self.assertEqual(me["username"], "priya")

    def test_wrong_password_is_401(self):
        c = Client(self.port)
        c.get("/api/me")
        status, body = c.post("/api/login", {"username": "priya", "password": "nope"})
        self.assertEqual(status, 401)

    def test_logout_clears_session(self):
        c, _, _ = self._login()
        status, body = c.post("/api/logout", {})
        self.assertEqual(status, 200)
        status, _ = c.get("/api/me")
        self.assertEqual(status, 401)

    def test_security_headers_present(self):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/api/me")
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        conn.close()

    # -- data routes -------------------------------------------------------
    def test_summary_shape(self):
        self.store.record_verdict(*_verdict())
        c, _, _ = self._login()
        status, body = c.get("/api/summary")
        self.assertEqual(status, 200)
        self.assertIn("today", body)
        self.assertIn("lifetime", body)

    def test_record_filters_by_decision(self):
        self.store.record_verdict(*_verdict(decision=Decision.ESCALATE))
        self.store.record_verdict(*_verdict(decision=Decision.SUPPRESS))
        c, _, _ = self._login()
        status, body = c.get("/api/record?decision=escalate")
        self.assertEqual(status, 200)
        self.assertTrue(body["rows"])
        self.assertTrue(all(r["decision"] == "escalate" for r in body["rows"]))

    def test_estate_returns_assets_and_facts(self):
        c, _, _ = self._login()
        status, body = c.get("/api/estate")
        self.assertEqual(status, 200)
        self.assertEqual(body["assets"][0]["host"], "db-prod-01")
        self.assertTrue(body["facts"])

    def test_day_buckets_hours_param(self):
        c, _, _ = self._login()
        status, body = c.get("/api/day?hours=3")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["buckets"]), 3)

    # -- feedback loop -------------------------------------------------------
    def test_label_validates_and_records(self):
        c, _, _ = self._login()
        status, _ = c.post("/api/label", {"signature": "sig1", "label": "confirmed"})
        self.assertEqual(status, 200)
        status, _ = c.post("/api/label", {"signature": "sig1", "label": "bogus"})
        self.assertEqual(status, 400)

    def test_acknowledge_marks_row_and_rejects_unknown_id(self):
        row = self.store.record_verdict(*_verdict())
        c, _, _ = self._login()
        status, _ = c.post("/api/acknowledge", {"id": row["id"]})
        self.assertEqual(status, 200)
        status, _ = c.post("/api/acknowledge", {"id": 999999})
        self.assertEqual(status, 404)

    # -- live feed -------------------------------------------------------------
    def test_stream_requires_auth(self):
        status, _ = Client(self.port).get("/api/stream")
        self.assertEqual(status, 401)

    def test_stream_delivers_published_message(self):
        c, _, _ = self._login()
        result: dict = {}

        def reader():
            conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
            conn.request("GET", "/api/stream", headers=c._headers())
            resp = conn.getresponse()
            line = resp.fp.readline()
            while not line.strip():
                line = resp.fp.readline()
            result["line"] = line
            conn.close()

        t = threading.Thread(target=reader)
        t.start()
        time.sleep(0.2)
        self.ctx.hub.publish({"host": "web-prod-01", "decision": "escalate"})
        t.join(timeout=3)
        self.assertIn(b"data:", result.get("line", b""))


class TailPollerTests(unittest.TestCase):
    """The SSE feed is fed by polling the store, not by whoever wrote the
    row — this is what lets `arbiter run`, a real collector, or --demo-feed
    all show up live without the API talking to the triage engine."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = AuditStore(Path(self.tmp.name) / "audit.db")
        self.hub = Hub()

    def tearDown(self):
        self.store.close()  # release the sqlite handle before rmtree (Windows)
        self.tmp.cleanup()

    def test_poller_publishes_rows_inserted_after_it_started(self):
        ctx = Ctx(store=self.store, iam=None, memory=None, hub=self.hub)
        q = self.hub.subscribe()
        stop = threading.Event()
        t = threading.Thread(target=tail_poller, args=(ctx, 0.02, stop))
        t.start()
        time.sleep(0.05)
        self.store.record_verdict(*_verdict())
        msg = q.get(timeout=2)
        self.assertEqual(msg["host"], "web-prod-01")
        stop.set()
        t.join(timeout=2)


class DemoFeedTests(unittest.TestCase):
    """--demo-feed is dev-only and off by default; this checks the loop
    itself does what it claims when explicitly driven."""

    def test_demo_feed_writes_verdicts_to_the_store(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = AuditStore(root / "audit.db")
            mem = Memory(root / "mem.db")
            events_path = root / "events.jsonl"
            ev, _ = _verdict()
            events_path.write_text(ev.to_json() + "\n", encoding="utf-8")
            ctx = Ctx(store=store, iam=None, memory=mem, hub=Hub())
            stop = threading.Event()

            def stop_after_one():
                time.sleep(0.05)
                stop.set()

            threading.Thread(target=stop_after_one).start()
            demo_feed_loop(ctx, mem, str(events_path), "mock", "m",
                           interval=0.01, stop=stop)
            self.assertGreaterEqual(store.lifetime_counts()["triaged"], 1)
            store.close()
            mem.close()


class LoadFeedEventsTests(unittest.TestCase):
    """--demo-feed used to raise TypeError on the first line of any eval
    suite and take the feeder thread down with it, leaving the dashboard
    empty and the reason buried in the server log. Both sample shapes have
    to load."""

    def _write(self, root: Path, *lines: str) -> str:
        p = root / "feed.jsonl"
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return str(p)

    def test_bare_events_load(self):
        with tempfile.TemporaryDirectory() as td:
            ev, _ = _verdict()
            path = self._write(Path(td), "# a comment", "", ev.to_json())
            events = load_feed_events(path)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].signature, ev.signature)

    def test_eval_suite_wrapper_is_unwrapped(self):
        with tempfile.TemporaryDirectory() as td:
            ev, _ = _verdict()
            case = json.dumps({"event": json.loads(ev.to_json()),
                               "expected": "escalate",
                               "category": "brute force",
                               "facts": [], "notes": "labelled case"})
            path = self._write(Path(td), "# realistic suite", case)
            events = load_feed_events(path)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].signature, ev.signature)

    def test_unparseable_lines_are_skipped_not_fatal(self):
        with tempfile.TemporaryDirectory() as td:
            ev, _ = _verdict()
            path = self._write(Path(td),
                               "{not json",
                               json.dumps({"source": "sshd"}),  # missing fields
                               ev.to_json())
            with contextlib.redirect_stdout(io.StringIO()):
                events = load_feed_events(path)
            self.assertEqual(len(events), 1)

    def test_real_sample_files_all_load(self):
        root = Path(__file__).resolve().parent.parent / "samples"
        for name in ("events.jsonl", "realistic_suite.jsonl",
                     "adversarial_suite.jsonl"):
            path = root / name
            if not path.exists():
                continue
            with self.subTest(sample=name):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    events = load_feed_events(str(path))
                self.assertGreater(len(events), 0)
                self.assertNotIn("skipped", out.getvalue())


class RequireAdminTests(unittest.TestCase):
    def test_require_admin(self):
        self.assertTrue(require_admin({"username": "a", "role": "admin"}))
        self.assertFalse(require_admin({"username": "a", "role": "analyst"}))
        self.assertFalse(require_admin(None))


if __name__ == "__main__":
    unittest.main()
