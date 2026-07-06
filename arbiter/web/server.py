from __future__ import annotations

import json
import queue
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..llm import get_backend
from ..memory import Memory
from ..schema import Event
from ..store import AuditStore
from ..triage import TriageEngine
from ..iam import IAM
from . import ui

SEC_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy":
        "default-src 'self'; style-src 'unsafe-inline'; "
        "script-src 'unsafe-inline'; connect-src 'self'",
}


class Hub:
    def __init__(self):
        self._subs = []
        self._lock = threading.Lock()

    def subscribe(self):
        q = queue.Queue(maxsize=100)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def publish(self, msg):
        with self._lock:
            for q in list(self._subs):
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    pass


class Ctx:
    def __init__(self, store, iam, hub):
        self.store = store
        self.iam = iam
        self.hub = hub


def _row_msg(row):
    return {"host": row["host"], "signature": row["signature"],
            "decision": row["decision"], "score": row["score"],
            "tier": row["tier"], "rationale": row.get("rationale", "")}


def _feed_auth_failure(ctx, username):
    from ..schema import Verdict, Decision, Tier
    ev = Event(source="arbiter-dashboard", host="dashboard",
               event_type="auth_failure",
               message=f"failed dashboard login for '{username}'",
               severity=4.0, fields={"user": username})
    v = Verdict(event_id=ev.id, signature=ev.signature,
                decision=Decision.ESCALATE, score=4.0, tier=Tier.PREFILTER,
                rationale="dashboard login failure", evidence=ev.message)
    row = ctx.store.record_verdict(ev, v)
    ctx.hub.publish(_row_msg(row))


def make_handler(ctx):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Arbiter"

        def log_message(self, *a):
            pass

        def _send(self, code, body=b"", ctype="text/html; charset=utf-8",
                  cookies=None, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            for k, v in SEC_HEADERS.items():
                self.send_header(k, v)
            for c in (cookies or []):
                self.send_header("Set-Cookie", c)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _redirect(self, loc, cookies=None):
            self._send(303, b"", cookies=cookies, extra={"Location": loc})

        def _cookies(self):
            return SimpleCookie(self.headers.get("Cookie", ""))

        def _session(self):
            c = self._cookies()
            tok = c["arb_session"].value if "arb_session" in c else None
            return ctx.iam.verify_session(tok)

        def _body_form(self):
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n).decode() if n else ""
            return {k: v[0] for k, v in parse_qs(raw).items()}

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/":
                if self._session():
                    return self._redirect("/dashboard")
                return self._send(200, ui.splash(ctx.store.lifetime_counts()))
            if path == "/login":
                csrf = secrets.token_urlsafe(16)
                cookie = f"arb_csrf={csrf}; HttpOnly; SameSite=Strict; Path=/"
                return self._send(200, ui.login(csrf), cookies=[cookie])
            if path == "/dashboard":
                user = self._session()
                if not user:
                    return self._redirect("/login")
                return self._send(200, ui.dashboard(
                    user, ctx.store.today_counts(),
                    ctx.store.lifetime_counts(), ctx.store.query(limit=40)))
            if path == "/api/verdicts":
                if not self._session():
                    return self._send(401, b'{"error":"auth required"}', "application/json")
                q = parse_qs(urlparse(self.path).query)
                data = ctx.store.query(
                    decision=(q.get("decision") or [None])[0],
                    host=(q.get("host") or [None])[0],
                    limit=int((q.get("limit") or [100])[0]))
                return self._send(200, json.dumps(data).encode(), "application/json")
            if path == "/api/stream":
                return self._stream()
            return self._send(404, b"not found")

        def do_POST(self):
            path = urlparse(self.path).path
            if path == "/login":
                return self._login()
            if path == "/logout":
                dead = "arb_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
                return self._redirect("/", cookies=[dead])
            return self._send(404, b"not found")

        def _login(self):
            form = self._body_form()
            cookies = self._cookies()
            csrf_cookie = cookies["arb_csrf"].value if "arb_csrf" in cookies else None
            if not csrf_cookie or form.get("csrf") != csrf_cookie:
                return self._send(400, ui.login(secrets.token_urlsafe(16),
                                                "Session expired. Try again."))
            user = ctx.iam.authenticate(form.get("username", ""), form.get("password", ""))
            if not user:
                ctx.store.record_iam(form.get("username", "?"), "login_failed")
                _feed_auth_failure(ctx, form.get("username", "?"))
                return self._send(401, ui.login(secrets.token_urlsafe(16),
                                                "Wrong username or password."))
            ctx.store.record_iam(user["username"], "login")
            tok = ctx.iam.issue_session(user)
            sess = (f"arb_session={tok}; HttpOnly; SameSite=Strict; Path=/; "
                    f"Max-Age={8*3600}")
            return self._redirect("/dashboard", cookies=[sess])

        def _stream(self):
            if not self._session():
                return self._send(401, b"auth required")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            for k, v in SEC_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            q = ctx.hub.subscribe()
            try:
                while True:
                    try:
                        msg = q.get(timeout=15)
                        self.wfile.write(f"data: {json.dumps(msg)}\n\n".encode())
                    except queue.Empty:
                        self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                ctx.hub.unsubscribe(q)

    return Handler


def start_feeder(ctx, events_path, db, backend, model, interval):
    lines = [ln for ln in Path(events_path).read_text().splitlines()
             if ln.strip() and not ln.startswith("#")]

    def loop():
        mem = Memory(db)
        engine = TriageEngine(memory=mem, llm=get_backend(backend, model=model),
                              audit_path="/tmp/arbiter_web_audit.jsonl", shadow=True)
        i = 0
        while True:
            ev = Event.from_json(lines[i % len(lines)])
            ev.id = ""
            ev.__post_init__()
            verdict = engine.triage(ev)
            row = ctx.store.record_verdict(ev, verdict)
            ctx.hub.publish(_row_msg(row))
            i += 1
            time.sleep(interval)

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


def serve(host, port, store_db, iam_db, mem_db, events, backend, model, interval, feed):
    store = AuditStore(store_db)
    iam = IAM(iam_db)
    if not iam.any_users():
        admin_pw = secrets.token_urlsafe(9)
        analyst_pw = secrets.token_urlsafe(9)
        iam.create_user("admin", admin_pw, "admin")
        iam.create_user("analyst", analyst_pw, "analyst")
        print("First run — created accounts:", flush=True)
        print(f"  admin    / {admin_pw}", flush=True)
        print(f"  analyst  / {analyst_pw}", flush=True)
    hub = Hub()
    ctx = Ctx(store, iam, hub)
    if feed:
        start_feeder(ctx, events, mem_db, backend, model, interval)
        print(f"Feeder running: {events} -> {backend} backend every {interval}s", flush=True)
    httpd = ThreadingHTTPServer((host, port), make_handler(ctx))
    print(f"Arbiter dashboard on http://{host}:{port}  (Ctrl-C to stop)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
