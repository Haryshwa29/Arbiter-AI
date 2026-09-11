"""JSON API and bundled dashboard over store.py, iam.py, memory.py.

Release archives serve the self-hosted SPA on the API's origin (ADR-003).
Only bundled static resources are public; operational API routes require
a session. Source development can continue using the Vite proxy.

stdlib `http.server` only — deliberately, not FastAPI. See AGENTS.md: the
dependency-minimalism rule (this product's sales argument is that a customer
can audit it) and the zipapp packaging model (a single-file, pure-Python
.pyz) both rule out FastAPI's stack, whose Pydantic-core/Uvicorn deps are
compiled per-platform wheels.

Auth: session is an HMAC-signed cookie issued by `iam.py`, 8h TTL. CSRF is
double-submit: every response ensures a non-HttpOnly `arb_csrf` cookie
exists, and every POST must echo its value back in an `X-CSRF-Token`
header. This assumes the frontend dev server (and any production reverse
proxy) serves the SPA and proxies /api/* same-origin — that's what lets
`SameSite=Strict` on both cookies keep working. A cross-origin frontend
would need a different CSRF/cookie strategy.

Live feed: a background thread polls the audit store for newly inserted
verdict rows and fans them out over SSE (`/api/stream`). It does not care
who wrote the row — `arbiter run`, a future real collector, or the
dev-only --demo-feed below — which keeps this layer from ever talking to
the triage engine directly (the frontend only ever reads store.py/memory.py
through here).
"""

from __future__ import annotations

import hmac
import json
import queue
import secrets
import threading
from dataclasses import dataclass, replace
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlparse

from ..iam import IAM, SESSION_TTL, load_or_create_secret
from ..memory import Memory
from ..store import AuditStore
from .static import CSP, dashboard_resource

SESSION_COOKIE = "arb_session"
CSRF_COOKIE = "arb_csrf"

SEC_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
}


@dataclass
class Ctx:
    store: AuditStore
    iam: IAM
    memory: Memory
    hub: "Hub"
    demo: bool = False
    shutdown: Callable[[], None] | None = None


class Hub:
    """Fan-out for the SSE feed: one queue per connected client."""

    def __init__(self) -> None:
        self._subs: list[queue.Queue] = []
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=200)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def publish(self, msg: dict) -> None:
        with self._lock:
            for q in list(self._subs):
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    pass


def require_admin(user: dict | None) -> bool:
    """True if `user` (as returned by iam.verify_session) holds admin.

    No route in the current contract needs this yet — the Admin view
    (users/roles, retention/policy) isn't specified in AGENTS.md's endpoint
    list, only sketched as a future frontend view. This is the check its
    routes gate on when they land.
    """
    return bool(user) and user.get("role") == "admin"


def _row_msg(row: dict) -> dict:
    return {"id": row["id"], "ts": row["ts"], "host": row["host"],
            "signature": row["signature"], "decision": row["decision"],
            "score": row["score"], "tier": row["tier"],
            "rationale": row.get("rationale", "")}


def tail_poller(ctx: Ctx, interval: float = 1.0,
                stop: threading.Event | None = None) -> None:
    """Watch the audit store for new verdict rows, publish each to the Hub.

    Runs forever (until `stop` is set) regardless of what inserted the
    row — see module docstring.
    """
    stop = stop or threading.Event()
    last_id = ctx.store.max_id()
    while not stop.is_set():
        for row in ctx.store.rows_since(last_id):
            ctx.hub.publish(_row_msg(row))
            last_id = row["id"]
        stop.wait(interval)


def start_tail_poller(ctx: Ctx, interval: float = 1.0) -> threading.Thread:
    t = threading.Thread(target=tail_poller, args=(ctx, interval), daemon=True)
    t.start()
    return t


def load_feed_events(events_path: str) -> list["Event"]:
    """Read a JSONL file of events for the demo feed, tolerating both shapes
    that exist in `samples/`.

    `samples/events.jsonl` is one bare Event per line. The eval suites
    (`realistic_suite.jsonl`, `adversarial_suite.jsonl`, ...) wrap each event
    in a labelled case: `{"event": {...}, "expected": ..., "facts": [...]}`.
    Pointing --demo-feed at a suite used to raise TypeError on the first line
    and kill the feeder thread, leaving the dashboard empty with the reason
    only in the server log — so unwrap the labelled shape here.

    Unparseable lines are reported and skipped rather than taking the whole
    feed down; this is dev scaffolding, not the ingest path a collector uses.
    """
    from ..schema import Event

    events: list[Event] = []
    for n, line in enumerate(
            Path(events_path).read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            data = json.loads(line)
            # A labelled eval case carries the event under "event"; a bare
            # event never has that key (it is not a field on Event).
            if isinstance(data, dict) and isinstance(data.get("event"), dict):
                data = data["event"]
            events.append(Event(**data))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            print(f"!! --demo-feed: {events_path}:{n} skipped: {exc}")
    return events


def demo_feed_loop(ctx: Ctx, mem: Memory, events_path: str, backend: str,
                   model: str, interval: float,
                   stop: threading.Event | None = None,
                   ollama_url: str = "http://localhost:11434") -> None:
    """Dev-only: replay `events_path` through a real TriageEngine on a timer
    so the dashboard has something to show without a real collector wired
    up yet. Never started unless `arbiter serve --demo-feed` is passed.

    Verdicts land in the same audit store as anything else, so the tail
    poller above picks them up and the SSE feed sees them like any other
    verdict — this function doesn't touch the Hub itself.
    """
    import os

    from ..llm import get_backend, OllamaBackend
    from ..triage import TriageEngine

    events = load_feed_events(events_path)
    if not events:
        print(f"!! --demo-feed: no usable events in {events_path}, "
              "feed not started", flush=True)
        return
    print(f"-- demo feed: {len(events)} events from {events_path}", flush=True)
    llm = OllamaBackend(model=model, url=ollama_url) if backend == "ollama" else get_backend(backend, model=model)
    engine = TriageEngine(memory=mem, llm=llm,
                          audit_path=os.devnull, shadow=True)
    stop = stop or threading.Event()
    i = 0
    while not stop.is_set():
        event = replace(events[i % len(events)], id="", timestamp="")
        try:
            verdict = engine.triage(event)
            ctx.store.record_verdict(event, verdict)
        except Exception as exc:  # one bad event must not kill the thread
            print(f"!! --demo-feed: {event.signature} failed to triage: "
                  f"{exc!r}", flush=True)
        i += 1
        stop.wait(interval)


def start_demo_feed(ctx: Ctx, mem: Memory, events_path: str, backend: str,
                    model: str, interval: float) -> threading.Thread:
    t = threading.Thread(target=demo_feed_loop,
                         args=(ctx, mem, events_path, backend, model, interval),
                         daemon=True)
    t.start()
    return t


def make_handler(ctx: Ctx):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ArbiterAPI"

        def log_message(self, *a):
            pass

        # -- cookies / session / csrf ---------------------------------------
        def _cookies(self) -> SimpleCookie:
            return SimpleCookie(self.headers.get("Cookie", ""))

        def _session_user(self) -> dict | None:
            c = self._cookies()
            tok = c[SESSION_COOKIE].value if SESSION_COOKIE in c else None
            return ctx.iam.verify_session(tok)

        def _csrf_cookie_value(self) -> str | None:
            c = self._cookies()
            return c[CSRF_COOKIE].value if CSRF_COOKIE in c else None

        def _check_csrf(self) -> bool:
            cookie = self._csrf_cookie_value()
            header = self.headers.get("X-CSRF-Token")
            return bool(cookie) and bool(header) and hmac.compare_digest(cookie, header)

        # -- response helpers -------------------------------------------------
        def _send_json(self, code: int, payload: dict,
                       extra_cookies: list[str] | None = None) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            for k, v in SEC_HEADERS.items():
                self.send_header(k, v)
            cookies = list(extra_cookies or [])
            if not self._csrf_cookie_value():
                cookies.append(f"{CSRF_COOKIE}={secrets.token_urlsafe(16)}; "
                              f"SameSite=Strict; Path=/")
            for c in cookies:
                self.send_header("Set-Cookie", c)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict | None:
            n = int(self.headers.get("Content-Length", 0) or 0)
            if n == 0:
                return {}
            raw = self.rfile.read(n)
            try:
                data = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None
            return data if isinstance(data, dict) else None

        # -- GET ---------------------------------------------------------------
        def do_GET(self) -> None:
            path = urlparse(self.path).path
            query = parse_qs(urlparse(self.path).query)

            if path != "/api" and not path.startswith("/api/"):
                resource = dashboard_resource(path)
                if resource is None:
                    return self._send_json(404, {"error": "dashboard resource not found"})
                body, content_type = resource
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                for key, value in SEC_HEADERS.items():
                    self.send_header(key, CSP if key == "Content-Security-Policy" else value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/api/stream":
                return self._stream()

            user = self._session_user()
            if path == "/api/me":
                if not user:
                    return self._send_json(401, {"error": "unauthenticated"})
                return self._send_json(200, {**user, "demo": True} if ctx.demo else user)
            if not user:
                return self._send_json(401, {"error": "unauthenticated"})

            if path == "/api/summary":
                return self._send_json(200, {
                    "today": ctx.store.today_counts(),
                    "lifetime": ctx.store.lifetime_counts(),
                })
            if path == "/api/day":
                try:
                    hours = int(query.get("hours", ["24"])[0])
                except ValueError:
                    hours = 24
                hours = max(1, min(hours, 168))
                return self._send_json(200, {"buckets": ctx.store.day_buckets(hours)})
            if path == "/api/record":
                try:
                    limit = int(query.get("limit", ["100"])[0])
                    offset = int(query.get("offset", ["0"])[0])
                except ValueError:
                    limit, offset = 100, 0
                rows = ctx.store.query(
                    decision=(query.get("decision") or [None])[0],
                    host=(query.get("host") or [None])[0],
                    tier=(query.get("tier") or [None])[0],
                    limit=max(1, min(limit, 500)), offset=max(0, offset))
                return self._send_json(200, {"rows": rows})
            if path == "/api/estate":
                return self._send_json(200, {
                    "assets": ctx.memory.list_assets(),
                    "facts": ctx.memory.list_facts(),
                })
            return self._send_json(404, {"error": "not found"})

        # -- POST --------------------------------------------------------------
        def do_POST(self) -> None:
            path = urlparse(self.path).path
            if path != "/api/login" and not self._session_user():
                return self._send_json(401, {"error": "unauthenticated"})
            if not self._check_csrf():
                return self._send_json(403, {"error": "csrf token missing or invalid"})
            body = self._read_json()
            if body is None:
                return self._send_json(400, {"error": "invalid json body"})

            if path == "/api/login":
                return self._login(body)

            user = self._session_user()
            if path == "/api/logout":
                return self._logout(user)
            if path == "/api/label":
                return self._label(user, body)
            if path == "/api/acknowledge":
                return self._acknowledge(user, body)
            return self._send_json(404, {"error": "not found"})

        def _login(self, body: dict) -> None:
            username = str(body.get("username", ""))[:200]
            password = str(body.get("password", ""))
            user = ctx.iam.authenticate(username, password)
            if not user:
                ctx.store.record_iam(username or "?", "login_failed")
                return self._send_json(401, {"error": "invalid credentials"})
            ctx.store.record_iam(user["username"], "login")
            token = ctx.iam.issue_session(user)
            cookie = (f"{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; "
                     f"Path=/; Max-Age={SESSION_TTL}")
            return self._send_json(200, {**user, "demo": True} if ctx.demo else user, extra_cookies=[cookie])

        def _logout(self, user: dict) -> None:
            ctx.store.record_iam(user["username"], "logout")
            dead = f"{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
            self._send_json(200, {"ok": True}, extra_cookies=[dead])
            # Portable Arbiter is a single-user foreground application. Give
            # the logout response time to reach the browser, then tell its
            # supervisor to stop. Installed/server deployments leave this
            # callback unset and continue serving other users normally.
            if ctx.shutdown is not None:
                timer = threading.Timer(0.25, ctx.shutdown)
                timer.daemon = True
                timer.start()

        def _label(self, user: dict, body: dict) -> None:
            signature = str(body.get("signature", ""))
            label = body.get("label")
            if not signature or label not in ("confirmed", "overruled"):
                return self._send_json(400, {
                    "error": "signature and label ('confirmed'|'overruled') required"})
            ctx.memory.label_verdicts(signature, label)
            ctx.store.record_iam(user["username"], "label", detail=f"{signature}={label}")
            return self._send_json(200, {"ok": True})

        def _acknowledge(self, user: dict, body: dict) -> None:
            try:
                row_id = int(body.get("id"))
            except (TypeError, ValueError):
                return self._send_json(400, {"error": "id required"})
            if not ctx.store.acknowledge(row_id, user["username"]):
                return self._send_json(404, {"error": "no such record"})
            return self._send_json(200, {"ok": True})

        # -- SSE ------------------------------------------------------------
        def _stream(self) -> None:
            user = self._session_user()
            if not user:
                return self._send_json(401, {"error": "unauthenticated"})
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
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                ctx.hub.unsubscribe(q)

    return Handler


def build_httpd(ctx: Ctx, host: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(ctx))


DEV_ACCOUNTS = {"admin": ("admin123", "admin"),
                "analyst": ("analyst123", "analyst")}


def serve(*, host: str, port: int, store_db: str, iam_db: str, mem_db: str,
          demo_feed: bool = False, events: str | None = None,
          backend: str = "mock", model: str = "qwen3.5:4b",
          demo_feed_interval: float = 2.0,
          dev_accounts: bool = False) -> None:
    store = AuditStore(store_db)
    secret_path = Path(iam_db).with_name(Path(iam_db).name + ".secret")
    secret = load_or_create_secret(secret_path)
    account = IAM(iam_db, secret=secret)
    if dev_accounts:
        # Dev/trial convenience: fixed, known-weak credentials, reset on every
        # boot so a lockout or a lost password never blocks local work.
        # Off by default; the installed service never passes it (see
        # install/service.py serve_argv, same treatment as --demo-feed).
        for name, (pw, role) in DEV_ACCOUNTS.items():
            if not account.set_password(name, pw):
                account.create_user(name, pw, role)
        print("!! --dev-accounts: passwords reset to KNOWN WEAK values")
        for name, (pw, _role) in DEV_ACCOUNTS.items():
            print(f"     {name:9}/ {pw}")
        print("!! never run this on anything reachable from outside localhost")
    elif not account.any_users():
        admin_pw = secrets.token_urlsafe(9)
        analyst_pw = secrets.token_urlsafe(9)
        account.create_user("admin", admin_pw, "admin")
        account.create_user("analyst", analyst_pw, "analyst")
        print("First run — created accounts:")
        print(f"  admin    / {admin_pw}")
        print(f"  analyst  / {analyst_pw}")

    mem = Memory(mem_db)
    ctx = Ctx(store=store, iam=account, memory=mem, hub=Hub())

    start_tail_poller(ctx)

    if demo_feed:
        if not events or not Path(events).exists():
            raise SystemExit(f"--demo-feed needs a real --events file (got {events!r})")
        start_demo_feed(ctx, mem, events, backend, model, demo_feed_interval)
        print(f"demo feed: replaying {events} into the store every "
              f"{demo_feed_interval}s (dev only — off by default)")

    httpd = build_httpd(ctx, host, port)
    print(f"Arbiter API on http://{host}:{port}  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
