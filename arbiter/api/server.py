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
import ipaddress
import sys
import threading
import time
from dataclasses import dataclass, replace
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlparse

from ..iam import IAM, SESSION_TTL, load_or_create_secret
from ..memory import Memory
from ..briefing import validate_briefing
from ..store import AuditStore
from .static import CSP, dashboard_resource
from ..ingestion.schema import safe_json
from ..ingestion.service import IngestionService, ingestion_path
from ..ingestion.store import BufferFull
from ..ingestion.demo import DemoManager
from ..ingestion.files import parse_upload
from ..ingestion.permissions import request_elevation
from ..ingestion.protection import Protection
from ..ingestion.response_workflow import ResponseWorkflow
from ..ingestion.models import available_models

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
    backend: str = "mock"
    shutdown: Callable[[], None] | None = None
    ingestion: IngestionService | None = None
    simulator: DemoManager | None = None
    elevate: Callable[[], None] | None = None
    protection: Protection | None = None
    responses: ResponseWorkflow | None = None
    local_access: bool = False


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
    return {"id": row["id"], "event_id": row["event_id"], "ts": row["ts"], "host": row["host"],
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


def start_tail_poller(ctx: Ctx, interval: float = 1.0,
                      stop: threading.Event | None = None) -> threading.Thread:
    t = threading.Thread(target=tail_poller, args=(ctx, interval, stop), daemon=True)
    t.start()
    return t


def _feed_paths(events_path: str) -> list[Path]:
    path = Path(events_path)
    if path.is_dir():
        return sorted(p for p in path.iterdir()
                      if p.is_file() and p.suffix.lower() in (".json", ".jsonl"))
    return [path]


def _feed_revision(events_path: str) -> tuple:
    """Cheap change token used by the portable live-editable demo folder."""
    try:
        return tuple((str(path), path.stat().st_mtime_ns, path.stat().st_size)
                     for path in _feed_paths(events_path))
    except OSError:
        return ()


def load_feed_events(events_path: str) -> list["Event"]:
    """Read a JSON/JSONL file or directory, tolerating both sample shapes.

    `samples/events.jsonl` is one bare Event per line. The eval suites
    (`realistic_suite.jsonl`, `adversarial_suite.jsonl`, ...) wrap each event
    in a labelled case: `{"event": {...}, "expected": ..., "facts": [...]}`.
    A `.json` file may contain one such object or a list of objects. A directory
    loads its top-level `.json` and `.jsonl` files in filename order, which is
    how the portable demo exposes individually named, editable scenarios.
    Pointing --demo-feed at a suite used to raise TypeError on the first line
    and kill the feeder thread, leaving the dashboard empty with the reason
    only in the server log — so unwrap the labelled shape here.

    Unparseable lines are reported and skipped rather than taking the whole
    feed down; this is dev scaffolding, not the ingest path a collector uses.
    """
    from ..schema import Event

    events: list[Event] = []
    for path in _feed_paths(events_path):
        try:
            if path.suffix.lower() == ".json":
                decoded = json.loads(path.read_text(encoding="utf-8"))
                objects = decoded if isinstance(decoded, list) else [decoded]
            else:
                objects = []
                for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        objects.append(json.loads(line))
                    except json.JSONDecodeError as exc:
                        print(f"!! --demo-feed: {path}:{n} skipped: {exc}")
            for n, data in enumerate(objects, start=1):
                try:
                    # A labelled case carries the event under "event"; a bare
                    # event never has that key (it is not a field on Event).
                    if isinstance(data, dict) and isinstance(data.get("event"), dict):
                        data = data["event"]
                    events.append(Event(**data))
                except (TypeError, ValueError) as exc:
                    print(f"!! --demo-feed: {path}:{n} skipped: {exc}")
        except (json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
            print(f"!! --demo-feed: {path} skipped: {exc}")
    return events


def demo_feed_loop(ctx: Ctx, mem: Memory, events_path: str, backend: str,
                   model: str, interval: float,
                   stop: threading.Event | None = None,
                   ollama_url: str = "http://localhost:11434",
                   reload_on_change: bool = False) -> None:
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
    if ctx.simulator:
        from ..ingestion.normalization import normalize
        stop = stop or threading.Event()
        while not stop.is_set():
            if ctx.simulator.status()["state"] in {"ready", "completed"}:
                events = load_feed_events(events_path)
                if events:
                    ctx.simulator.start([[normalize(json.loads(event.to_json()), "legacy") for event in events]], "1x")
            stop.wait(max(.1, interval))
        return
    llm = OllamaBackend(model=model, url=ollama_url) if backend == "ollama" else get_backend(backend, model=model)
    engine = TriageEngine(memory=mem, llm=llm,
                          audit_path=os.devnull, shadow=True)
    stop = stop or threading.Event()
    i = 0
    revision = _feed_revision(events_path)
    while not stop.is_set():
        if reload_on_change:
            current = _feed_revision(events_path)
            if current != revision:
                refreshed = load_feed_events(events_path)
                if refreshed:
                    events = refreshed
                    i = 0
                    print(f"-- demo feed reloaded: {len(events)} events from {events_path}",
                          flush=True)
                else:
                    print("!! --demo-feed: change detected but no usable events; "
                          "keeping the previous set", flush=True)
                revision = current
        event = replace(events[i % len(events)], id="", timestamp="")
        try:
            if ctx.ingestion:
                ctx.ingestion.submit(event, connector="replay")
            else:
                # Low-level API consumers/tests that supply no lifecycle owner.
                verdict = engine.triage(event)
                ctx.store.record_verdict(event, verdict)
        except Exception as exc:  # one bad event must not kill the thread
            print(f"!! --demo-feed: {event.signature} failed to triage: "
                  f"{exc!r}", flush=True)
        i += 1
        stop.wait(interval)


def start_demo_feed(ctx: Ctx, mem: Memory, events_path: str, backend: str,
                    model: str, interval: float, stop: threading.Event | None = None,
                    ollama_url: str = "http://localhost:11434") -> threading.Thread:
    t = threading.Thread(target=demo_feed_loop,
                         args=(ctx, mem, events_path, backend, model, interval, stop, ollama_url),
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
            if ctx.local_access:
                # Explicit owner mode: no forwarded headers or DNS names can
                # turn a remote/rebound request into a trusted local request.
                port = self.server.server_address[1]
                hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
                host = self.headers.get("Host", "").lower()
                origin = self.headers.get("Origin")
                site = self.headers.get("Sec-Fetch-Site")
                if (host not in hosts or not ipaddress.ip_address(self.client_address[0]).is_loopback
                        or site not in (None, "same-origin", "none")
                        or (origin is not None and origin != "http://" + host)):
                    return None
                return {"username": "Local owner", "role": "admin", "local_access": True}
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
            try:
                n = int(self.headers.get("Content-Length", 0) or 0)
            except ValueError:
                return None
            if n < 0 or n > 8 * 1024 * 1024 or self.headers.get("Transfer-Encoding"):
                return None
            if n == 0:
                return {}
            self.connection.settimeout(10)
            raw = self.rfile.read(n)
            try:
                data = safe_json(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return None
            return data if isinstance(data, dict) else None

        # -- GET ---------------------------------------------------------------
        def do_GET(self) -> None:
            path = urlparse(self.path).path
            query = parse_qs(urlparse(self.path).query)

            if path == "/health":
                if not self._session_user():
                    return self._send_json(401, {"error": "unauthenticated"})
                return self._send_json(200, {"ok": True, "ingestion": bool(ctx.ingestion and
                    ctx.ingestion.pipeline.thread and ctx.ingestion.pipeline.thread.is_alive())})

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
                return self._send_json(200, {**user, "demo": ctx.demo,
                                             "backend": ctx.backend})
            if not user:
                return self._send_json(401, {"error": "unauthenticated"})

            if path == "/api/models":
                return self._send_json(200, available_models(ctx.ingestion.ollama_url) if ctx.ingestion else {"available": False, "models": []})

            if path in {"/api/demo/status", "/api/demo/event", "/api/demo/history"}:
                if not ctx.simulator:
                    return self._send_json(503, {"error": "simulator unavailable"})
                if path == "/api/demo/history":
                    try:
                        offset = max(0, int((query.get("offset") or ["0"])[0]))
                    except ValueError:
                        return self._send_json(400, {"error": "invalid offset"})
                    return self._send_json(200, ctx.simulator.history(offset, {key: (query.get(key) or [""])[0] for key in ("decision", "event_type", "host", "source", "response", "search")}))
                if path == "/api/demo/status":
                    return self._send_json(200, ctx.simulator.status())
                event = ctx.simulator.detail((query.get("id") or [""])[0])
                return self._send_json(200 if event else 404, event or {"error": "event not found"})

            if path == "/api/response/status":
                return self._send_json(200, ctx.responses.status() if ctx.responses else {"stopped": True, "error": "Response workflow unavailable; restart the dashboard server.", "cases": []})

            if path in {"/api/ingestion/status", "/api/events", "/api/event", "/api/ingestion/assets", "/api/datasets"}:
                if not ctx.ingestion:
                    return self._send_json(503, {"error": "ingestion service unavailable"})
                if path == "/api/ingestion/status":
                    return self._send_json(200, {**ctx.ingestion.status(), "can_request_permission": ctx.elevate is not None})
                if path == "/api/ingestion/assets":
                    return self._send_json(200, {"assets": ctx.ingestion.buffer.assets()})
                if path == "/api/datasets":
                    return self._send_json(200, {"datasets": list(prepared_datasets())})
                if path == "/api/event":
                    event = ctx.ingestion.buffer.detail((query.get("id") or [""])[0])
                    if event and ctx.responses:
                        event = ctx.responses.enrich(event)
                    if event and ctx.protection:
                        event["protection_proposal"] = ctx.protection.proposal(event)
                        event["protection_actions"] = ctx.protection.actions(event["event_id"])
                    return self._send_json(200 if event else 404, event or {"error": "event not found"})
                try:
                    filters = {k: v[0] for k, v in query.items() if k in {"source", "host", "severity", "category", "since", "ip", "username", "scope"}}
                    rows = ctx.ingestion.buffer.query(filters, int(query.get("limit", ["100"])[0]), int(query.get("offset", ["0"])[0]))
                except (ValueError, OverflowError):
                    return self._send_json(400, {"error": "invalid event filters"})
                return self._send_json(200, {"events": rows})

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
                    event_id=(query.get("event_id") or [None])[0],
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
            try:
                size = int(self.headers.get("Content-Length", 0) or 0)
            except ValueError:
                return self._send_json(400, {"error": "invalid content length"})
            if size > 8 * 1024 * 1024:
                return self._send_json(413, {"error": "request exceeds 8 MiB"})
            body = self._read_json()
            if body is None:
                return self._send_json(400, {"error": "invalid json body"})

            if path == "/api/login":
                return self._login(body)

            user = self._session_user()
            if path in {"/api/briefing/preview", "/api/briefing/save", "/api/briefing/remove"}:
                if not require_admin(user):
                    return self._send_json(403, {"error": "administrator role required"})
                try:
                    if path.endswith("remove"):
                        fact_id = body.get("id")
                        if type(fact_id) is not int or fact_id < 1:
                            raise ValueError("valid briefing id required")
                        if not ctx.memory.remove_briefing(fact_id):
                            return self._send_json(404, {"error": "briefing not found"})
                        ctx.store.record_iam(user["username"], "briefing_removed", str(fact_id))
                        return self._send_json(200, {"ok": True})
                    briefing = validate_briefing(body)
                    if path.endswith("preview"):
                        return self._send_json(200, {"briefing": briefing})
                    fact_id = ctx.memory.save_briefing(briefing, user["username"])
                    ctx.store.record_iam(user["username"], "briefing_saved", json.dumps({"id": fact_id, **briefing}))
                    return self._send_json(200, {"id": fact_id})
                except (ValueError, TypeError):
                    return self._send_json(400, {"error": "invalid briefing; supply an exact host, context, valid priority and future expiry"})
            if path == "/api/models/connect":
                if not require_admin(user): return self._send_json(403, {"error": "administrator role required"})
                if not ctx.ingestion: return self._send_json(400, {"error": "ingestion unavailable"})
                if ctx.simulator and ctx.simulator.status()["state"] in {"running", "paused"}:
                    return self._send_json(400, {"error": "stop the simulation before changing the analysis model"})
                try:
                    ctx.ingestion.connect_model(body.get("model"))
                    ctx.backend = ctx.ingestion.backend
                    if ctx.simulator: ctx.simulator.close()
                    ctx.simulator = DemoManager(ctx.ingestion.backend, ctx.ingestion.model, ctx.ingestion.ollama_url)
                    ctx.store.record_iam(user["username"], "local_model_connected", ctx.ingestion.model)
                    return self._send_json(200, {"backend": ctx.backend})
                except (ValueError, OSError, RuntimeError):
                    return self._send_json(400, {"error": "local model unavailable; check the inference service and installed models"})

            if path in {"/api/response/control", "/api/demo/response/control"}:
                if not require_admin(user) or not ipaddress.ip_address(self.client_address[0]).is_loopback:
                    return self._send_json(403, {"error": "local administrator session required"})
                try:
                    if path == "/api/demo/response/control" and ctx.simulator:
                        result = ctx.simulator.response_control(body.get("event_id", ""), body.get("command", ""), user["username"], body.get("reason", ""))
                    elif path == "/api/response/control" and ctx.responses:
                        reason = body.get("reason", "")
                        if not isinstance(reason, str): raise ValueError("invalid reason")
                        result = ctx.responses.control(body.get("event_id", ""), body.get("command", ""), user["username"], reason, body.get("protected_networks"))
                    else: raise ValueError("response workflow unavailable")
                    return self._send_json(200, result)
                except (ValueError, TypeError, OSError) as exc:
                    return self._send_json(400, {"error": str(exc) if isinstance(exc, ValueError) else "invalid response request"})

            if path in {"/api/protection/approve", "/api/protection/undo"}:
                if not require_admin(user) or not ipaddress.ip_address(self.client_address[0]).is_loopback:
                    return self._send_json(403, {"error": "local administrator session required"})
                if not ctx.protection:
                    return self._send_json(400, {"error": "device protection unavailable"})
                try:
                    with (ctx.responses.lock if ctx.responses else ctx.protection.lock):
                        result = ctx.protection.approve(body.get("event_id", ""), user["username"]) if path.endswith("approve") else ctx.protection.undo(body.get("action_id", ""), user["username"])
                        if ctx.responses and result:
                            case = ctx.responses.ensure(ctx.ingestion.buffer.detail(result[0]["event_id"]))
                            if case:
                                case.update(state="executed" if path.endswith("approve") else "undone", mode="manual", note="Operator-approved native action; inspect the verified action record below.")
                                ctx.responses.save(case, "l1_manual_action", user["username"])
                    return self._send_json(200, {"actions": result})
                except (ValueError, OSError):
                    return self._send_json(400, {"error": "action unavailable or failed; check event evidence and Windows administrator access"})

            if path == "/api/permissions/request":
                if not require_admin(user) or not ipaddress.ip_address(self.client_address[0]).is_loopback:
                    return self._send_json(403, {"error": "local administrator session required"})
                if not ctx.elevate:
                    return self._send_json(400, {"error": "restart the local packaged dashboard as administrator"})
                try:
                    ctx.elevate()
                    ctx.store.record_iam(user["username"], "permission_requested", "Windows UAC relaunch")
                    return self._send_json(202, {"status": "restarting"})
                except (ValueError, OSError, TimeoutError):
                    return self._send_json(400, {"error": "Windows permission request cancelled, timed out, or unavailable"})

            if path in {"/api/demo/start", "/api/demo/control", "/api/demo/preview"}:
                if not require_admin(user):
                    return self._send_json(403, {"error": "administrator role required"})
                if not ctx.simulator:
                    return self._send_json(503, {"error": "simulator unavailable"})
                try:
                    if path == "/api/demo/control":
                        result = ctx.simulator.control(body.get("action"))
                    else:
                        catalogue = prepared_datasets()
                        names = body.get("datasets", [])
                        if not isinstance(names, list) or len(names) > 30 or any(not isinstance(name, str) or name not in catalogue for name in names):
                            raise ValueError("invalid dataset selection")
                        parsed_files = [parse_upload(*catalogue[name]) for name in dict.fromkeys(names)]
                        groups = [parsed.events for parsed in parsed_files]
                        uploads = body.get("uploads", [])
                        if not isinstance(uploads, list) or len(uploads) > 20:
                            raise ValueError("invalid uploads")
                        for upload in uploads:
                            if not isinstance(upload, dict): raise ValueError("invalid upload")
                            parsed = parse_upload(upload.get("filename"), upload.get("content"), body.get("source", "auto"))
                            parsed_files.append(parsed)
                            groups.append(parsed.events)
                        if path == "/api/demo/preview":
                            return self._send_json(200, {"files": [parsed.summary() for parsed in parsed_files]})
                        if any(parsed.invalid_events for parsed in parsed_files):
                            raise ValueError("selection contains invalid records; validate first")
                        result = ctx.simulator.start(groups, body.get("speed", "1x"), body.get("order", "mixed"), body.get("seed", 0), body.get("traffic", "steady"))
                    ctx.store.record_iam(user["username"], "simulation_control", result["state"])
                    return self._send_json(200, result)
                except (ValueError, TypeError, KeyError):
                    return self._send_json(400, {"error": "invalid simulation request; check datasets, playback settings and current session"})

            if path in {"/api/ingestion/configure", "/api/ingestion/import", "/api/ingestion/submit", "/api/ingestion/dataset"}:
                if not ctx.ingestion:
                    return self._send_json(503, {"error": "ingestion service unavailable"})
                if not require_admin(user):
                    return self._send_json(403, {"error": "administrator role required for ingestion writes"})
                try:
                    if path == "/api/ingestion/configure":
                        ctx.ingestion.configure(body.get("name"), body.get("enabled"), body.get("configuration", {}))
                        ctx.store.record_iam(user["username"], "connector_configured", str(body.get("name", "")))
                        return self._send_json(200, {"ok": True})
                    if path == "/api/ingestion/submit":
                        accepted = ctx.ingestion.submit(body.get("event"), body.get("source", "auto"))
                        return self._send_json(202, {"accepted": accepted})
                    if ctx.simulator and not body.get("preview", False):
                        return self._send_json(400, {"error": "dataset playback belongs in the isolated simulation workspace; use /api/demo/start"})
                    if path == "/api/ingestion/dataset":
                        datasets = prepared_datasets()
                        name = body.get("dataset")
                        if name not in datasets:
                            raise ValueError("unknown prepared dataset")
                        filename, content = datasets[name]
                    else:
                        filename, content = body.get("filename"), body.get("content")
                    result = ctx.ingestion.import_file(filename, content, body.get("source", "auto"),
                        body.get("speed", "instant"), body.get("preview", False))
                    ctx.store.record_iam(user["username"], "dataset_preview" if body.get("preview") else "dataset_import", result["filename"])
                    return self._send_json(200 if body.get("preview") else 202, result)
                except BufferFull:
                    return self._send_json(429, {"error": "event queue full; retry when processing catches up"})
                except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
                    return self._send_json(400, {"error": "invalid ingestion request; check file, source and configuration"})
                except RuntimeError:
                    return self._send_json(409, {"error": "source is still stopping; retry shortly"})
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
            return self._send_json(200, {**user, "demo": ctx.demo,
                                         "backend": ctx.backend},
                                   extra_cookies=[cookie])

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
    if ctx.local_access and not ipaddress.ip_address(host).is_loopback:
        raise ValueError("local access requires a literal loopback bind address")
    return ThreadingHTTPServer((host, port), make_handler(ctx))


def prepared_datasets() -> dict:
    """Fixed allowlisted files; no request-controlled filesystem paths."""
    roots = [Path(__file__).resolve().parents[2] / "samples"]
    if hasattr(__import__("sys"), "argv"):
        import sys
        roots.append(Path(sys.argv[0]).resolve().parent / "samples")
    result = {}
    # importlib.resources also works inside a release zipapp.
    from importlib.resources import files
    bundled = files("arbiter").joinpath("datasets")
    if bundled.is_dir():
        for path in bundled.iterdir():
            if path.name.endswith(".jsonl") and path.is_file():
                result[path.name] = (path.name, path.read_text(encoding="utf-8"))
    # Portable editable cases are allowlisted afresh on each request.
    case_root = Path(__import__("sys").argv[0]).resolve().parent / "Demo Test Cases" / "Active"
    if case_root.is_dir():
        for path in case_root.iterdir():
            if path.is_file() and path.suffix in {".json", ".jsonl"} and path.stat().st_size <= 5 * 1024 * 1024:
                result["case:" + path.name] = (path.name, path.read_text(encoding="utf-8"))
    for root in roots:
        if root.is_dir():
            for path in root.glob("*.jsonl"):
                if path.stat().st_size <= 5 * 1024 * 1024:
                    result[path.name] = (path.name, path.read_text(encoding="utf-8"))
    return result


DEV_ACCOUNTS = {"admin": ("admin123", "admin"),
                "analyst": ("analyst123", "analyst")}


def serve(*, host: str, port: int, store_db: str, iam_db: str, mem_db: str,
          demo_feed: bool = False, events: str | None = None,
          backend: str = "mock", model: str = "qwen3.5:4b",
          demo_feed_interval: float = 2.0,
          dev_accounts: bool = False,
          ollama_url: str = "http://localhost:11434",
          health_callback=None, local_access: bool = False) -> None:
    if local_access and not ipaddress.ip_address(host).is_loopback:
        raise ValueError("local access requires a literal loopback bind address")
    if demo_feed and (not events or not Path(events).exists()):
        raise SystemExit(f"--demo-feed needs a real --events file (got {events!r})")
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
    ctx = Ctx(store=store, iam=account, memory=mem, hub=Hub(), backend=backend,
              local_access=local_access)
    ctx.ingestion = IngestionService(ingestion_path(store_db), mem, store, backend, model, ollama_url)
    ctx.backend = ctx.ingestion.backend
    ctx.simulator = DemoManager(ctx.ingestion.backend, ctx.ingestion.model, ollama_url)
    ctx.protection = Protection(ctx.ingestion.buffer, store, verify=True)
    ctx.responses = ResponseWorkflow(ctx.ingestion.buffer, store, ctx.protection)
    # Preserve earlier demo imports as an archive rather than device detections.
    with ctx.ingestion.buffer.lock:
        old_demo_ids = [r[0] for r in ctx.ingestion.buffer.conn.execute("SELECT event_id FROM telemetry WHERE connector IN ('file','replay')")]
    with store._lock, store.conn:
        store.conn.executemany("UPDATE audit SET kind='demo_verdict' WHERE kind='verdict' AND event_id=?", [(event_id,) for event_id in old_demo_ids])
    stop = threading.Event()
    httpd = poller = demo_thread = health_thread = None
    health_failure = []
    try:
        httpd = build_httpd(ctx, host, port)
        if Path(sys.argv[0]).suffix == ".pyz" and "serve" in sys.argv and ipaddress.ip_address(host).is_loopback:
            def elevate():
                argv = ["-u", str(Path(sys.argv[0]).resolve()), "--db", str(Path(mem_db).resolve()),
                    "serve", "--host", host, "--port", str(port), "--store-db", str(Path(store_db).resolve()),
                    "--iam-db", str(Path(iam_db).resolve()), "--backend", backend, "--model", model]
                if local_access:
                    argv.append("--local-access")
                request_elevation(argv, port)
                threading.Timer(.5, httpd.shutdown).start()
            ctx.elevate = elevate
        ctx.ingestion.start(discover=True)
        ctx.responses.start()
        if health_callback:
            def monitor():
                while not stop.is_set():
                    try:
                        with ctx.ingestion.lock:
                            health = ctx.ingestion.status(include_metrics=False)
                            worker = ctx.ingestion.pipeline
                            if not health["worker_alive"] or time.monotonic() - worker.last_activity > 180:
                                raise RuntimeError("analysis worker stopped or stalled")
                            for collector in ctx.ingestion.collectors.values():
                                if not collector.thread or not collector.thread.is_alive():
                                    raise RuntimeError("enabled collector stopped")
                        health_callback(health)
                    except Exception as exc:
                        health_failure.append(True)
                        print(f"Monitoring health check failed ({type(exc).__name__}); restarting the installed process")
                        httpd.shutdown()
                        return
                    stop.wait(10)
            health_thread = threading.Thread(target=monitor, daemon=True)
            health_thread.start()
        poller = start_tail_poller(ctx, stop=stop)
        if demo_feed:
            demo_thread = start_demo_feed(ctx, mem, events, backend, model, demo_feed_interval, stop, ollama_url)
            print(f"demo feed: replaying {events} into the store every "
                  f"{demo_feed_interval}s (dev only — off by default)")
        print(f"Arbiter API on http://{host}:{port}  (Ctrl-C to stop)")
        httpd.serve_forever()
        if health_failure:
            raise RuntimeError("monitoring health failed; service recovery required")
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        stop.set()
        if httpd:
            httpd.server_close()
        if health_thread:
            health_thread.join(timeout=2)
        if poller:
            poller.join(timeout=2)
        if demo_thread:
            demo_thread.join(timeout=3)
        ctx.responses.close()
        ctx.simulator.close()
        ctx.ingestion.stop()
        mem.close()
        account.close()
        store.close()
