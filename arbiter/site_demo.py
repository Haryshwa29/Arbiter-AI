"""Standalone website + visitor-isolated simulations. No device API or collectors.

Run: python -m arbiter.site_demo --root work/public-site-preview --port 4173
Public deployment requires a same-origin reverse proxy with HTTPS and quotas.
"""
from __future__ import annotations

import argparse
from collections import deque
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import threading
import time
from urllib.parse import parse_qs, urlparse

from .api.server import prepared_datasets
from .ingestion.demo import DemoManager
from .ingestion.files import MAX_UPLOAD_BYTES, parse_upload
from .site_cloud import WebsiteCloudBackend

COOKIE = "arbiter_website_demo"
MAX_BODY = 6 * 1024 * 1024


class VisitorPool:
    def __init__(self, capacity=8, ttl=1800, clock=time.monotonic, backend="mock"):
        self.backend = backend
        self.capacity, self.ttl, self.clock = capacity, ttl, clock
        self.entries = {}
        self.lock = threading.RLock()

    def expire(self):
        with self.lock:
            expired = [key for key, entry in self.entries.items() if self.clock() - entry["seen"] > self.ttl]
            for key in expired:
                self.entries.pop(key)["manager"].close()

    def acquire(self, token, create=False):
        with self.lock:
            self.expire()
            fresh = False
            if token not in self.entries:
                if not create:
                    raise PermissionError("Demo session expired. Close and reopen the demo.")
                if len(self.entries) >= self.capacity:
                    raise OverflowError("All demo slots are busy. Please try again later.")
                token, fresh = secrets.token_urlsafe(32), True
                self.entries[token] = {"manager": DemoManager(backend=self.backend), "seen": self.clock(), "requests": deque()}
            entry = self.entries[token]
            stamp = self.clock()
            requests = entry["requests"]
            while requests and stamp - requests[0] > 60:
                requests.popleft()
            if len(requests) >= 300:
                raise OverflowError("Demo request limit reached. Wait a minute and try again.")
            requests.append(stamp)
            entry["seen"] = stamp
            return token, entry["manager"], fresh

    def close(self):
        with self.lock:
            for entry in self.entries.values():
                entry["manager"].close()
            self.entries.clear()


def selection(body, catalogue):
    if not isinstance(body, dict):
        raise ValueError("Expected an object containing datasets and uploads.")
    names, uploads = body.get("datasets", []), body.get("uploads", [])
    if not isinstance(names, list) or len(names) > 30 or any(not isinstance(name, str) or name not in catalogue for name in names):
        raise ValueError("Choose datasets from the available list.")
    if not isinstance(uploads, list) or len(uploads) > 20:
        raise ValueError("Choose at most 20 uploaded event files.")
    if any(not isinstance(item, dict) or not isinstance(item.get("content"), str) for item in uploads):
        raise ValueError("Uploads must contain a filename and text content.")
    if sum(len(item["content"].encode("utf-8")) for item in uploads) > MAX_UPLOAD_BYTES:
        raise ValueError("Combined upload limit is 5 MiB.")
    parsed = [parse_upload(*catalogue[name]) for name in dict.fromkeys(names)]
    parsed.extend(parse_upload(item.get("filename"), item["content"]) for item in uploads)
    if sum(len(item.events) + item.invalid_events for item in parsed) > 5000:
        raise ValueError("Choose at most 5,000 events per session.")
    return parsed


def make_server(root, host="127.0.0.1", port=4173, origin=None, pool=None):
    root = Path(root).resolve()
    if not (root / "arbiter-build.json").is_file() or json.loads((root / "arbiter-build.json").read_text())["target"] != "public":
        raise ValueError("Serve a public website build, never an installed dashboard build.")
    pool = pool or VisitorPool(backend=WebsiteCloudBackend())
    expected_origin = origin or f"http://{host}:{port}"
    allowed_host = urlparse(expected_origin).netloc
    catalogue = prepared_datasets()

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(root), **kwargs)

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *_):
            pass  # Do not log uploaded payloads, tokens or query event IDs.

        def end_headers(self):
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            super().end_headers()

        def reply(self, status, body, token=None):
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            if token:
                secure = "; Secure" if expected_origin.startswith("https:") else ""
                self.send_header("Set-Cookie", f"{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/public-demo; Max-Age=1800{secure}")
            self.end_headers()
            self.wfile.write(data)

        def token(self):
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get("Cookie", ""))
                return cookie[COOKIE].value if COOKIE in cookie else None
            except Exception:
                return None

        def api(self, write=False):
            if self.headers.get("Host") != allowed_host or self.headers.get("X-Arbiter-Demo") != "1" or self.headers.get("Origin", expected_origin) != expected_origin:
                return self.reply(403, {"error": "Use the demo from this website."})
            path = urlparse(self.path)
            route = path.path.removeprefix("/public-demo/")
            if route not in ({"start", "preview", "control"} if write else {"datasets", "status", "event", "history"}):
                return self.reply(404, {"error": "Unknown demo route."})
            try:
                if route == "datasets":
                    return self.reply(200, {"datasets": list(catalogue)})
                if write:
                    if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                        raise ValueError("Upload event data as JSON request content.")
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= MAX_BODY:
                        raise ValueError("Request exceeds the demo upload limit.")
                    body = json.loads(self.rfile.read(length))
                    if not isinstance(body, dict):
                        raise ValueError("Invalid demo request.")
                # Serialize pool lifetime and operations so expiry cannot close
                # databases during a concurrent visitor request.
                with pool.lock:
                    token, manager, fresh = pool.acquire(self.token(), create=route == "status")
                    if write:
                        if route == "control":
                            result = manager.control(body.get("action"))
                        else:
                            parsed = selection(body, catalogue)
                            if route == "preview":
                                result = {"files": [item.summary() for item in parsed]}
                            else:
                                if isinstance(pool.backend, WebsiteCloudBackend):
                                    pool.backend.require_configured()
                                    if body.get("uploads") and body.get("cloud_consent") is not True:
                                        raise ValueError("Confirm that uploaded sample data may be sent to Ollama Cloud.")
                                    if sum(len(item.events) for item in parsed) > 100:
                                        raise ValueError("Live cloud demos allow at most 100 events per run.")
                                if any(item.invalid_events for item in parsed):
                                    raise ValueError("Some events are invalid. Validate the selection first.")
                                result = manager.start([item.events for item in parsed], body.get("speed", "1x"), body.get("order", "mixed"), body.get("seed", 0), body.get("traffic", "steady"))
                    elif route == "status":
                        result = manager.status()
                    else:
                        query = {key: values[0] for key, values in parse_qs(path.query).items()}
                        if route == "event":
                            result = manager.detail(query.get("id", ""))
                            if result is None:
                                return self.reply(404, {"error": "This event does not belong to your demo session."})
                        else:
                            offset = int(query.get("offset", "0"))
                            if not 0 <= offset <= 5000:
                                raise ValueError("Invalid history offset.")
                            result = manager.history(offset, query)
                    if route in {"status", "start", "control"}:
                        result["inference"] = pool.backend.status() if isinstance(pool.backend, WebsiteCloudBackend) else {"backend": "mock", "configured": False}
                    return self.reply(200, result, token)
            except RuntimeError as exc:
                self.reply(503, {"error": str(exc)})
            except PermissionError as exc:
                self.reply(403, {"error": str(exc)})
            except OverflowError as exc:
                self.reply(429, {"error": str(exc)})
            except (ValueError, TypeError, KeyError, RecursionError, UnicodeError) as exc:
                self.reply(400, {"error": str(exc)[:300] or "Invalid event data."})

        def do_GET(self):
            path = urlparse(self.path).path
            if path.startswith("/public-demo/"):
                return self.api()
            if path.startswith(("/api/", "/app", "/health")):
                return self.reply(404, {"error": "Operational routes are not available on the website."})
            # This server exposes only the public build, never repo/data files.
            resolved = Path(self.translate_path(path)).resolve()
            if not resolved.is_relative_to(root) or resolved.is_dir() and path != "/":
                return self.reply(404, {"error": "Not found."})
            super().do_GET()

        def do_POST(self):
            if urlparse(self.path).path.startswith("/public-demo/"):
                return self.api(write=True)
            self.reply(404, {"error": "Only simulation operations are available."})

        def do_HEAD(self):
            self.reply(405, {"error": "Method unavailable."})

    server = ThreadingHTTPServer((host, port), Handler)
    if port == 0 and origin is None:
        expected_origin = f"http://{host}:{server.server_port}"
        allowed_host = urlparse(expected_origin).netloc
    server.demo_pool = pool
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4173)
    parser.add_argument("--origin", default=os.environ.get("ARBITER_SITE_ORIGIN"), help="Exact external HTTPS website origin behind a reverse proxy")
    parser.add_argument("--model", default="nemotron-3-nano:30b", help="Ollama cloud API model ID (not the CLI :cloud alias)")
    parser.add_argument("--ai-hourly-limit", type=int, default=100, help="Maximum cloud requests per hour across all visitors")
    args = parser.parse_args()
    backend = WebsiteCloudBackend(args.model, args.ai_hourly_limit)
    server = make_server(args.root, args.host, args.port, args.origin, VisitorPool(backend=backend))
    stopping = threading.Event()
    def reap():
        while not stopping.wait(30):
            server.demo_pool.expire()
    threading.Thread(target=reap, daemon=True).start()
    try:
        print(f"Website demo listening at {args.origin or f'http://{args.host}:{args.port}'}", flush=True)
        server.serve_forever()
    finally:
        stopping.set()
        server.server_close()
        server.demo_pool.close()


if __name__ == "__main__":
    main()
