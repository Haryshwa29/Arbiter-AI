import http.cookiejar
import json
import threading
import urllib.error
import urllib.request

import pytest

from arbiter.site_demo import VisitorPool, make_server, selection


@pytest.fixture
def website(tmp_path):
    (tmp_path / "arbiter-build.json").write_text('{"target":"public"}')
    (tmp_path / "index.html").write_text("website only")
    pool = VisitorPool()
    server = make_server(tmp_path, port=0, pool=pool)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", pool
    server.shutdown()
    server.server_close()
    thread.join()
    pool.close()


def visitor():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def request(client, base, route, body=None, headers=None):
    req = urllib.request.Request(base + route, data=None if body is None else json.dumps(body).encode(),
        headers={"X-Arbiter-Demo": "1", "Content-Type": "application/json", **(headers or {})})
    try:
        result = client.open(req)
    except urllib.error.HTTPError as exc:
        result = exc
    return result.status, json.loads(result.read())


def test_visitors_have_isolated_events_and_no_operational_access(website):
    base, pool = website
    first, second = visitor(), visitor()
    for client in (first, second):
        assert request(client, base, "/public-demo/status")[0] == 200
    payload = {"datasets": ["events.jsonl"], "speed": "10x", "order": "random", "seed": 8, "traffic": "bursts"}
    assert request(first, base, "/public-demo/preview", payload)[1]["files"][0]["valid_events"] > 0
    assert request(first, base, "/public-demo/start", payload)[0] == 200
    manager = next(entry["manager"] for entry in pool.entries.values() if entry["manager"].session)
    manager.session.control("pause")
    with manager.session.lock:
        manager.session.state = "running"
        manager.session.tick()
        manager.session.state = "paused"
    row = request(first, base, "/public-demo/status")[1]["events"][0]
    assert request(first, base, "/public-demo/event?id=" + row["event_id"])[0] == 200
    assert request(second, base, "/public-demo/event?id=" + row["event_id"])[0] == 404
    assert request(second, base, "/public-demo/status")[1]["events"] == []
    assert request(first, base, "/public-demo/history")[1]["total"] >= 1
    assert request(first, base, "/public-demo/control", {"action":"resume"})[0] == 200
    assert request(first, base, "/public-demo/control", {"action":"stop"})[1]["state"] == "stopped"
    for route in ("/api/events", "/api/protection/approve", "/app/login", "/health"):
        assert request(first, base, route)[0] == 404


def test_upload_validation_and_same_origin_boundary(website):
    base, _ = website
    client = visitor()
    assert request(client, base, "/public-demo/status", headers={"Origin":"https://elsewhere.test"})[0] == 403
    assert request(client, base, "/public-demo/status", headers={"X-Arbiter-Demo":""})[0] == 403
    request(client, base, "/public-demo/status")
    payload = {"uploads":[{"filename":"case.jsonl", "content":'{"source":"demo","host":"test","event_type":"login","message":"test","severity":2}'}]}
    assert request(client, base, "/public-demo/preview", payload)[1]["files"][0]["valid_events"] == 1
    for filename in ("../../case.jsonl", "anything.exe", "document.pdf"):
        payload["uploads"][0]["filename"] = filename
        assert request(client, base, "/public-demo/preview", payload)[0] == 400
    assert request(client, base, "/public-demo/start", {"datasets":["events.jsonl"], "speed":"unbounded"})[0] == 400
    assert request(client, base, "/public-demo/history?offset=-1")[0] == 400


def test_pool_is_bounded_expires_and_never_uses_device_backend():
    clock = [0]
    pool = VisitorPool(capacity=1, ttl=2, clock=lambda: clock[0])
    token, manager, fresh = pool.acquire(None, create=True)
    assert fresh and manager.backend == "mock"
    with pytest.raises(OverflowError):
        pool.acquire(None, create=True)
    clock[0] = 3
    pool.expire()
    assert not pool.entries
    with pytest.raises(PermissionError):
        pool.acquire(token)
    pool.close()


def test_combined_upload_limit_and_public_build_required(tmp_path):
    with pytest.raises(ValueError, match="Combined upload"):
        selection({"uploads":[{"filename":"x.json", "content":" " * (3*1024*1024)}] * 2}, {})
    (tmp_path / "arbiter-build.json").write_text('{"target":"self-hosted"}')
    with pytest.raises(ValueError, match="public website"):
        make_server(tmp_path, port=0)
