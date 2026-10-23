import io
import json
from unittest.mock import Mock

import pytest

from arbiter.llm import get_backend
from arbiter.schema import Event
from arbiter.site_cloud import NoRedirect, WebsiteCloudBackend
from arbiter.site_demo import VisitorPool


def backend(monkeypatch, answer=None, limit=100):
    monkeypatch.setenv("OLLAMA_API_KEY", "private-test-key")
    cloud = WebsiteCloudBackend(hourly_limit=limit)
    answer = answer or {"decision": "escalate", "confidence": .9,
                        "rationale": "Unexpected process", "evidence": "Review process on h1"}
    cloud._opener = Mock()
    cloud._opener.open.side_effect = lambda *a, **k: io.BytesIO(json.dumps({"message": {"content": json.dumps(answer)}}).encode())
    return cloud


def event():
    return Event(source="test", host="h1", event_type="anomaly", message="Unexpected process")


def test_authenticated_live_request_and_metadata(monkeypatch):
    cloud = backend(monkeypatch)
    assert cloud.triage(event(), 1, "first occurrence", []).rationale == "Unexpected process"
    req = cloud._opener.open.call_args.args[0]
    assert req.full_url == "https://ollama.com/api/chat"
    assert req.get_header("Authorization") == "Bearer private-test-key"
    data = json.loads(req.data)
    assert data["model"] == "nemotron-3-nano:30b"
    assert "Unexpected process" in data["messages"][1]["content"]
    assert cloud.status()["succeeded"] == 1
    assert cloud.status()["active"] == 0
    assert "private-test-key" not in json.dumps(cloud.status())


def test_missing_key_cannot_silently_run_mock(monkeypatch):
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    cloud = WebsiteCloudBackend()
    assert not cloud.status()["configured"]
    with pytest.raises(RuntimeError, match="configure OLLAMA_API_KEY"):
        cloud.triage(event(), 1, "", [])
    with pytest.raises(ValueError):
        get_backend("ollama-cloud")  # Installed backend selector stays local-only.


def test_remote_failures_are_sanitized_and_not_mocked(monkeypatch):
    cloud = backend(monkeypatch)
    cloud._opener.open.side_effect = ValueError("secret private-test-key remote payload")
    with pytest.raises(RuntimeError, match="no AI verdict") as exc:
        cloud.triage(event(), 1, "", [])
    assert "private-test-key" not in str(exc.value)
    assert cloud.status()["failed"] == 1
    assert cloud.status()["succeeded"] == 0


def test_global_quota_and_context_limit(monkeypatch):
    cloud = backend(monkeypatch, limit=1)
    cloud.triage(event(), 1, "", [])
    with pytest.raises(RuntimeError, match="hourly allowance"):
        cloud.triage(event(), 1, "", [])
    assert cloud._opener.open.call_count == 1
    with pytest.raises(RuntimeError, match="context exceeds"):
        cloud.triage(event(), 1, "x" * 32769, [])
    assert cloud._opener.open.call_count == 1


def test_cloud_is_shared_by_isolated_visitors(monkeypatch):
    cloud = backend(monkeypatch)
    pool = VisitorPool(backend=cloud)
    try:
        _, first, _ = pool.acquire(None, create=True)
        _, second, _ = pool.acquire(None, create=True)
        assert first is not second
        assert first.backend is second.backend is cloud
    finally:
        pool.close()


def test_cloud_redirects_cannot_forward_api_key():
    with pytest.raises(ValueError, match="redirects"):
        NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.test")
