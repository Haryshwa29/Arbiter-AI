"""Ollama Cloud adapter exclusively for the opt-in public website simulator.

Never registered in get_backend: installed monitoring remains local-only.
"""
import json
import os
import threading
import time
import urllib.request
from collections import deque

from .llm import LLMBackend, SYSTEM_PROMPT, build_prompt, parse_response


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Cloud redirects are disabled")


class WebsiteCloudBackend(LLMBackend):
    name = "ollama-cloud"

    def __init__(self, model="nemotron-3-nano:30b", hourly_limit=100):
        if not isinstance(hourly_limit, int) or not 1 <= hourly_limit <= 10000:
            raise ValueError("Cloud hourly limit must be between 1 and 10000")
        if not model or len(model) > 120 or any(c.isspace() for c in model):
            raise ValueError("Invalid cloud model name")
        self.model = model
        self._key = os.environ.get("OLLAMA_API_KEY", "").strip()
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self._slot = threading.Lock()
        self._lock = threading.Lock()
        self._calls = deque()
        self.limit = hourly_limit
        self.active = self.succeeded = self.failed = 0
        self.error = ""

    def status(self):
        with self._lock:
            return {"backend": self.name, "model": self.model,
                    "configured": bool(self._key), "active": self.active,
                    "succeeded": self.succeeded, "failed": self.failed,
                    "error": self.error}

    def require_configured(self):
        if not self._key:
            raise RuntimeError("Live AI is unavailable: the website operator must configure OLLAMA_API_KEY.")

    def triage(self, event, criticality, history_summary, facts):
        self.require_configured()
        # Shared across visitors: free accounts permit one concurrent request.
        # A bounded wait prevents an unbounded queue of cloud requests.
        if not self._slot.acquire(timeout=10):
            raise RuntimeError("Cloud AI is busy; no AI verdict was produced")
        try:
            prompt = build_prompt(event, criticality, history_summary, facts)
            if len(prompt.encode("utf-8")) > 32768:
                raise RuntimeError("Event context exceeds the cloud demo limit; no AI verdict was produced")
            with self._lock:
                stamp = time.monotonic()
                while self._calls and stamp - self._calls[0] >= 3600:
                    self._calls.popleft()
                if len(self._calls) >= self.limit:
                    raise RuntimeError("Website AI hourly allowance reached; no AI verdict was produced")
                self._calls.append(stamp)
                self.active = 1
            payload = {"model": self.model, "stream": False, "think": False,
                       "format": "json", "options": {"temperature": .1, "num_predict": 512},
                       "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                    {"role": "user", "content": prompt}]}
            request = urllib.request.Request("https://ollama.com/api/chat",
                data=json.dumps(payload).encode(), headers={"Content-Type": "application/json",
                "Authorization": "Bearer " + self._key})
            try:
                with self._opener.open(request, timeout=45) as response:
                    raw = response.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise ValueError("Oversized cloud response")
                verdict = parse_response(json.loads(raw)["message"]["content"])
                if not verdict.rationale.strip() or (verdict.decision.value == "escalate" and not verdict.evidence.strip()):
                    raise ValueError("Cloud verdict lacks an explanation or escalation evidence")
            except Exception:
                # Do not copy remote bodies, request headers or secrets into audit/UI.
                raise RuntimeError("Cloud AI request failed or returned an invalid answer; no AI verdict was produced") from None
            with self._lock:
                self.succeeded += 1
                self.error = ""
            return verdict
        except Exception as exc:
            with self._lock:
                self.failed += 1
                self.error = str(exc)
            raise
        finally:
            with self._lock:
                self.active = 0
            self._slot.release()
