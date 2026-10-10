"""Discover models on the configured local inference service only."""
import json
from urllib.request import urlopen


def available_models(url="http://localhost:11434"):
    try:
        with urlopen(url.rstrip("/") + "/api/tags", timeout=2) as response:
            data = json.loads(response.read(1024 * 1024))
        if not isinstance(data, dict): return {"available": False, "models": []}
        return {"available": True, "models": [m["name"] for m in data.get("models", []) if isinstance(m, dict) and isinstance(m.get("name"), str)]}
    except (OSError, ValueError, KeyError, TypeError):
        return {"available": False, "models": []}
