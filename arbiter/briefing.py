"""Validate operator context without inference or execution authority."""
from __future__ import annotations

import re
from datetime import datetime, timezone


def validate_briefing(body: dict) -> dict:
    def text(key, limit, required=False):
        value = body.get(key, "")
        if not isinstance(value, str) or len(value) > limit:
            raise ValueError(f"{key} must be text of at most {limit} characters")
        value = value.strip()
        if required and not value:
            raise ValueError(f"{key} is required")
        if any(ord(c) < 32 and c not in "\n\t" for c in value):
            raise ValueError(f"{key} contains control characters")
        return value

    host = text("host", 255, True)
    if not re.fullmatch(r"[A-Za-z0-9_:.%-]+", host) or host == "*":
        raise ValueError("host must be an exact hostname or IP, not a subnet or wildcard")
    fact = text("fact", 2000, True)
    role = text("role", 200)
    priority = body.get("priority", "unchanged")
    if priority not in ("unchanged", "standard", "important", "critical"):
        raise ValueError("invalid priority")
    expires = text("expires_at", 40)
    if expires:
        try:
            parsed = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed <= datetime.now(timezone.utc):
                raise ValueError()
            expires = parsed.astimezone(timezone.utc).isoformat()
        except ValueError:
            raise ValueError("expiry must be a future timestamp with timezone") from None
    return {"host": host, "fact": fact, "role": role, "priority": priority,
            "expires_at": expires}
