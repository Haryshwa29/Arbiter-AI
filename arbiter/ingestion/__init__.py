"""Local telemetry ingestion; collectors never invoke the reasoning engine."""

from .schema import SecurityEvent

__all__ = ["SecurityEvent"]
