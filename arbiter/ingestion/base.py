"""Small collector contract, explicit lifecycle and checkpoint after enqueue."""
from __future__ import annotations

from abc import ABC, abstractmethod
import threading
from typing import Callable, Iterable

from .normalization import normalize
from .schema import SecurityEvent


class Collector(ABC):
    interval = 5.0

    def __init__(self, config: dict, checkpoint: dict | None = None):
        self.config = config
        self.checkpoint = dict(checkpoint or {})
        self.status = "Configured"
        self.error = ""
        self.errors = 0
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.on_normalization_error = lambda: None

    def start(self, submit: Callable[[SecurityEvent], bool], save: Callable[[dict], None]):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, args=(submit, save), daemon=True)
        self.thread.start()

    def _run(self, submit, save):
        while not self.stop_event.is_set():
            self.error = ""
            try:
                for item in self.collect():
                    if self.stop_event.is_set():
                        break
                    try:
                        event = self.normalize(item)
                    except (ValueError, TypeError, KeyError, OverflowError):
                        self.on_normalization_error()
                        self.errors += 1
                        self.error = "Malformed source event skipped"
                        self.status = "Error"
                        save(self.checkpoint)
                        continue
                    submit(event)  # queue full raises: generator cursor not advanced
                    save(self.checkpoint)
                save(self.checkpoint)
                if not self.error and self.status not in {"Connected", "Listening"}:
                    self.status = "Connected"
            except Exception as exc:
                # Never expose SDK error text (may contain credentials/requests).
                self.errors += 1
                self.error = "Queue full; collection will retry" if type(exc).__name__ == "BufferFull" else (
                    "Source unavailable or permission denied; check setup")
                self.status = "Error"
                save(self.checkpoint)
            self.stop_event.wait(self.interval)
        self.status = "Disabled"

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=35)
            if self.thread.is_alive():
                raise RuntimeError("collector is still stopping")
        self.status = "Disabled"

    def health(self) -> dict:
        return {"status": self.status, "error": self.error, "errors": self.errors}

    @abstractmethod
    def collect(self) -> Iterable[dict]: ...

    def normalize(self, raw: dict) -> SecurityEvent:
        return normalize(raw, self.config["adapter"])
