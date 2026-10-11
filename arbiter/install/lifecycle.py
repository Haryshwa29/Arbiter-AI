"""Shared installed-process ownership and bounded operational logging."""
from __future__ import annotations

from contextlib import contextmanager
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sys
from datetime import datetime, timezone


@contextmanager
def instance_lock(data_dir: Path):
    data_dir.mkdir(parents=True, exist_ok=True)
    handle = (data_dir / "service.lock").open("a+b")
    acquired = False
    try:
        handle.seek(0)
        if not handle.read(1):
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        acquired = True
        yield
    except OSError as exc:
        if not acquired:
            raise RuntimeError("Arbiter is already running for this data directory") from exc
        raise
    finally:
        # Closing releases the OS lock, including after a crashed process exits.
        handle.close()


def write_health(data_dir: Path, state: str, **details):
    payload = {"state": state, "pid": os.getpid(),
               "updated_at": datetime.now(timezone.utc).isoformat(), **details}
    target = data_dir / "service-health.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    temporary.replace(target)


class LogStream:
    def __init__(self, logger, level):
        self.logger, self.level = logger, level

    def write(self, text):
        for line in text.rstrip().splitlines():
            self.logger.log(self.level, line)
        return len(text)

    def flush(self):
        for handler in self.logger.handlers:
            handler.flush()


@contextmanager
def operational_logs(log_dir: Path):
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.Logger("arbiter-service", level=logging.INFO)
    handler = RotatingFileHandler(log_dir / "service.log", maxBytes=5 * 1024 * 1024,
                                  backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    previous = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = LogStream(logger, logging.INFO), LogStream(logger, logging.ERROR)
    try:
        yield
    finally:
        sys.stdout, sys.stderr = previous
        handler.close()
