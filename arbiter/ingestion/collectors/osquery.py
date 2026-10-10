"""Read-only endpoint inventory; fixed queries, no uploaded SQL or extensions."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import subprocess

from ..base import Collector
from ..schema import safe_json

TABLES = ("system_info", "os_version", "processes", "logged_in_users", "listening_ports",
          "interface_addresses", "programs", "startup_items", "scheduled_tasks")


class OsqueryCollector(Collector):
    def __init__(self, config, checkpoint=None):
        super().__init__(config, checkpoint)
        self.interval = float(config.get("interval", 300))

    def collect(self):
        executable = Path(self.config["path"])
        for table in TABLES:
            if self.stop_event.is_set():
                return
            # Some tables are platform-specific; osquery errors are per table.
            result = subprocess.run([str(executable), "--json", "--disable_extensions=true",
                f"SELECT * FROM {table} LIMIT 100;"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0)
            if result.returncode:
                self.errors += 1
                self.error = "Some inventory tables unavailable on this platform"
                continue
            if len(result.stdout) > 200 * 1024:
                self.errors += 1
                continue
            rows = safe_json(result.stdout)
            yield {"hostname": socket.gethostname(), "table": table, "rows": rows}
