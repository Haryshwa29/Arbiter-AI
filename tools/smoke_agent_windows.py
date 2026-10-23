"""Read-only Windows collector smoke; generates only a benign cmd.exe exit."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from arbiter.agent import Agent


def main():
    if os.name != "nt": raise SystemExit("Windows only")
    with tempfile.TemporaryDirectory(prefix="arbiter-agent-windows-") as directory:
        agent = Agent(directory)
        try:
            agent.start()
            collector = agent.service.collectors.get("sysmon")
            if collector:
                deadline = time.monotonic() + 10
                while not collector.checkpoint and time.monotonic() < deadline:
                    time.sleep(.1)
                subprocess.run([os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe"), "/d", "/c", "exit", "0"],
                               check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    rows = agent.service.buffer.query({"source": "sysmon", "completed": True})
                    if any(row["event"]["process_name"].lower().endswith("cmd.exe") for row in rows):
                        break
                    time.sleep(.2)
            else:
                time.sleep(2)
            status = agent.command("status")
            result = {"test_type": "read_only_native_windows_collection", "thm_tested": False,
                "enforcement_tested": False,
                "containment_enabled": status["containment_enabled"],
                "collectors": [{k: c.get(k) for k in ("name", "status", "errors", "events_received")}
                               for c in status["connectors"] if c["enabled"] and c["name"] in {"windows", "sysmon", "defender"}],
                "processed_events": sum(c["events_received"] for c in status["connectors"] if c["name"] == "sysmon"),
                "benign_cmd_observed": any(row["event"]["process_name"].lower().endswith("cmd.exe")
                                          for row in agent.service.buffer.query({"source": "sysmon", "completed": True}))}
            target = Path("work/agent-windows-observation.json")
            target.parent.mkdir(exist_ok=True)
            target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(result))
        finally:
            agent.close()


if __name__ == "__main__": main()
