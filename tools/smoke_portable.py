"""Test a fresh, relocated bundle with no Python or Ollama on PATH.

Uses temporary hardlinks for immutable bundle files, fresh private data, and
never changes the supplied bundle's accounts or model files. Windows only.
"""
import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    source = args.bundle.resolve()
    work = source.parents[1] / "work"
    work.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="portable smoke with spaces ", dir=work) as tmp:
        root = Path(tmp)
        for file in source.rglob("*"):
            rel = file.relative_to(source)
            if rel.parts[0] in {"data", "logs"} or not file.is_file():
                continue
            dest = root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            os.link(file, dest)
        env = os.environ.copy()
        env["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32")
        process = subprocess.Popen([str(root / "Start Arbiter.exe"), "--no-browser"],
                                   cwd=root, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, encoding="utf-8", errors="replace")
        lines = queue.Queue()
        def read():
            for line in process.stdout:
                lines.put(line)
        reader = threading.Thread(target=read, daemon=True); reader.start()
        address = password = None
        try:
            deadline = time.monotonic() + 240
            while not address and time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("Portable startup exited unexpectedly.")
                try:
                    line = lines.get(timeout=1)
                except queue.Empty:
                    continue
                if line.startswith("Password: "): password = line.strip().split(": ", 1)[1]
                if line.startswith("Dashboard: "): address = line.strip().split(": ", 1)[1]
            if not address or not password:
                raise RuntimeError("Startup did not supply a dashboard and first-run credentials.")
            jar = http.cookiejar.CookieJar()
            client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))
            try:
                client.open(address + "/api/me")
            except urllib.error.HTTPError as error:
                assert error.code == 401
            csrf = next(c.value for c in jar if c.name == "arb_csrf")
            request = urllib.request.Request(address + "/api/login",
                data=json.dumps({"username": "admin", "password": password}).encode(),
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf})
            with client.open(request) as response: assert json.load(response)["demo"] is True
            with client.open(address + "/login") as response:
                html = response.read().decode()
                for asset in re.findall(r'(?:src|href)="(/[^\"]+)"', html):
                    with client.open(address + asset) as asset_response: assert asset_response.status == 200
            deadline = time.monotonic() + 150
            while time.monotonic() < deadline:
                with client.open(address + "/api/record") as response: rows = json.load(response)["rows"]
                if any(row["tier"] == "llm" and "LLM tier failed" not in row["rationale"] for row in rows):
                    break
                time.sleep(1)
            else:
                raise RuntimeError("No successful local-model verdict arrived.")
            template = root / "Demo Test Cases" / "Templates" / "00-new-live-case.json"
            active = root / "Demo Test Cases" / "Active"
            if len(list(active.glob("*.json"))) != 16 or not template.is_file():
                raise RuntimeError("Named demonstration cases are missing.")
            shutil.copy2(template, active / "00-smoke-test-live-reload.json")
            deadline = time.monotonic() + 150
            while time.monotonic() < deadline:
                with client.open(address + "/api/record") as response: rows = json.load(response)["rows"]
                if any(row["host"] == "requested-demo-host" for row in rows):
                    break
                time.sleep(1)
            else:
                raise RuntimeError("A demonstration case added while running was not processed.")
            duplicate = subprocess.run([str(root / "Start Arbiter.exe"), "--no-browser"],
                                       cwd=root, env=env, stdin=subprocess.DEVNULL,
                                       capture_output=True, timeout=15)
            assert duplicate.returncode != 0
            print("PASS: relocated path with spaces, bundled runtimes, login, demo flag, "
                  "named cases, live case reload, assets, real inference, duplicate guard.")
        finally:
            subprocess.run([str(root / "Stop Arbiter.exe")], cwd=root, env=env,
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
            try:
                code = process.wait(timeout=140)
            except subprocess.TimeoutExpired:
                # Keep the temporary folder for diagnosis if graceful stop fails.
                raise RuntimeError("Stop timed out; the test process needs attention.")
            reader.join(timeout=5)
            process.stdout.close()
        assert code == 0
        assert not (root / "data" / "session.json").exists()
        print("PASS: clean shutdown and session cleanup.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
