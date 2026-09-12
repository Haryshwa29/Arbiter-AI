"""End-to-end Windows check for Install Arbiter.exe using a portable payload.

Installs into a temporary directory with no service registration, launches the
installed runtime after the source bundle is logically removable, verifies the
dashboard login, then removes the temporary installation.
"""
from __future__ import annotations

import argparse
import functools
import http.cookiejar
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import socket
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--release-dir", type=Path)
    args = parser.parse_args()
    bundle = args.bundle.resolve()
    setup = bundle / "Install Arbiter.exe"
    if not setup.is_file():
        raise SystemExit(f"missing {setup}")

    work = bundle.parents[1] / "work"
    work.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="installer-smoke-", dir=work) as tmp:
        root = Path(tmp)
        prefix = root / "installed"
        local_app_data = root / "localappdata"
        local_app_data.mkdir()
        port = free_port()
        env = os.environ.copy()
        env["LOCALAPPDATA"] = str(local_app_data)
        env["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32")
        install = subprocess.run(
            [str(setup), "-Mode", "local", "-Scope", "user",
             "-InstallerArgs", f"--prefix {prefix} --port {port} --no-service"],
            cwd=bundle, env=env, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=600)
        output = install.stdout + install.stderr
        if install.returncode:
            raise RuntimeError(f"installer failed ({install.returncode}):\n{output}")
        password_match = re.search(r"One-time pw\s+(\S+)", output)
        if not password_match:
            raise RuntimeError("installer did not print first-run credentials")
        password = password_match.group(1)
        python = local_app_data / "Arbiter" / "runtime" / "python" / "python.exe"
        pyz = prefix / "app" / "arbiter.pyz"
        config = prefix / "config" / "arbiter.conf"
        for required in (python, pyz, config,
                         prefix / "runtime" / "ollama" / "ollama.exe",
                         prefix / "models"):
            if not required.exists():
                raise RuntimeError(f"installed file is missing: {required}")
        if str(bundle) in config.read_text(encoding="utf-8"):
            raise RuntimeError("installed configuration still points to the source bundle")

        service = subprocess.Popen(
            [str(python), str(pyz), "--service-run", "--config", str(config)],
            cwd=prefix, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace")
        address = f"http://127.0.0.1:{port}"
        try:
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                if service.poll() is not None:
                    raise RuntimeError("installed service exited during startup:\n" +
                                       service.stdout.read())
                try:
                    urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                        address + "/api/me", timeout=1)
                except urllib.error.HTTPError as error:
                    if error.code == 401:
                        break
                except OSError:
                    time.sleep(.25)
            else:
                raise RuntimeError("installed dashboard did not start")

            jar = http.cookiejar.CookieJar()
            client = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPCookieProcessor(jar))
            try:
                client.open(address + "/api/me")
            except urllib.error.HTTPError as error:
                if error.code != 401:
                    raise
            csrf = next(cookie.value for cookie in jar if cookie.name == "arb_csrf")
            request = urllib.request.Request(
                address + "/api/login",
                data=json.dumps({"username": "admin", "password": password}).encode(),
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf})
            with client.open(request) as response:
                if json.load(response)["role"] != "admin":
                    raise RuntimeError("installed dashboard login returned the wrong role")
        finally:
            service.terminate()
            try:
                service.wait(timeout=30)
            except subprocess.TimeoutExpired:
                service.kill()
            service.stdout.close()

        rules_prefix = root / "rules-installed"
        rules = subprocess.run(
            [str(setup), "-Mode", "rules", "-Scope", "user",
             "-InstallerArgs", f"--prefix {rules_prefix} --port {free_port()} --no-service"],
            cwd=bundle, env=env, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=120)
        if rules.returncode:
            raise RuntimeError("rules-only installation failed:\n" + rules.stdout + rules.stderr)
        rules_config = (rules_prefix / "config" / "arbiter.conf").read_text(encoding="utf-8")
        if "backend = mock" not in rules_config:
            raise RuntimeError("rules-only installation did not select the mock backend")
        if (rules_prefix / "models").exists():
            raise RuntimeError("rules-only installation copied local-model files")

        release_dir = (args.release_dir or (bundle.parents[1] / "work" / "install-release")).resolve()
        if not (release_dir / "SHA256SUMS").is_file():
            raise RuntimeError(f"release directory is missing: {release_dir}")
        standalone = root / "standalone"
        standalone.mkdir()
        shutil.copy2(setup, standalone / setup.name)

        class QuietHandler(SimpleHTTPRequestHandler):
            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            functools.partial(QuietHandler, directory=str(release_dir)))
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        online_prefix = root / "online-installed"
        online_env = env.copy()
        online_env["PATH"] = str(bundle / "runtime" / "python") + os.pathsep + online_env["PATH"]
        try:
            online = subprocess.run(
                [str(standalone / setup.name), "-BaseUrl",
                 f"http://127.0.0.1:{server.server_port}", "-Mode", "rules",
                 "-Scope", "user", "-InstallerArgs",
                 f"--prefix {online_prefix} --port {free_port()} --no-service"],
                cwd=standalone, env=online_env, stdin=subprocess.DEVNULL,
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=120)
            if online.returncode:
                raise RuntimeError("standalone download installation failed:\n" +
                                   online.stdout + online.stderr)
            if not (online_prefix / "app" / "arbiter.pyz").is_file():
                raise RuntimeError("standalone installer did not install the downloaded release")
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=5)

        print("PASS: setup EXE, hardware-selected local payload, permanent paths, "
              "bundled runtime/model startup, rules-only choice, verified standalone "
              "release download, and dashboard login.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
