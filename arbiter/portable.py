"""Windows portable demo supervisor. No install, cloud fallback or live response."""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser

from .api.server import Ctx, Hub, build_httpd, demo_feed_loop, tail_poller
from .iam import IAM, load_or_create_secret
from .memory import Memory
from .store import AuditStore
from .install.preflight import _total_ram_gb


def model_files(root: Path, model: str) -> list[tuple[Path, str, int]]:
    """Validate the local manifest; never follow arbitrary manifest paths."""
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+", model) or model.endswith(":cloud"):
        raise ValueError("Use a bundled local model name such as qwen3.5:4b.")
    name, tag = model.split(":")
    manifest = root / "manifests" / "registry.ollama.ai" / "library" / name / tag
    data = json.loads(manifest.read_text(encoding="utf-8"))
    entries = [data["config"], *data["layers"]]
    if not any(x.get("mediaType") == "application/vnd.ollama.image.model" for x in entries):
        raise ValueError("The selected model has no local weights.")
    result = []
    for entry in entries:
        digest = entry["digest"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("Invalid model digest.")
        size = entry["size"]
        blob = root / "blobs" / digest.replace(":", "-")
        if not isinstance(size, int) or size < 0 or blob.stat().st_size != size:
            raise ValueError(f"Incomplete model file: {blob.name}")
        result.append((blob, digest.split(":")[1], size))
    return result


def local_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def ollama_environment(root: Path, port: int) -> dict[str, str]:
    env = os.environ.copy()
    for key in list(env):
        if key.upper().startswith("OLLAMA_") or key.upper() in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}:
            env.pop(key)
    home = root / "data" / "runtime-home"
    temp = root / "data" / "temp"
    home.mkdir(parents=True, exist_ok=True)
    temp.mkdir(parents=True, exist_ok=True)
    env.update(OLLAMA_HOST=f"127.0.0.1:{port}", OLLAMA_MODELS=str(root / "models"),
               OLLAMA_NO_CLOUD="1", OLLAMA_CONTEXT_LENGTH="4096", OLLAMA_NUM_PARALLEL="1",
               OLLAMA_MAX_LOADED_MODELS="1", OLLAMA_KEEP_ALIVE="5m",
               HOME=str(home), USERPROFILE=str(home), LOCALAPPDATA=str(home),
               APPDATA=str(home), TEMP=str(temp), TMP=str(temp), NO_PROXY="127.0.0.1,localhost")
    return env


def request_json(url, payload=None, timeout=5):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    # Do not send localhost requests through a host-configured proxy.
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=timeout) as response:
        return json.load(response)


class OwnedJob:
    """Close only our Ollama process tree, including after supervisor failure."""
    def __init__(self):
        from ctypes import wintypes
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        # JOBOBJECT_EXTENDED_LIMIT_INFORMATION on Windows x64: LimitFlags at byte 16.
        self.handle = self.kernel.CreateJobObjectW(None, None)
        info = ctypes.create_string_buffer(144)
        ctypes.c_uint32.from_buffer(info, 16).value = 0x2000  # KILL_ON_JOB_CLOSE
        if not self.handle or not self.kernel.SetInformationJobObject(self.handle, 9, info, len(info)):
            self.close()
            raise ctypes.WinError(ctypes.get_last_error())

    def assign(self, process):
        if not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            process.terminate()
            process.wait(timeout=10)
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def run(root: Path, open_browser=True, check_only=False) -> int:
    if platform.system() != "Windows" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise ValueError("This bundle requires 64-bit Windows on an Intel/AMD computer.")
    # All inference calls in this dedicated process stay direct to loopback.
    urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))
    config = json.loads((root / "config" / "portable.json").read_text(encoding="utf-8"))
    model = config["model"]
    model_files(root / "models", model)
    executable = root / "runtime" / "ollama" / "ollama.exe"
    if not executable.is_file():
        raise ValueError("Bundled Ollama runtime is missing. Re-copy the complete bundle.")
    ram = _total_ram_gb()
    print(f"Model: {model}. RAM: {ram:.1f} GB" if ram else f"Model: {model}. RAM could not be measured.", flush=True)
    if ram is not None and ram < 8:
        raise ValueError("This initial 4B bundle requires at least 8 GB RAM. Use a supported demo computer.")
    if shutil.disk_usage(root).free < 500 * 1024**2:
        raise ValueError("Keep at least 500 MB free on the portable drive for data and logs.")
    data = root / "data"
    data.mkdir(exist_ok=True)
    if check_only:
        print("Portable files and hardware checks passed. Model execution is checked at startup.")
        return 0

    import msvcrt
    lock = (data / "running.lock").open("a+b")
    lock.seek(0); lock.write(b"0"); lock.flush(); lock.seek(0)
    try:
        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError:
        lock.close()
        raise ValueError("This portable copy is already running. Use Stop Arbiter before restarting.")

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    request = data / "stop.request"
    request.unlink(missing_ok=True)
    threads = []
    httpd = store = iam = memory = job = process = log = None
    try:
        logs = root / "logs"; logs.mkdir(exist_ok=True)
        log = (logs / "ollama.log").open("ab")
        port = local_port()
        url = f"http://127.0.0.1:{port}"
        job = OwnedJob()
        process = subprocess.Popen([str(executable), "serve"], cwd=data,
                                   env=ollama_environment(root, port), stdout=log, stderr=log,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        job.assign(process)
        print("Starting bundled local AI (no downloads)...", flush=True)
        deadline = time.monotonic() + 45
        while True:
            if process.poll() is not None:
                raise ValueError("Local AI exited. See logs/ollama.log.")
            try:
                tags = request_json(url + "/api/tags")
                break
            except (OSError, ValueError):
                if time.monotonic() > deadline:
                    raise ValueError("Local AI did not start within 45 seconds. See logs/ollama.log.")
                if stop.wait(.25) or request.exists():
                    return 0
        if model not in {m["name"] for m in tags.get("models", [])}:
            raise ValueError("The bundled model is unavailable. No download or mock fallback was attempted.")
        print("Checking that the model can load on this computer; first load may take a few minutes...", flush=True)
        request_json(url + "/api/generate", {"model": model, "stream": False, "keep_alive": "5m"}, timeout=180)
        store = AuditStore(data / "arbiter_audit.db")
        iam = IAM(data / "arbiter_iam.db", secret=load_or_create_secret(data / "arbiter_iam.db.secret"))
        if not iam.any_users():
            password = secrets.token_urlsafe(12)
            iam.create_user("admin", password, "admin")
            print(f"First sign-in: admin\nPassword: {password}\nKeep this password for the next launch.", flush=True)
        memory = Memory(data / "arbiter_memory.db")
        if not memory.list_assets():
            memory.upsert_asset("db-prod-01", 2.0, "sample database", True)
            memory.add_fact("backups run at 02:00; nightly IO spike is normal", scope="db-prod-01", event_types=("io_anomaly",))
        ctx = Ctx(store, iam, memory, Hub(), demo=True)
        httpd = build_httpd(ctx, "127.0.0.1", 0)
        for target, args in (
            (httpd.serve_forever, ()),
            (tail_poller, (ctx, 1.0, stop)),
            (demo_feed_loop, (ctx, memory, str(root / "samples" / "events.jsonl"), "ollama", model, 3.0, stop, url)),
        ):
            thread = threading.Thread(target=target, args=args, daemon=True)
            thread.start(); threads.append(thread)
        address = f"http://127.0.0.1:{httpd.server_port}"
        (data / "session.json").write_text(json.dumps({"url": address, "model": model}), encoding="utf-8")
        print(f"SAMPLE EVENTS ONLY - this computer is not monitored.\nDashboard: {address}\nUse Stop Arbiter.exe or Ctrl+C before removing the USB.", flush=True)
        if open_browser:
            webbrowser.open(address)
        while not stop.wait(.5) and not request.exists():
            if process.poll() is not None:
                raise ValueError("Local AI stopped unexpectedly. See logs/ollama.log.")
        return 0
    finally:
        print("Stopping Arbiter; waiting for current analysis to finish...", flush=True)
        stop.set()
        if httpd:
            httpd.shutdown(); httpd.server_close()
        for thread in threads:
            thread.join(timeout=125)
        if job:
            job.close()
        if process:
            process.wait(timeout=15)
        for resource in (memory, iam, store, log):
            if resource:
                resource.close()
        request.unlink(missing_ok=True)
        (data / "session.json").unlink(missing_ok=True)
        lock.close()
        print("Stopped. You can safely eject the drive using Windows.", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Run the portable Arbiter demonstration")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--stop", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        if args.stop:
            (root / "data").mkdir(exist_ok=True)
            (root / "data" / "stop.request").touch()
            print("Stop requested. Wait for the Start Arbiter window to report Stopped before ejecting.")
            return 0
        return run(root, not args.no_browser, args.check)
    except (OSError, ValueError, KeyError) as exc:
        print(f"Arbiter could not start: {exc}", file=sys.stderr, flush=True)
        return 1
