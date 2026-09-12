"""Runtime entry point used by a permanent installation.

The installer may use either a normal Ollama installation or the standalone
runtime copied from the USB. In the latter case this process owns Ollama and
stops it with Arbiter, while the ordinary server and security pipeline remain
unchanged.
"""
from __future__ import annotations

import argparse
import configparser
import os
from pathlib import Path
import subprocess
import time
import urllib.request


def _wait_for_ollama(url: str, process: subprocess.Popen | None,
                     timeout: float = 45) -> None:
    deadline = time.monotonic() + timeout
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError("bundled local AI stopped during startup")
        try:
            with opener.open(url + "/api/tags", timeout=1):
                return
        except OSError:
            time.sleep(.25)
    raise RuntimeError("local AI did not become ready within 45 seconds")


def run(config_path: Path) -> None:
    from ..api.server import serve
    from ..portable import OwnedJob, local_port, ollama_environment

    cfg = configparser.ConfigParser()
    if not cfg.read(config_path, encoding="utf-8"):
        raise RuntimeError(f"configuration not found: {config_path}")
    host = cfg.get("server", "host")
    port = cfg.getint("server", "port")
    backend = cfg.get("llm", "backend", fallback="mock")
    model = cfg.get("llm", "model", fallback="qwen3.5:4b")
    paths = cfg["paths"]
    executable = cfg.get("runtime", "ollama_executable", fallback="")
    models_dir = cfg.get("runtime", "models_dir", fallback="")
    process = job = log = None
    ollama_url = "http://localhost:11434"
    try:
        if backend == "ollama" and executable:
            ollama_port = local_port()
            ollama_url = f"http://127.0.0.1:{ollama_port}"
            log_path = Path(paths["data_dir"]).parent / "logs" / "ollama.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log = log_path.open("ab")
            env = ollama_environment(Path(models_dir).parent, ollama_port)
            env["OLLAMA_MODELS"] = models_dir
            process = subprocess.Popen(
                [executable, "serve"], cwd=str(Path(executable).parent),
                env=env, stdout=log, stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            if os.name == "nt":
                job = OwnedJob()
                job.assign(process)
            _wait_for_ollama(ollama_url, process)

        serve(host=host, port=port, store_db=paths["audit_db"],
              iam_db=paths["iam_db"], mem_db=paths["memory_db"],
              events=paths.get("events", ""), backend=backend, model=model)
    finally:
        if job:
            job.close()
        elif process and process.poll() is None:
            process.terminate()
        if process:
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
        if log:
            log.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an installed Arbiter service")
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        run(args.config.resolve())
        return 0
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        print(f"Arbiter service could not start: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
