"""Assemble a Windows portable demo from explicit local runtime/model inputs.

Never downloads, installs services, or copies a developer's databases/accounts.
The destination must be empty. Keep large generated bundles out of Git.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from arbiter.portable import model_files


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--python-zip", type=Path, required=True)
    p.add_argument("--python-sha256", required=True)
    p.add_argument("--ollama-dir", type=Path, required=True)
    p.add_argument("--ollama-license", type=Path, required=True)
    p.add_argument("--models-dir", type=Path, required=True)
    p.add_argument("--model", default="qwen3.5:4b")
    p.add_argument("--release", type=Path, required=True)
    p.add_argument("--out", type=Path, default=ROOT / "dist" / "Arbiter-Portable-Windows")
    args = p.parse_args()
    out = args.out.resolve()
    if out.exists() and any(out.iterdir()):
        p.error("Output is not empty. Choose a new output folder; existing data is never overwritten.")
    if sha256(args.python_zip) != args.python_sha256.lower():
        p.error("Python archive checksum mismatch.")
    blobs = model_files(args.models_dir, args.model)
    print("Checking model digests...", flush=True)
    for path, digest, _ in blobs:
        if sha256(path) != digest:
            p.error(f"Corrupt model blob: {path.name}")
    with zipfile.ZipFile(args.release) as archive:
        if "arbiter/static/index.html" not in archive.namelist():
            p.error("Build the dashboard and release first.")
    runtime = out / "runtime"
    python = runtime / "python"
    python.mkdir(parents=True)
    with zipfile.ZipFile(args.python_zip) as archive:
        for name in archive.namelist():
            target = (python / name).resolve()
            if not target.is_relative_to(python.resolve()):
                p.error("Unsafe Python archive path.")
        archive.extractall(python)
    # The embedded distribution is isolated. Explicitly expose only our app.
    for config in python.glob("python*._pth"):
        config.write_text(config.read_text() + "\n../../app/arbiter.pyz\n", encoding="utf-8")
    ollama = runtime / "ollama"
    ollama.mkdir()
    print("Copying local runtime and model...", flush=True)
    shutil.copy2(args.ollama_dir / "ollama.exe", ollama / "ollama.exe")
    shutil.copytree(args.ollama_dir / "lib", ollama / "lib")
    for source in args.ollama_dir.glob("*LICENSE*"):
        if source.is_file(): shutil.copy2(source, ollama / source.name)
    model_name, tag = args.model.split(":")
    rel = Path("manifests") / "registry.ollama.ai" / "library" / model_name / tag
    target = out / "models" / rel
    target.parent.mkdir(parents=True)
    shutil.copy2(args.models_dir / rel, target)
    (out / "models" / "blobs").mkdir()
    for source, _, _ in blobs:
        shutil.copy2(source, out / "models" / "blobs" / source.name)
    for directory in ("app", "config", "data", "logs", "licenses"):
        (out / directory).mkdir(exist_ok=True)
    shutil.copy2(args.release, out / "app" / "arbiter.pyz")
    shutil.copytree(ROOT / "samples" / "demo_cases", out / "Demo Test Cases")
    shutil.copy2(ROOT / "LICENSE", out / "licenses" / "Arbiter-LICENSE")
    shutil.copy2(args.ollama_license, out / "licenses" / "Ollama-LICENSE")
    manifest_data = json.loads(target.read_text(encoding="utf-8"))
    for entry in manifest_data["layers"]:
        if entry.get("mediaType") == "application/vnd.ollama.image.license":
            shutil.copy2(args.models_dir / "blobs" / entry["digest"].replace(":", "-"),
                         out / "licenses" / "Model-LICENSE")
    shutil.copy2(ROOT / "docs" / "PORTABLE.md", out / "README.md")
    (out / "config" / "portable.json").write_text(json.dumps({"model": args.model}, indent=2), encoding="utf-8")
    compiler = Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe")
    for name, defines in (("Start Arbiter.exe", []), ("Stop Arbiter.exe", ["/define:STOP"])):
        subprocess.run([str(compiler), "/nologo", "/target:exe", "/platform:x64",
                        "/out:" + str(out / name), *defines,
                        str(ROOT / "packaging" / "PortableLauncher.cs")], check=True)
    (out / "BUILD.json").write_text(json.dumps({
        "model": args.model, "python_archive": args.python_zip.name,
        "python_sha256": args.python_sha256.lower(),
        "ollama_exe_sha256": sha256(ollama / "ollama.exe"),
        "release_sha256": sha256(args.release),
        "purpose": "Local sample-event demonstration; not live monitoring",
    }, indent=2), encoding="utf-8")
    print("Writing bundle checksums...", flush=True)
    with (out / "SHA256SUMS").open("w", encoding="utf-8") as sums:
        for file in sorted(out.rglob("*")):
            if file.is_file() and file.name != "SHA256SUMS":
                sums.write(f"{sha256(file)}  {file.relative_to(out).as_posix()}\n")
    print(f"Portable bundle ready: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
