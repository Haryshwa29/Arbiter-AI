"""Build a stdlib-only terminal agent zipapp, with no dashboard build required."""
import argparse
import hashlib
from pathlib import Path
import tempfile
import zipapp

from build_release import stage_source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("dist/arbiter-agent.pyz"))
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="arbiter-agent-build-") as directory:
        stage = Path(directory)
        stage_source(stage)
        zipapp.create_archive(stage, args.out, compressed=True)
    digest = hashlib.sha256(args.out.read_bytes()).hexdigest()
    checksum = args.out.with_suffix(args.out.suffix + ".sha256")
    checksum.write_text(f"{digest}  {args.out.name}\n", encoding="ascii")
    print(f"Built {args.out} ({args.out.stat().st_size} bytes); SHA256 {digest}")


if __name__ == "__main__":
    main()
