# -*- coding: utf-8 -*-
"""Generate the hash manifest consumed by the elevated installed broker."""
import argparse
import hashlib
import json
import os
from pathlib import Path

ALLOWED_SUFFIXES = {".py", ".exe", ".dll", ".srs", ".dat", ".pem", ".sig", ".json"}
SKIP_DIRS = {"__pycache__", "logs", "raw", "data", "runtime", "dist", "build"}
SKIP_FILES = {"install-manifest.json", "nodes.json", "pinned.json", "pinned_pids.json",
              "node_deep.json", "ACTIVE.json", "state_backup.json", "google_gate.json"}


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(install_dir, output):
    install_dir = Path(install_dir).resolve()
    files = {}
    for base in (install_dir / "app", install_dir / "_proxy"):
        if not base.is_dir():
            raise FileNotFoundError(base)
        for path in sorted(base.rglob("*")):
            relative = path.relative_to(install_dir).as_posix()
            if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.name in SKIP_FILES or path.suffix.lower() not in ALLOWED_SUFFIXES:
                continue
            files[relative] = sha256(path)
    for relative in ("runtime/python/python.exe", "runtime/tray.exe"):
        path = install_dir / relative
        if not path.is_file():
            raise FileNotFoundError(path)
        files[relative] = sha256(path)
    document = {"schema": 1, "files": files}
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, output)
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-dir", required=True)
    parser.add_argument("--output", default=str(Path(__file__).resolve().parents[1] / "install-manifest.json"))
    args = parser.parse_args(argv)
    try:
        document = build(args.install_dir, args.output)
    except OSError as error:
        parser.error(str(error))
    print("install manifest written: %d files" % len(document["files"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
