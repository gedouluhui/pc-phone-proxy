# -*- coding: utf-8 -*-
"""Download, verify and stage a Windows release without replacing the installation."""
import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

APP = Path(__file__).resolve().parent
ROOT = APP.parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "pc" / "_proxy"))
import release_manifest  # noqa: E402
import source_fetch  # noqa: E402

MAX_AUTO_UPDATE = 64 * 1024 * 1024


def stage(manifest_path, signature_path, public_key_path, download_dir, previous_version=0):
    document = release_manifest.verify_bytes(
        Path(manifest_path).read_bytes(), Path(signature_path).read_bytes(),
        Path(public_key_path).read_bytes(), previous_version=previous_version)
    download_dir = Path(download_dir)
    download_dir.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".phoneproxy-update-", dir=str(download_dir)))
    try:
        for record in document["artifacts"]:
            name = record["name"]
            target = staging / name
            existing = download_dir / name
            if existing.is_file():
                shutil.copyfile(existing, target)
            else:
                if record["size"] > MAX_AUTO_UPDATE:
                    raise ValueError("artifact is too large for automatic update")
                body = source_fetch.fetch(record["url"], max_bytes=max(1, record["size"]),
                                          timeout=120, allow_private=False)
                target.write_bytes(body)
            release_manifest.verify_artifact(record, target)
        return str(staging)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def launch(staging, artifact_name):
    staging = Path(staging).resolve()
    target = (staging / artifact_name).resolve()
    if target.parent != staging or not target.is_file():
        raise ValueError("installer is outside the verified staging directory")
    return subprocess.Popen([str(target)], cwd=str(staging))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--signature", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--download-dir", required=True)
    parser.add_argument("--previous-version", type=int, default=0)
    parser.add_argument("--launch", metavar="ARTIFACT_NAME")
    args = parser.parse_args(argv)
    try:
        staging = stage(args.manifest, args.signature, args.public_key,
                        args.download_dir, args.previous_version)
        print("verified update staged: " + staging)
        if args.launch:
            process = launch(staging, args.launch)
            print("installer started pid=%d" % process.pid)
        return 0
    except (OSError, ValueError) as error:
        print("update rejected: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
