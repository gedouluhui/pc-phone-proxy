#!/usr/bin/env python3
"""Create and verify signed release manifests with exact artifact hashes."""
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.parse
from pathlib import Path

from sign_sources import sign_bytes
from verify_sources import verify_bytes as verify_signature

ROOT = Path(__file__).resolve().parents[1]


def _validate_record(record):
    if not isinstance(record, dict):
        raise ValueError("artifact record must be an object")
    name = record.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", name) or name in (".", ".."):
        raise ValueError("unsafe artifact name")
    size = record.get("size")
    digest = record.get("sha256")
    if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= 2 * 1024**3:
        raise ValueError("invalid artifact size")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("invalid artifact SHA-256")
    url = record.get("url")
    try:
        parsed = urllib.parse.urlsplit(url)
    except (TypeError, ValueError) as error:
        raise ValueError("invalid artifact URL") from error
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None:
        raise ValueError("artifact URL must be credential-free HTTPS")


def build(version, commit, artifacts):
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ValueError("invalid release version")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("invalid source commit")
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 50:
        raise ValueError("invalid artifact count")
    names = set()
    for record in artifacts:
        _validate_record(record)
        if record["name"] in names:
            raise ValueError("duplicate artifact name")
        names.add(record["name"])
    document = {"schema": 1, "version": version, "commit": commit,
                "artifacts": artifacts}
    return (json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def verify_bytes(data, signature, public_key, previous_version=0):
    if not verify_signature(data, signature, public_key):
        raise ValueError("release manifest signature mismatch")
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid release manifest JSON") from error
    if not isinstance(document, dict) or document.get("schema") != 1:
        raise ValueError("unsupported release manifest schema")
    version = document.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version <= previous_version:
        raise ValueError("release version is not newer")
    build(document["version"], document.get("commit"), document.get("artifacts"))
    return document


def verify_artifact(record, path):
    _validate_record(record)
    path = Path(path)
    if not path.is_file() or path.stat().st_size != record["size"]:
        raise ValueError("release artifact size mismatch")
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != record["sha256"]:
        raise ValueError("release artifact hash mismatch")


def create(spec_path, private_key, manifest_path, signature_path):
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    records = []
    for item in spec["artifacts"]:
        path = Path(item["path"])
        if not path.is_file():
            raise FileNotFoundError(path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        records.append({"name": item["name"], "size": path.stat().st_size,
                        "sha256": digest, "url": item["url"]})
    data = build(spec["version"], spec["commit"], records)
    signature = sign_bytes(data, private_key)
    for output, content in ((manifest_path, data), (signature_path, signature)):
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(output.name + ".tmp")
        temporary.write_bytes(content)
        os.replace(temporary, output)
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--create", metavar="SPEC_JSON")
    parser.add_argument("--private-key")
    parser.add_argument("--manifest", default=str(ROOT / "release-manifest.json"))
    parser.add_argument("--signature", default=str(ROOT / "release-manifest.sig"))
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--public-key", default=str(ROOT / "phone" / "source_signing_public.pem"))
    parser.add_argument("--previous-version", type=int, default=0)
    args = parser.parse_args(argv)
    try:
        if args.create:
            if not args.private_key:
                parser.error("--create requires --private-key")
            create(args.create, args.private_key, args.manifest, args.signature)
            print("signed release manifest written")
            return 0
        document = verify_bytes(Path(args.manifest).read_bytes(), Path(args.signature).read_bytes(),
                                Path(args.public_key).read_bytes(), args.previous_version)
        print("release manifest v%d signature OK (%d artifacts)" %
              (document["version"], len(document["artifacts"])))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print("release manifest failed: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
