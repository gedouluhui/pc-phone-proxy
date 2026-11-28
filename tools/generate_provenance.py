#!/usr/bin/env python3
"""Generate an in-toto/SLSA v1 statement binding source materials to artifacts."""
import argparse
import datetime
import hashlib
import json
import re
import sys
from pathlib import Path


def _digests(path):
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha1.update(chunk)
            sha256.update(chunk)
    return sha1.hexdigest(), sha256.hexdigest()


def generate(repository, commit, builder, materials, artifacts, output):
    if not re.fullmatch(r"[0-9a-f]{40}", commit or ""):
        raise ValueError("commit must be a full SHA-1")
    if not repository.startswith("https://") or not builder:
        raise ValueError("repository and builder are required")
    if not artifacts:
        raise ValueError("at least one artifact is required")
    material_records = []
    for path in materials:
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(path)
        sha1, sha256 = _digests(path)
        material_records.append({"uri": str(path.resolve()).replace("\\", "/"),
                                 "digest": {"sha1": sha1, "sha256": sha256}})
    subjects = []
    for path in artifacts:
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(path)
        _, sha256 = _digests(path)
        subjects.append({"name": path.name, "digest": {"sha256": sha256}})
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "externalParameters": {"repository": repository, "commit": commit},
                "internalParameters": {"generator": "PhoneProxy provenance generator v1"},
                "resolvedDependencies": material_records,
            },
            "runDetails": {
                "builder": {"id": builder},
                "metadata": {
                    "buildInvocationId": hashlib.sha256(
                        (repository + commit + builder).encode("utf-8")).hexdigest(),
                    "buildStartedOn": datetime.datetime.now(datetime.timezone.utc)
                    .isoformat().replace("+00:00", "Z"),
                },
            },
        },
    }
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(statement, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return statement


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--builder", required=True)
    parser.add_argument("--material", action="append", default=[])
    parser.add_argument("--artifact", action="append", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        generate(args.repository, args.commit, args.builder,
                 [Path(value) for value in args.material],
                 [Path(value) for value in args.artifact], args.output)
    except (OSError, ValueError) as error:
        print("provenance generation failed: %s" % error, file=sys.stderr)
        return 1
    print("provenance written: " + args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
