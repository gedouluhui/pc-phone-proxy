#!/usr/bin/env python3
"""Generate a minimal CycloneDX 1.6 SBOM from reviewed component records."""
import argparse
import datetime
import json
import re
import sys
import uuid
from pathlib import Path


def generate(components, output):
    if not isinstance(components, list) or not components:
        raise ValueError("at least one component is required")
    cleaned = []
    refs = set()
    for component in components:
        item = dict(component)
        ref = item.get("bom-ref") or "pkg:generic/%s@%s" % (item.get("name"), item.get("version"))
        if not ref or ref in refs:
            raise ValueError("missing or duplicate component bom-ref")
        refs.add(ref)
        for digest in item.get("hashes", []):
            if digest.get("alg") != "SHA-256" or not re.fullmatch(r"[0-9a-f]{64}", digest.get("content", "")):
                raise ValueError("component hash must be SHA-256")
        item["bom-ref"] = ref
        cleaned.append(item)
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "PhoneProxy SBOM generator",
                                      "version": "1"}]},
        },
        "components": cleaned,
    }
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--components", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        generate(json.loads(Path(args.components).read_text(encoding="utf-8")), args.output)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print("SBOM generation failed: %s" % error, file=sys.stderr)
        return 1
    print("SBOM written: " + args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
