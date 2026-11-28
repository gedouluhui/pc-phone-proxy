#!/usr/bin/env python3
"""Fail closed when CI actions or downloaded engine binaries are not pinned."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

ACTION_PINS = {
    "actions/checkout": "11bd71901bbe5b1630ceea73d27597364c9af683",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/setup-java": "c5195efecf7bdfc987ee8bae7a71cb8b11521c00",
    "actions/cache": "5a3ec84eff668545956fd18022155c47e93e2684",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
}
SINGBOX_SHA256 = "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df"
AAR_SHA256 = "cdfef146218233a31a8b52c8b1016557730d3b63fc121d4c84cacea50e669155"


def check_text(text):
    errors = []
    if not re.search(r"(?m)^permissions:\s*\n\s+contents:\s*read\s*$", text):
        errors.append("permissions must set contents: read")
    uses = re.findall(r"(?m)^\s*-?\s*uses:\s*([^\s@]+)@([^\s]+)", text)
    seen = set()
    for action, ref in uses:
        seen.add(action)
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            errors.append("action %s is not pinned to a commit SHA" % action)
        elif ACTION_PINS.get(action) != ref:
            errors.append("action %s has an unreviewed pin" % action)
    missing = set(ACTION_PINS) - seen
    if missing:
        errors.append("missing reviewed actions: " + ", ".join(sorted(missing)))
    if SINGBOX_SHA256 not in text or "Get-FileHash" not in text:
        errors.append("sing-box download lacks the reviewed SHA-256 gate")
    if AAR_SHA256 not in text:
        errors.append("AAR download lacks the reviewed SHA-256")
    verify_at = text.find("sha256sum -c -")
    unzip_at = text.find("unzip -o -q /tmp/libv2ray.aar")
    if verify_at < 0 or unzip_at < 0 or verify_at > unzip_at:
        errors.append("AAR must be verified before extraction")
    return errors


def check_repository():
    errors = []
    for path in sorted(WORKFLOW.parent.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for action, ref in re.findall(r"(?m)^\s*-?\s*uses:\s*([^\s@]+)@([^\s]+)", text):
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                errors.append("%s: action %s is not pinned to a commit SHA" % (path.name, action))
            elif ACTION_PINS.get(action) != ref:
                errors.append("%s: action %s has an unreviewed pin" % (path.name, action))
        if path.name in ("phone-apk.yml", "release.yml"):
            if AAR_SHA256 not in text or "sha256sum -c -" not in text:
                errors.append("%s: AAR must be verified before use" % path.name)
    errors.extend(check_text(WORKFLOW.read_text(encoding="utf-8")))
    return errors


def main():
    errors = check_repository()
    for error in errors:
        print("FAIL " + error, file=sys.stderr)
    print("CI supply-chain pins OK" if not errors else "CI supply-chain pins INVALID")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
