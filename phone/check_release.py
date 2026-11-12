# -*- coding: utf-8 -*-
"""Pre-release guard for the phone APK.

Checks the two mistakes that actually happened:
  1. a credential file (nodes.json / pinned.json / keystore / apk) is tracked by git;
  2. the APK you are about to publish embeds real nodes instead of the empty sample.

Usage:
    python check_release.py                     # git check only
    python check_release.py ../dist/手机代理-公版.apk   # also inspect the APK
"""
import json
import subprocess
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

FORBIDDEN = (
    "phone/assets/nodes.json",
    "phone/pc_test_config.json",
    "pinned.json",
    "pinned_health.json",
    "node_deep.json",
    "pool.json",
)
SUFFIXES = (".keystore", ".jks", ".apk")


def git_tracked():
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "ls-files"],
                             capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=30).stdout
    except Exception as exc:  # noqa: BLE001
        print("WARN: cannot run git ls-files:", exc)
        return []
    return [l.strip() for l in out.splitlines() if l.strip()]


def main() -> int:
    bad = []
    for path in git_tracked():
        low = path.lower()
        if low in FORBIDDEN or low.endswith(SUFFIXES):
            bad.append(path)
    if bad:
        print("FAIL: credential/binary files are tracked by git:")
        for b in bad:
            print("  " + b)
        print("Remove them with: git rm --cached <path>  (keep the local copy)")
    else:
        print("OK: git tracks no node credentials, keystores or APKs")

    if len(sys.argv) > 1:
        apk = Path(sys.argv[1])
        if not apk.is_file():
            print("SKIP: APK not found:", apk)
        else:
            with zipfile.ZipFile(apk) as z:
                try:
                    nodes = json.loads(z.read("assets/nodes.json").decode("utf-8"))
                    n = len(nodes) if isinstance(nodes, list) else -1
                except Exception:  # noqa: BLE001
                    n = -1
            print("APK %s embeds %s node(s)" % (apk.name, n))
            if n > 0:
                print("NOTE: this build carries real credentials - do NOT upload it to a public release.")
            elif n == 0:
                print("OK: empty node pool (safe for public release).")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
