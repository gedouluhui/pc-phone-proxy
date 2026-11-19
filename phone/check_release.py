# -*- coding: utf-8 -*-
"""Check git and public APK node assets, failing closed on inspection errors.

Usage: python phone/check_release.py [APK ...]
With no arguments, inspect existing default artifacts. Explicit APKs are required.
"""
import subprocess
import sys
from pathlib import Path, PurePosixPath

from release_guard import ReleaseCheckError, nodes_in_apk

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

FORBIDDEN = frozenset((
    "nodes.json", "pc_test_config.json", "pinned.json", "pinned_health.json",
    "node_deep.json", "pool.json",
))
SUFFIXES = (".keystore", ".jks", ".apk")


def git_tracked():
    try:
        result = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"],
                                capture_output=True, text=True, encoding="utf-8",
                                errors="strict", timeout=30)
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise ReleaseCheckError("cannot inspect git tracked files") from None
    if result.returncode != 0:
        raise ReleaseCheckError("git ls-files failed (rc=%d)" % result.returncode)
    return [path for path in result.stdout.split("\0") if path]


def sensitive_path(path):
    parts = PurePosixPath(path.replace("\\", "/").lower()).parts
    return any(part in FORBIDDEN or part.endswith(SUFFIXES) for part in parts)


def nodes_in(apk):
    return nodes_in_apk(apk)


def main(argv=None):
    bad = []
    try:
        tracked = [path for path in git_tracked() if sensitive_path(path)]
    except ReleaseCheckError as exc:
        bad.append("git")
        print("FAIL:", exc)
    else:
        if tracked:
            bad.extend(tracked)
            print("FAIL: credential/binary files are tracked by git:")
            for path in tracked:
                print("  " + repr(path))
            print("Remove them with: git rm --cached <path> (keep the local copy)")
        else:
            print("OK: git tracks no node credentials, keystores or APKs")

    targets = [Path(arg) for arg in (sys.argv[1:] if argv is None else argv)]
    if not targets:
        targets = [path for path in (ROOT / "dist" / "手机代理-公版.apk",
                                     HERE / "手机代理.apk") if path.exists()]
    for apk in targets:
        try:
            nodes_in(apk)
        except ReleaseCheckError as exc:
            bad.append(str(apk))
            print("FAIL: APK %s: %s" % (apk.name, exc))
        else:
            print("OK: APK %s: assets/nodes.json = []" % apk.name)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
