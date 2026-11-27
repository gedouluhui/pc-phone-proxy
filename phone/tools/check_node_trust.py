#!/usr/bin/env python3
"""Compile and run the pure-JVM node trust proof."""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PHONE = Path(__file__).resolve().parents[1]
SRC = PHONE / "src" / "com" / "luhui" / "phoneproxy"
JAR = PHONE / "tools" / ".cache" / "json-20240303.jar"


def javac_path():
    home = os.environ.get("JAVA_HOME")
    if home:
        candidate = Path(home) / "bin" / ("javac.exe" if os.name == "nt" else "javac")
        if candidate.is_file():
            return candidate
    found = shutil.which("javac")
    if not found:
        raise SystemExit("JDK 17 not found; set JAVA_HOME")
    return Path(found)


def main():
    if not JAR.is_file():
        raise SystemExit("missing org.json jar; run phone/tools/check_poison.py first")
    javac = javac_path()
    java = javac.with_name("java.exe" if os.name == "nt" else "java")
    with tempfile.TemporaryDirectory(prefix="node-trust-") as directory:
        classes = Path(directory)
        sources = [
            SRC / "NodeConfigCodec.java",
            SRC / "SubscriptionGuard.java",
            SRC / "RoutingPolicy.java",
            PHONE / "tests" / "NodeTrustHarness.java",
        ]
        result = subprocess.run(
            [str(javac), "-encoding", "UTF-8", "-cp", str(JAR), "-d", str(classes)]
            + [str(path) for path in sources],
            capture_output=True, text=True, errors="replace")
        if result.returncode:
            sys.stderr.write((result.stdout or "") + (result.stderr or ""))
            return 1
        result = subprocess.run(
            [str(java), "-cp", str(classes) + os.pathsep + str(JAR), "NodeTrustHarness"],
            capture_output=True, text=True, errors="replace")
        sys.stdout.write(result.stdout or "")
        sys.stderr.write(result.stderr or "")
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
