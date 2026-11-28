# -*- coding: utf-8 -*-
"""Compile and run the subscription catalog CRUD/schema proof."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PHONE = Path(__file__).resolve().parents[1]
ROOT = PHONE.parent
SRC = PHONE / "src" / "com" / "luhui" / "phoneproxy"
SOURCES = [SRC / "SubscriptionGuard.java", SRC / "SubscriptionCatalog.java"]
POC = PHONE / "tests" / "SubscriptionCatalogPoc.java"
JAR = PHONE / "tools" / ".cache" / "json-20240303.jar"
OUT = PHONE / "verification" / "subscription-catalog-poc.json"


def main():
    jdk = os.environ.get("JAVA_HOME") or r"C:\Program Files\Java\jdk-17"
    javac = Path(jdk) / "bin" / ("javac.exe" if os.name == "nt" else "javac")
    java = Path(jdk) / "bin" / ("java.exe" if os.name == "nt" else "java")
    with tempfile.TemporaryDirectory(prefix="catalog-poc-") as directory:
        classes = Path(directory)
        result = subprocess.run([str(javac), "-encoding", "UTF-8", "-cp", str(JAR),
                                 "-d", str(classes)] + [str(path) for path in SOURCES] + [str(POC)],
                                capture_output=True)
        if result.returncode:
            sys.stderr.buffer.write(result.stdout + result.stderr)
            raise SystemExit(1)
        run = subprocess.run([str(java), "-cp", str(classes) + os.pathsep + str(JAR),
                              "com.luhui.phoneproxy.SubscriptionCatalogPoc"],
                             capture_output=True, timeout=60)
    lines = run.stdout.decode("utf-8", "replace").splitlines()
    summary = next(json.loads(line) for line in reversed(lines) if line.startswith("{"))
    OUT.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(lines[-1])
    raise SystemExit(run.returncode)


if __name__ == "__main__":
    main()
