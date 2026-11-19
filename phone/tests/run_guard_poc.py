# -*- coding: utf-8 -*-
"""Compile and run the subscription-URL proof with the local JDK.

Writes phone/verification/uri-poc.json so the result is an artifact rather than
a claim. No Android SDK is needed: SubscriptionGuard has no Android imports.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PHONE = Path(__file__).resolve().parents[1]
ROOT = PHONE.parent
SOURCE = PHONE / "src" / "com" / "luhui" / "phoneproxy" / "SubscriptionGuard.java"
POC = PHONE / "tests" / "SubscriptionGuardPoc.java"
OUT = PHONE / "verification" / "uri-poc.json"

JDK_CANDIDATES = (
    os.environ.get("JAVA_HOME"),
    r"C:\Program Files\Java\jdk-17",
    r"C:\Program Files\Eclipse Adoptium\jdk-17",
    "/usr/lib/jvm/java-17-openjdk-amd64",
    "/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home",
)


def find_jdk():
    for candidate in JDK_CANDIDATES:
        if candidate and Path(candidate, "bin", "javac.exe" if os.name == "nt" else "javac").is_file():
            return Path(candidate)
    found = shutil.which("javac")
    if found:
        return Path(found).resolve().parent.parent
    raise SystemExit("JDK 17 not found; set JAVA_HOME")


def main():
    jdk = find_jdk()
    javac = jdk / "bin" / ("javac.exe" if os.name == "nt" else "javac")
    java = jdk / "bin" / ("java.exe" if os.name == "nt" else "java")
    with tempfile.TemporaryDirectory(prefix="uri-poc-") as directory:
        classes = Path(directory)
        # javac on a Chinese Windows prints GBK; decode defensively rather than
        # letting a code page turn a compile error into a traceback.
        compile_result = subprocess.run(
            [str(javac), "-J-Duser.language=en", "-J-Duser.country=US",
             "-encoding", "UTF-8", "-d", str(classes), str(SOURCE), str(POC)],
            capture_output=True)
        if compile_result.returncode != 0:
            sys.stderr.write((compile_result.stdout + compile_result.stderr).decode("utf-8", "replace"))
            raise SystemExit("javac failed")
        run = subprocess.run([str(java), "-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8",
                              "-cp", str(classes), "SubscriptionGuardPoc"], capture_output=True)
        lines = [line for line in run.stdout.decode("utf-8", "replace").splitlines() if line.strip()]
        summary = {}
        for line in reversed(lines):
            if line.startswith("{") and line.endswith("}"):
                summary = json.loads(line)
                break
        failures = [line for line in lines if line.startswith("FAIL ")]
        payload = {
            "kind": "subscription-uri-poc",
            "jdk": jdk.name,
            "source": str(SOURCE.relative_to(ROOT)).replace("\\", "/"),
            "cases": summary.get("cases"),
            "passed": summary.get("passed"),
            "failed": summary.get("failed"),
            "failures": failures,
            "exit": run.returncode,
        }
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        for line in lines:
            if line.startswith("FAIL ") or line.startswith("{"):
                print(line)
        print(f"cases={payload['cases']} passed={payload['passed']} failed={payload['failed']}")
        if run.returncode != 0:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
