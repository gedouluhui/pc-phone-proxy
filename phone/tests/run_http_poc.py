# -*- coding: utf-8 -*-
"""Compile and run the DNS-pinned HTTP proof; persist a machine-readable report."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PHONE = Path(__file__).resolve().parents[1]
ROOT = PHONE.parent
SOURCE_DIR = PHONE / "src" / "com" / "luhui" / "phoneproxy"
SOURCES = [SOURCE_DIR / "SubscriptionGuard.java", SOURCE_DIR / "ValidatedHttp.java"]
POC = PHONE / "tests" / "ValidatedHttpPoc.java"
OUT = PHONE / "verification" / "http-poc.json"

JDK_CANDIDATES = (
    os.environ.get("JAVA_HOME"),
    r"C:\Program Files\Java\jdk-17",
    r"C:\Program Files\Eclipse Adoptium\jdk-17",
    "/usr/lib/jvm/java-17-openjdk-amd64",
    "/Library/JavaVirtualMachines/temurin-17.jdk/Contents/Home",
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
    with tempfile.TemporaryDirectory(prefix="http-poc-") as directory:
        classes = Path(directory)
        keystore = classes / "tls-test.p12"
        keytool = jdk / "bin" / ("keytool.exe" if os.name == "nt" else "keytool")
        generated = subprocess.run(
            [str(keytool), "-genkeypair", "-keystore", str(keystore), "-storetype", "PKCS12",
             "-storepass", "changeit", "-keypass", "changeit", "-alias", "test",
             "-keyalg", "RSA", "-keysize", "2048", "-validity", "1",
             "-dname", "CN=public.test", "-ext", "SAN=dns:public.test"],
            capture_output=True)
        if generated.returncode != 0:
            sys.stderr.write((generated.stdout + generated.stderr).decode("utf-8", "replace"))
            raise SystemExit("test keystore generation failed")
        compiled = subprocess.run(
            [str(javac), "-J-Duser.language=en", "-J-Duser.country=US", "-encoding", "UTF-8",
             "-d", str(classes)] + [str(path) for path in SOURCES] + [str(POC)],
            capture_output=True)
        if compiled.returncode != 0:
            sys.stderr.write((compiled.stdout + compiled.stderr).decode("utf-8", "replace"))
            raise SystemExit("javac failed")
        env = dict(os.environ, PROXY_TEST_KEYSTORE=str(keystore))
        run = subprocess.run([str(java), "-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8",
                              "-cp", str(classes), "com.luhui.phoneproxy.ValidatedHttpPoc"],
                             capture_output=True, timeout=60, env=env)
    lines = [line for line in run.stdout.decode("utf-8", "replace").splitlines() if line.strip()]
    summary = {}
    for line in reversed(lines):
        if line.startswith("{") and line.endswith("}"):
            summary = json.loads(line)
            break
    failures = [line for line in lines if line.startswith("FAIL ")]
    payload = {
        "kind": "validated-http-poc",
        "jdk": jdk.name,
        "tls_hostname_check": True,
        "sources": [str(path.relative_to(ROOT)).replace("\\", "/") for path in SOURCES],
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
    if run.returncode != 0:
        sys.stderr.write(run.stderr.decode("utf-8", "replace"))
    print(f"cases={payload['cases']} passed={payload['passed']} failed={payload['failed']}")
    if run.returncode != 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
