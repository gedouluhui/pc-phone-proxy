#!/usr/bin/env python3
"""Poison corpus closed loop for the share-link parser.

Compiles NodeConfigCodec + PoisonHarness with a pinned org.json, feeds 300+
malformed/legacy links through parseUri, and runs every accepted outbound
through the real Xray binary (`xray run -test`). A parser rule that drifts from
the kernel fails this check instead of shipping an APK that cannot start.

Usage:
    python phone/tools/check_poison.py
    python phone/tools/check_poison.py --update-golden

Resource lookup (first hit wins):
    XRAY_BIN=/path/to/xray        ORG_JSON_JAR=/path/to/json.jar
    phone/tools/xray/xray[.exe]   phone/tools/.cache/*
    PATH                          downloaded into phone/tools/.cache/
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PHONE = ROOT / "phone"
SRC = PHONE / "src" / "com" / "luhui" / "phoneproxy"
CACHE = PHONE / "tools" / ".cache"
GOLDEN = PHONE / "tests" / "full_config.golden.json"

XRAY_VERSION = "v26.11.9"
ORG_JSON_VERSION = "20240303"
ORG_JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
XRAY_SHA = {
    "Windows": "1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d",
    "Linux": "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82",
}
XRAY_URL = {
    "Windows": f"https://github.com/XTLS/Xray-core/releases/download/{XRAY_VERSION}/Xray-windows-64.zip",
    "Linux": f"https://github.com/XTLS/Xray-core/releases/download/{XRAY_VERSION}/Xray-linux-64.zip",
}

MIN_CASES = 300
MIN_ACCEPTED = 100
MIN_REJECTED = 100


class Missing(Exception):
    pass


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url, dest, expect_sha):
    dest = Path(dest)
    if dest.is_file() and sha256(dest) == expect_sha:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    print(f"downloading {url}")
    try:
        with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f)
    except Exception as error:
        raise Missing(f"download failed: {url}: {error}")
    got = sha256(tmp)
    if got != expect_sha:
        tmp.unlink(missing_ok=True)
        raise Missing(f"sha256 mismatch for {dest.name}: {got}")
    tmp.replace(dest)
    return dest


def find_xray():
    env = os.environ.get("XRAY_BIN")
    if env:
        p = Path(env)
        if p.is_file():
            return p
        raise Missing(f"XRAY_BIN does not exist: {env}")
    local = PHONE / "tools" / "xray" / ("xray.exe" if os.name == "nt" else "xray")
    if local.is_file():
        return local
    cached = sorted(CACHE.glob("Xray-*/xray*"))
    for p in cached:
        if p.is_file():
            return p
    onpath = shutil.which("xray")
    if onpath:
        return Path(onpath)
    system = platform.system()
    if system not in XRAY_URL:
        raise Missing(f"no Xray binary for {system}; set XRAY_BIN")
    zip_path = CACHE / f"Xray-{XRAY_VERSION}-{system}.zip"
    download(XRAY_URL[system], zip_path, XRAY_SHA[system])
    out = CACHE / f"Xray-{XRAY_VERSION}-{system}"
    if not out.is_dir():
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(out)
    for name in ("xray", "xray.exe"):
        p = out / name
        if p.is_file():
            if os.name != "nt":
                p.chmod(p.stat().st_mode | 0o111)
            return p
    raise Missing("xray binary not found inside archive")


def find_org_json():
    env = os.environ.get("ORG_JSON_JAR")
    if env:
        p = Path(env)
        if p.is_file():
            return p
        raise Missing(f"ORG_JSON_JAR does not exist: {env}")
    jar = CACHE / f"json-{ORG_JSON_VERSION}.jar"
    url = ("https://repo1.maven.org/maven2/org/json/json/"
           f"{ORG_JSON_VERSION}/json-{ORG_JSON_VERSION}.jar")
    return download(url, jar, ORG_JSON_SHA)


def find_javac():
    env = os.environ.get("JAVA_HOME")
    if env:
        p = Path(env) / "bin" / ("javac.exe" if os.name == "nt" else "javac")
        if p.is_file():
            return p
    found = shutil.which("javac")
    if found:
        return Path(found)
    raise Missing("javac not found; set JAVA_HOME (JDK 17 recommended)")


def compile_harness(javac, jar, out):
    srcs = [
        SRC / "NodeConfigCodec.java",
        SRC / "SubscriptionGuard.java",
        SRC / "RoutingPolicy.java",
        PHONE / "tests" / "PoisonHarness.java",
    ]
    cmd = [str(javac), "-encoding", "UTF-8", "-cp", str(jar), "-d", str(out)] + [str(s) for s in srcs]
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        raise RuntimeError("javac failed:\n" + (r.stdout or "") + (r.stderr or ""))


def run_xray(xray, config, tmp):
    cfg = Path(tmp) / "check.json"
    cfg.write_text(json.dumps(config), encoding="utf-8")
    r = subprocess.run([str(xray), "run", "-test", "-c", str(cfg)],
                       capture_output=True, text=True, errors="replace", timeout=60)
    return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()


def last_line(text):
    lines = [ln for ln in text.replace("\r", "").split("\n") if ln.strip()]
    return lines[-1][:240] if lines else ""


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update-golden", action="store_true",
                        help="rewrite tests/full_config.golden.json from current output")
    parser.add_argument("--allow-skip", action="store_true",
                        help="exit 0 when toolchain/download is unavailable")
    args = parser.parse_args(argv)

    try:
        xray = find_xray()
        jar = find_org_json()
        javac = find_javac()
    except Missing as error:
        message = f"check_poison skipped: {error}"
        print(message, file=sys.stderr)
        return 0 if args.allow_skip else 2

    with tempfile.TemporaryDirectory(prefix="poison-") as td:
        tmp = Path(td)
        classes = tmp / "classes"
        classes.mkdir()
        try:
            compile_harness(javac, jar, classes)
        except RuntimeError as error:
            print(error, file=sys.stderr)
            return 1
        result_path = tmp / "result.json"
        r = subprocess.run(
            [str(Path(javac).with_name("java" if os.name != "nt" else "java.exe")),
             "-cp", str(jar) + os.pathsep + str(classes), "PoisonHarness", str(result_path)],
            capture_output=True, text=True, errors="replace")
        if r.returncode != 0 or not result_path.is_file():
            print("harness failed:\n" + (r.stdout or "") + (r.stderr or ""), file=sys.stderr)
            return 1
        result = json.loads(result_path.read_text(encoding="utf-8"))

        total = result.get("total", 0)
        accepted = result.get("accepted_nodes", [])
        failures = []
        if total < MIN_CASES:
            failures.append(f"corpus too small: {total} < {MIN_CASES}")
        if len(accepted) < MIN_ACCEPTED:
            failures.append(f"accepted too few: {len(accepted)} < {MIN_ACCEPTED} "
                            "(parser may be rejecting valid links)")
        if result.get("rejected", 0) < MIN_REJECTED:
            failures.append(f"rejected too few: {result.get('rejected')} < {MIN_REJECTED} "
                            "(poison corpus lost coverage)")
        if result.get("parse_crashes", 0):
            failures.append(f"parseUri threw {result['parse_crashes']} times")

        for item in accepted:
            cfg = {"log": {"loglevel": "error"}, "outbounds": [item["outbound"]],
                   "routing": {"rules": []}}
            code, out = run_xray(xray, cfg, tmp)
            if code != 0:
                failures.append(f"xray rejected {item['case']}: {last_line(out)}")

        for key in ("full_auto", "full_manual"):
            cfg = result.get(key)
            if not isinstance(cfg, dict):
                failures.append(f"{key} missing from harness output")
                continue
            code, out = run_xray(xray, cfg, tmp)
            if code != 0:
                failures.append(f"xray rejected {key}: {last_line(out)}")

        current = canonical({"auto": result.get("full_auto"),
                             "manual": result.get("full_manual")})
        if args.update_golden:
            GOLDEN.write_text(json.dumps(json.loads(current), ensure_ascii=False,
                                         indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"golden updated: {GOLDEN}")
        elif GOLDEN.is_file():
            wanted = canonical(json.loads(GOLDEN.read_text(encoding="utf-8")))
            if wanted != current:
                failures.append("fullConfig drifted from tests/full_config.golden.json "
                                "(review the diff, then rerun with --update-golden)")
        else:
            failures.append("missing tests/full_config.golden.json")

        if failures:
            for f in failures[:30]:
                print("FAIL " + f, file=sys.stderr)
            if len(failures) > 30:
                print(f"... {len(failures) - 30} more", file=sys.stderr)
            return 1

        print(f"poison OK: {total} cases, {len(accepted)} accepted "
              f"(all pass xray -test), {result.get('rejected')} rejected, "
              f"fullConfig auto/manual pass and match golden")
        return 0


if __name__ == "__main__":
    sys.exit(main())