# -*- coding: utf-8 -*-
"""Build PhoneProxy without Gradle: javac -> d8 -> aapt2 -> zipalign -> apksigner.

Requires JDK 17, Android SDK build-tools/platform and phone/libs/libv2ray.aar
(or an existing phone/libs/xray extraction). No work is performed on import.

--public requires the selected node input to be exactly an empty JSON array.
PROXY_NODES_JSON selects an input; otherwise prefer assets/nodes.json, then
assets/nodes.sample.json. Relative configured paths are relative to phone/.
PROXY_RELEASE (legacy alias PROXY_RELEASE_BUILD) also enforces public checks
and requires an existing PROXY_KEYSTORE and a non-demo PROXY_KS_PASS.
PROXY_KS_ALIAS defaults to phoneproxy. Passwords use the signers' env channels.
PROXY_APK_OUT selects the final path (default phone/手机代理.apk).
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from release_guard import ReleaseCheckError, nodes_in_apk, read_nodes

ROOT = Path(__file__).resolve().parent


class BuildError(ValueError):
    """A build could not complete; the previous final APK is retained."""


def _first_dir(*paths):
    for path in paths:
        if path and os.path.isdir(path):
            return path
    return None


def find_jdk():
    jdk = _first_dir(
        os.environ.get("JAVA_HOME"),
        r"C:\Program Files\Java\jdk-17",
        r"C:\Program Files\Java\jdk-17.0.13",
        r"C:\Program Files\Eclipse Adoptium\jdk-17",
        "/usr/lib/jvm/java-17-openjdk-amd64",
        "/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home",
    )
    if not jdk or not Path(jdk, "bin", "javac.exe" if os.name == "nt" else "javac").is_file():
        raise BuildError("JDK 17 not found. Set JAVA_HOME.")
    return Path(jdk) / "bin"


def find_sdk():
    sdk = _first_dir(
        os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"),
        os.path.expanduser("~/Android/Sdk"),
        os.path.expanduser("~/Library/Android/sdk"),
    )
    if not sdk:
        raise BuildError("Android SDK not found. Set ANDROID_HOME.")
    return Path(sdk)


def latest_dir(parent, prefix):
    if not parent.is_dir():
        return None
    names = sorted(path for path in parent.iterdir()
                   if path.is_dir() and path.name.startswith(prefix))
    return names[-1] if names else None


def exe(directory, name):
    suffix = ".bat" if name in ("d8", "apksigner") else ".exe"
    return directory / (name + suffix if os.name == "nt" else name)


def configured_path(value, default):
    path = Path(value) if value else default
    return path if path.is_absolute() else ROOT / path


def signing_config(release):
    keystore = configured_path(os.environ.get("PROXY_KEYSTORE"), ROOT / "phoneproxy.keystore")
    alias = os.environ.get("PROXY_KS_ALIAS", "phoneproxy")
    password = os.environ.get("PROXY_KS_PASS", "android")
    if not alias or not password:
        raise BuildError("signing preflight: PROXY_KS_ALIAS and PROXY_KS_PASS must not be empty")
    if release:
        if password == "android" or not os.environ.get("PROXY_KEYSTORE"):
            raise BuildError("signing preflight: release requires PROXY_KEYSTORE and non-demo PROXY_KS_PASS")
        if not keystore.is_file():
            raise BuildError("signing preflight: release keystore must already exist")
    return keystore, alias, password


def run(args, env, cwd):
    # Print env references rather than signing config values. Never print tool
    # diagnostics for signing: a failing tool can echo secrets or key metadata.
    args = [str(arg) for arg in args]
    sensitive = Path(args[0]).stem.lower() in ("keytool", "apksigner")
    display = list(args)
    for option, reference in (("--ks", "$PROXY_KEYSTORE"), ("-keystore", "$PROXY_KEYSTORE"),
                              ("--ks-key-alias", "$PROXY_KS_ALIAS"), ("-alias", "$PROXY_KS_ALIAS")):
        if option in display:
            display[display.index(option) + 1] = reference
    password = env["PROXY_KS_PASS"]

    def redacted(text):
        return text.replace(password, "<redacted>") if password else text

    print("+", redacted(subprocess.list2cmdline(display)), flush=True)
    try:
        result = subprocess.run(args, cwd=str(cwd), env=env, capture_output=True,
                                text=True, encoding="utf-8", errors="replace")
    except OSError:
        raise BuildError("cannot execute build tool: " + Path(args[0]).name) from None
    if not sensitive:
        if result.stdout.strip():
            print(redacted(result.stdout)[-3000:])
        if result.stderr.strip():
            print("[stderr]", redacted(result.stderr)[-4000:])
    if result.returncode != 0:
        raise BuildError("%s failed (rc=%d)" % (Path(args[0]).name, result.returncode))
    return result


def unpack_aar(stage):
    existing = ROOT / "libs" / "xray"
    if (existing / "classes.jar").is_file():
        return existing
    aar = ROOT / "libs" / "libv2ray.aar"
    if not aar.is_file():
        raise BuildError("Missing phone/libs/libv2ray.aar (or extracted libs/xray/classes.jar)")
    dest = stage / "xray"
    dest.mkdir()
    with zipfile.ZipFile(aar) as archive:
        for item in archive.infolist():
            path = (dest / item.filename).resolve()
            if os.path.commonpath((str(dest), str(path))) != str(dest):
                raise BuildError("unsafe path in AAR archive")
        archive.extractall(dest)
    return dest


def build(stage, nodes, public, keystore, alias, env, jdk, bt, android_jar, release):
    """Produce and verify a staged APK; never write the final output path."""
    aar_dir = unpack_aar(stage)
    aar_classes = aar_dir / "classes.jar"
    if not keystore.exists():
        if release:
            raise BuildError("release keystore is no longer available; refusing key generation")
        print("WARNING: generating a local test keystore; not for public releases")
        run([exe(jdk, "keytool"), "-genkeypair", "-keystore", keystore, "-alias", alias,
             "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
             "-storepass:env", "PROXY_KS_PASS", "-keypass:env", "PROXY_KS_PASS",
             "-dname", "CN=PhoneProxy, OU=Dev, O=OpenSource, C=CN"], env, stage)

    obj, dexout = stage / "obj", stage / "dexout"
    obj.mkdir()
    dexout.mkdir()
    srcs = sorted((ROOT / "src" / "com" / "luhui" / "phoneproxy").glob("*.java"))
    run([exe(jdk, "javac"), "-encoding", "UTF-8", "-source", "8", "-target", "8",
         "-classpath", str(android_jar) + os.pathsep + str(aar_classes), "-d", obj] + srcs,
        env, stage)
    classes = sorted((obj / "com" / "luhui" / "phoneproxy").glob("*.class"))
    run([exe(bt, "d8"), "--release", "--lib", android_jar, "--min-api", "24",
         "--output", dexout, aar_classes] + classes, env, stage)
    dexfiles = sorted(dexout.glob("classes*.dex"))
    if not dexfiles:
        raise BuildError("no dex produced")

    reszip, base = stage / "res.zip", stage / "base.apk"
    run([exe(bt, "aapt2"), "compile", "--dir", ROOT / "res", "-o", reszip], env, stage)
    run([exe(bt, "aapt2"), "link", "-o", base, "-I", android_jar,
         "--manifest", ROOT / "AndroidManifest.xml", reszip], env, stage)
    unsigned = stage / "unsigned.apk"
    with zipfile.ZipFile(base) as zin, zipfile.ZipFile(unsigned, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            zout.writestr(item, zin.read(item))
        for dex in dexfiles:
            zout.write(dex, dex.name)
        # Use the validated in-memory snapshot, never re-open a mutable node input.
        zout.writestr("assets/nodes.json", json.dumps(nodes, ensure_ascii=False).encode("utf-8"))
        for name in ("geoip.dat", "geosite.dat"):
            zout.write(aar_dir / "assets" / name, "assets/" + name)
        for abi in ("arm64-v8a", "armeabi-v7a", "x86", "x86_64"):
            zout.write(aar_dir / "jni" / abi / "libgojni.so", "lib/" + abi + "/libgojni.so")

    aligned, signed = stage / "aligned.apk", stage / "signed.apk"
    run([exe(bt, "zipalign"), "-f", "4", unsigned, aligned], env, stage)
    run([exe(bt, "apksigner"), "sign", "--ks", keystore, "--ks-key-alias", alias,
         "--ks-pass", "env:PROXY_KS_PASS", "--key-pass", "env:PROXY_KS_PASS",
         "--out", signed, aligned], env, stage)
    run([exe(bt, "apksigner"), "verify", "--print-certs", signed], env, stage)
    nodes_in_apk(signed, require_empty=public)
    return signed


def preflight_nodes():
    """用真 Xray 内核校验 nodes.json。没有 xray 二进制就跳过（本地无网也能打包）。"""
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "check_nodes.py")
    if not os.path.isfile(script):
        return
    r = subprocess.run([sys.executable, script], capture_output=True, text=True, errors="replace")
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0:
        sys.stderr.write(out + "\n")
        raise BuildError("nodes.json 有节点过不了 Xray 配置校验（见上）")
    line = out.strip().splitlines()[-1] if out.strip() else "nodes preflight skipped"
    print(line)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", action="store_true", help="require an empty selected node input")
    args = parser.parse_args(argv)
    # Preserve legacy truthiness: any nonempty value enables release protections.
    release = bool(os.environ.get("PROXY_RELEASE") or os.environ.get("PROXY_RELEASE_BUILD"))
    public = args.public or release
    local_nodes = ROOT / "assets" / "nodes.json"
    selected = configured_path(os.environ.get("PROXY_NODES_JSON"),
                               local_nodes if local_nodes.exists() else ROOT / "assets" / "nodes.sample.json")
    try:
        nodes = read_nodes(selected, require_empty=public)
    except ReleaseCheckError as exc:
        print("FAIL: node preflight:", exc)
        return 1

    committed = False
    try:
        if not public:
            preflight_nodes()
        keystore, alias, password = signing_config(release)
        jdk, sdk = find_jdk(), find_sdk()
        bt = latest_dir(sdk / "build-tools", "")
        platform = latest_dir(sdk / "platforms", "android-")
        if not bt or not platform:
            raise BuildError("Android build-tools/platform not found")
        env = dict(os.environ, JAVA_HOME=str(jdk.parent), PROXY_KS_PASS=password,
                   PYTHONIOENCODING="utf-8")
        output = configured_path(os.environ.get("PROXY_APK_OUT"), ROOT / "手机代理.apk")
        output.parent.mkdir(parents=True, exist_ok=True)
        # Same filesystem as final output, so promotion is atomic (including on Windows).
        with tempfile.TemporaryDirectory(prefix=".phoneproxy-build-", dir=str(output.parent)) as temp:
            signed = build(Path(temp), nodes, public, keystore, alias, env, jdk, bt,
                           platform / "android.jar", release=release)
            os.replace(signed, output)
            committed = True  # Commit point: later cleanup cannot undo promotion.
    except (BuildError, ReleaseCheckError) as exc:
        print("FAIL:", exc)
        return 1
    except (OSError, zipfile.BadZipFile, ValueError):
        # No raw exception text: filenames/tool errors may contain sensitive input.
        if not committed:
            print("FAIL: build filesystem/archive operation failed; final APK was not promoted")
            return 1
        print("WARNING: 产物已验证并晋升，但暂存清理失败")
    if public:
        print("public build: assets/nodes.json = [] (0 nodes)")
    else:
        print("WARNING: private APK; do not publish (embedded nodes: %d)" % len(nodes))
    print("APK OK: verified output atomically promoted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
