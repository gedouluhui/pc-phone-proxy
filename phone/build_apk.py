# -*- coding: utf-8 -*-
"""Build the PhoneProxy APK without Gradle.

Pipeline: javac -> d8 -> aapt2 -> zip -> zipalign -> apksigner

Requirements
  * JDK 17 (JAVA_HOME, or edit JDK below)
  * Android SDK build-tools + platform android-35
    (ANDROID_HOME / ANDROID_SDK_ROOT, or the default per-user SDK folder)
  * AndroidLibXrayLite: put libv2ray.aar at phone/libs/libv2ray.aar.
    The script extracts it into phone/libs/xray automatically.
    Download: https://github.com/2dust/AndroidLibXrayLite/releases

Configuration (environment variables, all optional)
  PROXY_KEYSTORE   signing keystore path (auto-generated on first build)
  PROXY_APK_OUT    output APK path
  PROXY_NODES_JSON node list to embed (default assets/nodes.json)

Node list format: [{"tag":"p0","name":"...","outbound":{...}}, ...]
Use gen_nodes.py to convert share links (pinned.json) into this format.
An empty [] builds an app with no bundled nodes; users then import their own
share links or subscription inside the app.
"""
import os
import shutil
import subprocess
import sys
import zipfile
import glob

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.abspath(__file__))


def _first_dir(*paths):
    for p in paths:
        if p and os.path.isdir(p):
            return p
    return None


def find_jdk():
    home = os.environ.get("JAVA_HOME")
    jdk = _first_dir(
        home,
        r"C:\Program Files\Java\jdk-17",
        r"C:\Program Files\Java\jdk-17.0.13",
        r"C:\Program Files\Eclipse Adoptium\jdk-17",
        "/usr/lib/jvm/java-17-openjdk-amd64",
        "/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home",
    )
    if not jdk or not os.path.exists(os.path.join(jdk, "bin", "javac.exe" if os.name == "nt" else "javac")):
        sys.exit("JDK 17 not found. Set JAVA_HOME.")
    return os.path.join(jdk, "bin")


def find_sdk():
    sdk = _first_dir(
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"),
        os.path.expanduser("~/Android/Sdk"),
        os.path.expanduser("~/Library/Android/sdk"),
    )
    if not sdk:
        sys.exit("Android SDK not found. Set ANDROID_HOME.")
    return sdk


def latest_dir(parent, prefix):
    if not os.path.isdir(parent):
        return None
    names = [n for n in os.listdir(parent) if n.startswith(prefix)]
    if not names:
        return None
    return os.path.join(parent, sorted(names)[-1])


def exe(bt, name):
    p = os.path.join(bt, name + (".exe" if os.name == "nt" else ""))
    return p if os.path.exists(p) else os.path.join(bt, name)


JDK = find_jdk()
SDK = find_sdk()
BT = latest_dir(os.path.join(SDK, "build-tools"), "")
if not BT:
    sys.exit("Android build-tools not found under " + SDK)
PLATFORM = latest_dir(os.path.join(SDK, "platforms"), "android-")
if not PLATFORM:
    sys.exit("Android platform not found under " + SDK)
ANDROID_JAR = os.path.join(PLATFORM, "android.jar")

LIBDIR = os.path.join(ROOT, "libs")
AAR = os.path.join(LIBDIR, "libv2ray.aar")
AAR_DIR = os.path.join(LIBDIR, "xray")
AAR_CLASSES = os.path.join(AAR_DIR, "classes.jar")

KEYSTORE = os.environ.get("PROXY_KEYSTORE") or os.path.join(ROOT, "phoneproxy.keystore")
OUT_APK = os.environ.get("PROXY_APK_OUT") or os.path.join(ROOT, "手机代理.apk")
# Prefer a node list you generated (assets/nodes.json, git-ignored); otherwise
# the committed empty sample, which builds an app with no bundled nodes.
NODES_JSON = (os.environ.get("PROXY_NODES_JSON")
              or (os.path.join(ROOT, "assets", "nodes.json")
                  if os.path.exists(os.path.join(ROOT, "assets", "nodes.json"))
                  else os.path.join(ROOT, "assets", "nodes.sample.json")))

env = dict(os.environ, JAVA_HOME=os.path.dirname(JDK), PYTHONIOENCODING="utf-8")


def run(args, **kw):
    print("+", " ".join(str(a) for a in args)[:200], flush=True)
    r = subprocess.run([str(a) for a in args], cwd=ROOT, env=env,
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", **kw)
    if r.stdout.strip():
        print(r.stdout[-3000:])
    if r.returncode != 0:
        print(r.stderr[-4000:])
        sys.exit("FAILED rc=%d" % r.returncode)
    if r.stderr.strip():
        print("[stderr]", r.stderr[-1500:])
    return r


# 0. unpack AndroidLibXrayLite if needed
if not os.path.exists(AAR_CLASSES):
    if not os.path.exists(AAR):
        sys.exit("Missing %s\nDownload libv2ray.aar from "
                 "https://github.com/2dust/AndroidLibXrayLite/releases "
                 "and put it in phone/libs/." % AAR)
    os.makedirs(AAR_DIR, exist_ok=True)
    with zipfile.ZipFile(AAR) as z:
        z.extractall(AAR_DIR)
if not os.path.exists(NODES_JSON):
    sys.exit("Node list not found: " + NODES_JSON)

# 1. signing keystore (self-generated, not a user credential)
if not os.path.exists(KEYSTORE):
    run([os.path.join(JDK, "keytool.exe" if os.name == "nt" else "keytool"),
         "-genkeypair", "-keystore", KEYSTORE, "-alias", "phoneproxy",
         "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
         "-storepass", "android", "-keypass", "android",
         "-dname", "CN=PhoneProxy, OU=Dev, O=OpenSource, C=CN"])

# 2. javac
obj = os.path.join(ROOT, "obj")
shutil.rmtree(obj, ignore_errors=True)
os.makedirs(obj)
srcs = glob.glob(os.path.join(ROOT, "src", "com", "luhui", "phoneproxy", "*.java"))
run([os.path.join(JDK, "javac.exe" if os.name == "nt" else "javac"),
     "-encoding", "UTF-8", "-source", "8", "-target", "8",
     "-classpath", ANDROID_JAR + os.pathsep + AAR_CLASSES, "-d", obj] + srcs)

# 3. d8 (app classes + go/libv2ray classes)
dexout = os.path.join(ROOT, "dexout")
shutil.rmtree(dexout, ignore_errors=True)
os.makedirs(dexout)
classes = glob.glob(os.path.join(obj, "com", "luhui", "phoneproxy", "*.class"))
run([exe(BT, "d8.bat" if os.name == "nt" else "d8"), "--release", "--lib", ANDROID_JAR,
     "--min-api", "24", "--output", dexout, AAR_CLASSES] + classes)
dexfiles = sorted(glob.glob(os.path.join(dexout, "classes*.dex")))
assert dexfiles, "no dex produced"

# 4. aapt2 resources + manifest
reszip = os.path.join(ROOT, "res.zip")
run([exe(BT, "aapt2.exe" if os.name == "nt" else "aapt2"), "compile",
     "--dir", os.path.join(ROOT, "res"), "-o", reszip])
base = os.path.join(ROOT, "base.apk")
run([exe(BT, "aapt2.exe" if os.name == "nt" else "aapt2"), "link", "-o", base,
     "-I", ANDROID_JAR, "--manifest", os.path.join(ROOT, "AndroidManifest.xml"), reszip])

# 5. package dex + assets + native libs
unsigned = os.path.join(ROOT, "unsigned.apk")
with zipfile.ZipFile(base, "r") as zin, zipfile.ZipFile(unsigned, "w", zipfile.ZIP_DEFLATED) as zout:
    for item in zin.infolist():
        zout.writestr(item, zin.read(item.filename))
    for d in dexfiles:
        zout.write(d, os.path.basename(d))
    zout.write(NODES_JSON, "assets/nodes.json")
    for name in ("geoip.dat", "geosite.dat"):
        zout.write(os.path.join(AAR_DIR, "assets", name), "assets/" + name)
    for abi in ("arm64-v8a", "armeabi-v7a", "x86", "x86_64"):
        so = os.path.join(AAR_DIR, "jni", abi, "libgojni.so")
        zout.write(so, "lib/" + abi + "/libgojni.so")

# 6. zipalign + sign
aligned = os.path.join(ROOT, "aligned.apk")
run([exe(BT, "zipalign.exe" if os.name == "nt" else "zipalign"), "-f", "4", unsigned, aligned])
run([exe(BT, "apksigner.bat" if os.name == "nt" else "apksigner"), "sign",
     "--ks", KEYSTORE, "--ks-pass", "pass:android", "--key-pass", "pass:android",
     "--out", OUT_APK, aligned])
run([exe(BT, "apksigner.bat" if os.name == "nt" else "apksigner"),
     "verify", "--print-certs", OUT_APK])
print("APK OK:", OUT_APK, os.path.getsize(OUT_APK), "bytes")
