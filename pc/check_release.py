#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check tracked release inputs and Windows installer PE/Authenticode integrity.

Local builds may be unsigned. PROXY_RELEASE=1 (or PROXY_RELEASE_BUILD) requires a
valid Authenticode signature and, when set, a matching PHONEPROXY_WINDOWS_SIGNER.
"""
import argparse
import os
import struct
import subprocess
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PHONE = ROOT / "phone"
sys.path.insert(0, str(PHONE))
import check_release as phone_guard  # noqa: E402

DEFAULT_INSTALLER = ROOT / "pc" / "dist" / "PhoneProxy-Setup-4.0.0.exe"
FORBIDDEN_SUFFIXES = (".exe", ".dll")


def signature_required():
    return bool(os.environ.get("PROXY_RELEASE") or os.environ.get("PROXY_RELEASE_BUILD"))


def authenticode(path):
    if os.name != "nt":
        return False, "Authenticode verification requires Windows"
    script = ("$ErrorActionPreference='Stop';"
              "$s=Get-AuthenticodeSignature -LiteralPath $env:PHONEPROXY_VERIFY_PATH;"
              "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
              "$s.Status.ToString() + '|' + $s.SignerCertificate.Subject")
    env = dict(os.environ, PHONEPROXY_VERIFY_PATH=str(Path(path).resolve()))
    try:
        result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                                capture_output=True, text=True, encoding="utf-8", errors="strict",
                                env=env, creationflags=0x08000000, timeout=30)
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return False, "Authenticode verification failed"
    if result.returncode != 0 or "|" not in result.stdout:
        return False, "Authenticode verification failed"
    status, subject = result.stdout.strip().split("|", 1)
    expected = os.environ.get("PHONEPROXY_WINDOWS_SIGNER", "").strip()
    return status == "Valid" and (not expected or expected in subject), subject or status


def check_installer(path, require_signature=None):
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError("installer is missing: %s" % path.name)
    size = path.stat().st_size
    if size < 0x40 or size > 2 * 1024**3:
        raise ValueError("installer size is invalid")
    with open(path, "rb") as stream:
        header = stream.read(0x40)
        if header[:2] != b"MZ":
            raise ValueError("installer is not a Windows PE executable")
        pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
        if pe_offset < 0x40 or pe_offset + 28 > size:
            raise ValueError("installer PE header offset is invalid")
        stream.seek(pe_offset)
        coff = stream.read(28)
        if coff[:4] != b"PE\0\0":
            raise ValueError("installer PE signature is invalid")
        machine = struct.unpack_from("<H", coff, 4)[0]
        optional_magic = struct.unpack_from("<H", coff, 24)[0]
    if not ((machine == 0x8664 and optional_magic == 0x20B) or
            (machine == 0x14C and optional_magic == 0x10B)):
        raise ValueError("installer must be an x86/x64 Windows PE executable")
    required = signature_required() if require_signature is None else require_signature
    if required:
        valid, detail = authenticode(path)
        if not valid:
            raise ValueError("installer Authenticode signature is not valid: %s" % detail)
    return True


def tracked_sensitive():
    tracked = []
    for name in phone_guard.git_tracked():
        parts = PurePosixPath(name.replace("\\", "/").lower()).parts
        if phone_guard.sensitive_path(name) or any(part.endswith(FORBIDDEN_SUFFIXES) for part in parts):
            tracked.append(name)
    return tracked


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("installers", nargs="*")
    args = parser.parse_args(argv)
    failed = False
    try:
        tracked = tracked_sensitive()
    except Exception as error:
        print("FAIL: cannot inspect git tracked files: %s" % error)
        failed = True
    else:
        if tracked:
            failed = True
            print("FAIL: credential or binary files are tracked by git:")
            for name in tracked:
                print("  " + repr(name))
        else:
            print("OK: git tracks no node credentials, keystores, APKs or Windows binaries")
    targets = [Path(value) for value in args.installers]
    if not targets and DEFAULT_INSTALLER.is_file():
        targets = [DEFAULT_INSTALLER]
    required = signature_required()
    for target in targets:
        try:
            check_installer(target, require_signature=required)
        except (OSError, ValueError) as error:
            failed = True
            print("FAIL: installer %s: %s" % (target.name, error))
        else:
            suffix = "Authenticode verified" if required else "unsigned local build allowed"
            print("OK: installer %s: Windows PE (%s)" % (target.name, suffix))
    if not targets:
        print("OK: no Windows installer artifact present")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
