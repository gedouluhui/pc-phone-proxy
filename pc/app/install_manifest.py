# -*- coding: utf-8 -*-
"""Verify the installed broker/payload hashes, ACL and user-data boundary."""
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

NOWIN = 0x08000000
REQUIRED = ("app/broker.py", "app/install_manifest.py", "_proxy/tun_mode.py",
            "_proxy/tun_supervisor.py", "_proxy/bin/sing-box.exe",
            "_proxy/bin/wintun.dll")


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inside(path, parent):
    try:
        return os.path.commonpath([os.path.realpath(path), os.path.realpath(parent)]) == os.path.realpath(parent)
    except ValueError:
        return False


def _acl_safe(install_dir):
    script = ("$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
              "$p=$env:VERIFY_INSTALL_DIR;$a=Get-Acl -LiteralPath $p;"
              "$bad=@($a.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and "
              "($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) -and "
              "($_.IdentityReference.Value -match 'Users|Everyone|Authenticated Users') });"
              "if($bad.Count){exit 3}")
    env = dict(os.environ, VERIFY_INSTALL_DIR=str(install_dir))
    result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, env=env, creationflags=NOWIN, timeout=20)
    return result.returncode == 0


def verify_install(install_dir, require_program_files=True):
    install_dir = os.path.realpath(install_dir)
    if require_program_files:
        roots = [os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles") or r"C:\Program Files"]
        if not any(_inside(install_dir, root) for root in roots):
            return False
    if not _acl_safe(install_dir):
        return False
    manifest_path = os.path.join(install_dir, "install-manifest.json")
    try:
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(manifest, dict) or manifest.get("schema") != 1:
        return False
    files = manifest.get("files")
    if not isinstance(files, dict) or any(name not in files for name in REQUIRED):
        return False
    for relative, expected in files.items():
        if not isinstance(relative, str) or not relative or os.path.isabs(relative):
            return False
        normalized = relative.replace("\\", "/")
        if normalized.startswith("../") or "/../" in normalized or ".." in normalized.split("/"):
            return False
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            return False
        path = os.path.realpath(os.path.join(install_dir, normalized))
        if not _inside(path, install_dir) or not os.path.isfile(path):
            return False
        if sha256(path) != expected:
            return False
    return True


def verify_data_dir(data_dir, local_appdata=None):
    local = local_appdata or os.environ.get("LOCALAPPDATA")
    if not local or not data_dir:
        return False
    expected = os.path.realpath(os.path.join(local, "PhoneProxy", "data"))
    actual = os.path.realpath(data_dir)
    return actual == expected and _inside(actual, os.path.realpath(local))
