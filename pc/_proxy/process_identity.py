"""Stable Windows process identity for safe lifecycle management.

A PID or image name is not ownership proof. Every process started by this
project records its creation time, executable hash, command line, owner SID,
and configuration hash. Termination re-inspects the live process and requires
all recorded fields to still match.
"""
import glob
import hashlib
import io
import json
import os
import re
import subprocess
from pathlib import Path

NOWIN = 0x08000000
_REQUIRED = ("created_at", "exe_path", "exe_sha256", "command_line", "owner_sid")


def _sha256(path):
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def _config_from_command(command_line):
    if not command_line:
        return ""
    match = re.search(r"(?:^|\s)(?:-c|--config)(?:\s+|=)(\"[^\"]*\"|'[^']*'|\S+)",
                      command_line, re.IGNORECASE)
    if not match:
        return ""
    return match.group(1).strip("\"'")


def inspect(pid):
    """Return a live process identity, or None when it cannot be proven."""
    if os.name != "nt":
        return None
    pid = int(pid)
    script = (
        "$ErrorActionPreference='Stop';"
        "$p=Get-CimInstance Win32_Process -Filter 'ProcessId=%d';" % pid
        + "if($null -eq $p){Write-Output 'null';exit 0};"
        "$o=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid;"
        "[PSCustomObject]@{pid=$p.ProcessId;"
        "created_at=$p.CreationDate.ToUniversalTime().ToString('o');"
        "exe_path=$p.ExecutablePath;command_line=$p.CommandLine;owner_sid=$o.SID}"
        "|ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=20, creationflags=NOWIN)
        if result.returncode != 0:
            return None
        data = json.loads((result.stdout or "").strip() or "null")
        if not isinstance(data, dict):
            return None
        exe_path = data.get("exe_path") or ""
        command_line = data.get("command_line") or ""
        config_path = _config_from_command(command_line)
        return {
            "pid": int(data.get("pid") or pid),
            "created_at": data.get("created_at") or "",
            "exe_path": exe_path,
            "exe_sha256": _sha256(exe_path) if exe_path else "",
            "command_line": command_line,
            "owner_sid": data.get("owner_sid") or "",
            "config_path": config_path,
            "config_sha256": _sha256(config_path) if config_path else "",
        }
    except (OSError, ValueError, TypeError, json.JSONDecodeError, subprocess.SubprocessError):
        return None


def _atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with io.open(temporary, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=1)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def record(pid, config_path=None, record_path=None):
    """Inspect and atomically record a process identity."""
    data = inspect(pid)
    if not data:
        return None
    if config_path:
        data["config_path"] = os.path.abspath(config_path)
        data["config_sha256"] = _sha256(config_path)
    if record_path:
        _atomic_json(record_path, data)
    return data


def record_many(entries, record_path):
    """Record multiple (pid, config_path) pairs as one JSON list."""
    records = []
    for pid, config_path in entries:
        data = record(pid, config_path)
        if data:
            records.append(data)
    _atomic_json(record_path, records)
    return records


def load_record(record_path):
    try:
        data = json.loads(Path(record_path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def find_record_for_pid(pid, directory):
    """Find a single-process identity record for a PID in this installation."""
    for path in glob.glob(os.path.join(directory, "*.identity.json")):
        data = load_record(path)
        if data and data.get("pid") == int(pid):
            return path
    return None


def matches(record, expected_config=None):
    """Re-inspect a process and require every recorded identity field to match."""
    if not isinstance(record, dict) or any(not record.get(key) for key in _REQUIRED):
        return False
    current = inspect(record.get("pid"))
    if not current:
        return False
    for key in _REQUIRED:
        if current.get(key) != record.get(key):
            return False
    if record.get("config_path"):
        recorded_config = os.path.abspath(record.get("config_path"))
        current_config = os.path.abspath(current.get("config_path") or "")
        # A staged config may be atomically renamed after launch. In that case
        # the command line still names the old staged path, while the final path
        # must carry the exact bytes that were launched.
        if current_config != recorded_config:
            if not (expected_config and current_config == os.path.abspath(expected_config)
                    and current.get("config_sha256") == record.get("config_sha256")):
                return False
        elif current.get("config_sha256") != record.get("config_sha256"):
            if not (expected_config and _sha256(expected_config) == record.get("config_sha256")):
                return False
    if expected_config:
        expected = os.path.abspath(expected_config)
        current_config = os.path.abspath(current.get("config_path") or "")
        recorded_config = os.path.abspath(record.get("config_path") or "")
        if current_config != expected:
            if not (current_config == recorded_config
                    and _sha256(expected) == record.get("config_sha256")):
                return False
        if current.get("config_sha256") not in ("", record.get("config_sha256")):
            return False
        if _sha256(expected) != record.get("config_sha256"):
            return False
    return True


def terminate_record(record, expected_config=None, log=print):
    """Terminate a positively reidentified record."""
    if not isinstance(record, dict) or not record.get("pid"):
        return False
    if not matches(record, expected_config=expected_config):
        try:
            log("  [skip] pid=%d identity changed or incomplete; not terminating" % int(record["pid"]))
        except Exception:
            pass
        return False
    try:
        result = subprocess.run(["taskkill", "/PID", str(int(record["pid"])), "/T", "/F"],
                                capture_output=True, creationflags=NOWIN)
    except OSError:
        return False
    return result.returncode == 0


def terminate_if_owned(pid, record_path=None, expected_config=None, log=print):
    """Terminate only a positively reidentified process."""
    if record_path is None:
        record_path = find_record_for_pid(pid, os.path.dirname(os.path.abspath(__file__)))
    record = load_record(record_path) if record_path else None
    if not record or int(record.get("pid") or 0) != int(pid):
        return False
    return terminate_record(record, expected_config=expected_config, log=log)
