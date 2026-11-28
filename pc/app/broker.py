# -*- coding: utf-8 -*-
"""Least-privilege elevated broker for installed TUN start/stop/status."""
import argparse
import ctypes
import os
import subprocess
import sys
from pathlib import Path

APP = Path(__file__).resolve().parent
INSTALL_DIR = APP.parent
PROXY_DIR = INSTALL_DIR / "_proxy"
sys.path.insert(0, str(APP))
import install_manifest  # noqa: E402

NOWIN = 0x08000000


def is_elevated():
    return sys.platform == "win32" and bool(ctypes.windll.shell32.IsUserAnAdmin())


def command(action, data_dir):
    if action not in ("tun-start", "tun-stop", "tun-status"):
        raise ValueError("unsupported broker action")
    if not install_manifest.verify_install(INSTALL_DIR):
        raise PermissionError("installed payload hash or ACL verification failed")
    if not install_manifest.verify_data_dir(data_dir):
        raise PermissionError("data directory is outside the current user's PhoneProxy directory")
    os.makedirs(data_dir, exist_ok=True)
    env = dict(os.environ, PHONEPROXY_DATA_DIR=data_dir, PHONEPROXY_INSTALLED="1",
               PYTHONIOENCODING="utf-8")
    verb = {"tun-start": "start", "tun-stop": "stop", "tun-status": "status"}[action]
    args = [sys.executable, str(PROXY_DIR / "tun_mode.py"), verb]
    if verb in ("start", "stop"):
        args += ["--admin", "--result", os.path.join(data_dir, "logs", "tun_broker_result.json")]
    return args, env


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("tun-start", "tun-stop", "tun-status"))
    parser.add_argument("--data-dir", required=True)
    args = parser.parse_args(argv)
    if args.action != "tun-status" and not is_elevated():
        print("broker requires verified elevation", file=sys.stderr)
        return 2
    try:
        cmd, env = command(args.action, args.data_dir)
        os.makedirs(os.path.join(args.data_dir, "logs"), exist_ok=True)
        result = subprocess.run(cmd, cwd=str(PROXY_DIR), env=env, capture_output=True,
                                text=True, encoding="utf-8", errors="replace",
                                creationflags=NOWIN, timeout=300 if args.action == "tun-start" else 60)
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return result.returncode
    except (OSError, PermissionError, ValueError, subprocess.SubprocessError) as error:
        print("broker rejected: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
