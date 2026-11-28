# -*- coding: utf-8 -*-
"""Dependency-free Windows tray shell for the verified PhoneProxy installation."""
import ctypes
import json
import os
import shutil
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

APP = Path(__file__).resolve().parent
if getattr(sys, "frozen", False):
    INSTALL = Path(sys.executable).resolve().parent
    APP = INSTALL / "app"
else:
    INSTALL = APP.parent
PROXY = INSTALL / "_proxy"
LOCAL = Path(os.environ.get("LOCALAPPDATA", ""))
DATA = LOCAL / "PhoneProxy" / "data"
RUNTIME = LOCAL / "PhoneProxy" / "runtime"
UPDATES = LOCAL / "PhoneProxy" / "updates"
PYTHON = INSTALL / "runtime" / "python" / "python.exe"
sys.path.insert(0, str(APP))
import install_manifest  # noqa: E402
import tray_state  # noqa: E402

user32 = ctypes.windll.user32
shell32 = ctypes.windll.shell32
kernel32 = ctypes.windll.kernel32
WM_APP = 0x8000
WM_TRAY = WM_APP + 1
WM_COMMAND = 0x0111
WM_TIMER = 0x0113
NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP = 1, 2, 4
MF_STRING = 0
TPM_RETURNCMD = 0x0100
IDI_APPLICATION = 32512
CMD_CONNECT, CMD_DISCONNECT, CMD_MODE, CMD_DOCTOR, CMD_UPDATE, CMD_EXIT = range(1001, 1007)
WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_longlong, wintypes.HWND, wintypes.UINT,
                             wintypes.WPARAM, wintypes.LPARAM)


class NotifyIcon(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND), ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT), ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON), ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD), ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256), ("uTimeout", wintypes.UINT),
        ("uVersion", wintypes.UINT), ("dwInfoFlags", wintypes.DWORD),
        ("szInfoTitle", wintypes.WCHAR * 64),
    ]


model = tray_state.Model()
hwnd = None
icon = None
wndproc = None


def ensure_runtime():
    if not install_manifest.verify_install(INSTALL):
        raise PermissionError("installation hash or ACL verification failed")
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / "logs").mkdir(parents=True, exist_ok=True)
    RUNTIME.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((INSTALL / "install-manifest.json").read_text(encoding="utf-8"))
    for relative, expected in manifest["files"].items():
        if not relative.startswith("_proxy/"):
            continue
        source = INSTALL / relative
        target = RUNTIME / relative[len("_proxy/"):]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if install_manifest.sha256(target) != expected:
            raise PermissionError("runtime deployment hash mismatch")
    return RUNTIME


def environment():
    return dict(os.environ, PHONEPROXY_DATA_DIR=str(DATA), PHONEPROXY_INSTALLED="1",
                PYTHONIOENCODING="utf-8")


def run_script(name, *args):
    runtime = ensure_runtime()
    return subprocess.Popen([str(PYTHON), str(runtime / name)] + list(args),
                            cwd=str(runtime), env=environment(),
                            creationflags=0x08000000)


def broker(action, elevate=False):
    args = [str(APP / "broker.py"), action, "--data-dir", str(DATA)]
    if elevate:
        result = shell32.ShellExecuteW(None, "runas", str(PYTHON),
                                       subprocess.list2cmdline(args), str(INSTALL), 1)
        if result <= 32:
            raise OSError("elevation was cancelled or failed")
        return None
    return subprocess.run([str(PYTHON)] + args, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=30,
                          creationflags=0x08000000)


def connect():
    model.state = "connecting"
    if model.mode == "tun":
        broker("tun-start", elevate=True)
    else:
        run_script("start_proxy.py")


def disconnect():
    if model.mode == "tun":
        broker("tun-stop", elevate=True)
    else:
        run_script("stop_proxy.py")
    model.disconnect()


def refresh():
    if model.mode == "tun":
        try:
            result = broker("tun-status")
            model.update({"state": "running" if result and "运行中" in result.stdout else "idle",
                          "mode": "tun"})
        except Exception:
            model.update({"state": "idle", "mode": "tun"})
    else:
        status = {}
        try:
            status = json.loads((DATA / "watchdog_status.json").read_text(encoding="utf-8"))
        except Exception:
            pass
        if (DATA / "ENABLED").exists():
            status.setdefault("state", "running")
        model.update(dict(status, mode="split"))


def toggle_mode():
    model.mode = "tun" if model.mode == "split" else "split"
    connect()


def doctor():
    run_script("doctor.py")


def update():
    UPDATES.mkdir(parents=True, exist_ok=True)
    manifest = UPDATES / "release-manifest.json"
    signature = UPDATES / "release-manifest.sig"
    if not manifest.is_file() or not signature.is_file():
        os.startfile(str(UPDATES))
        return
    from updater import stage
    try:
        previous = int((INSTALL / "version.txt").read_text(encoding="utf-8").strip())
    except Exception:
        previous = 0
    staged = stage(manifest, signature, APP / "release-public.pem", UPDATES,
                   previous_version=previous)
    os.startfile(staged)


@WNDPROC
def window_proc(window, message, wparam, lparam):
    if message == WM_COMMAND:
        action = wparam & 0xffff
        try:
            if action == CMD_CONNECT: connect()
            elif action == CMD_DISCONNECT: disconnect()
            elif action == CMD_MODE: toggle_mode()
            elif action == CMD_DOCTOR: doctor()
            elif action == CMD_UPDATE: update()
            elif action == CMD_EXIT:
                shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(icon))
                user32.PostQuitMessage(0)
        except Exception as error:
            user32.MessageBoxW(None, str(error)[:500], "PhoneProxy", 0x10)
        return 0
    if message == WM_TIMER:
        refresh()
        icon.szTip = model.label()[:127]
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(icon))
        return 0
    if message == WM_TRAY:
        if lparam == 0x205 or lparam == 0x203:  # right click / left double click
            menu = user32.CreatePopupMenu()
            labels = ((CMD_CONNECT, "连接"), (CMD_DISCONNECT, "断开"),
                      (CMD_MODE, "切换 TUN / 分流"), (CMD_DOCTOR, "体检 / 诊断"),
                      (CMD_UPDATE, "检查更新"), (CMD_EXIT, "退出托盘"))
            for command, label in labels:
                user32.AppendMenuW(menu, MF_STRING, command, label)
            pos = wintypes.POINT()
            user32.GetCursorPos(ctypes.byref(pos))
            user32.SetForegroundWindow(window)
            user32.TrackPopupMenu(menu, TPM_RETURNCMD, pos.x, pos.y, 0, window, None)
            user32.DestroyMenu(menu)
        return 0
    return user32.DefWindowProcW(window, message, wparam, lparam)


def main():
    global hwnd, icon, wndproc
    if "--version" in sys.argv:
        print("PhoneProxy tray 4.0.0")
        return 0
    if sys.platform != "win32":
        raise SystemExit("tray requires Windows")
    if not PYTHON.is_file() or not (INSTALL / "install-manifest.json").is_file():
        raise SystemExit("run the installed PhoneProxy tray, not the source tree")
    wndproc = window_proc
    wc = wintypes.WNDCLASSW()
    wc.lpfnWndProc = wndproc
    wc.hInstance = kernel32.GetModuleHandleW(None)
    wc.lpszClassName = "PhoneProxyTray"
    if not user32.RegisterClassW(ctypes.byref(wc)):
        raise ctypes.WinError(ctypes.get_last_error())
    hwnd = user32.CreateWindowExW(0, "PhoneProxyTray", "PhoneProxy", 0, 0, 0, 0, 0,
                                  wintypes.HWND(-3), None, wc.hInstance, None)
    if not hwnd:
        raise ctypes.WinError(ctypes.get_last_error())
    icon = NotifyIcon()
    icon.cbSize = ctypes.sizeof(icon)
    icon.hWnd = hwnd
    icon.uID = 1
    icon.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
    icon.uCallbackMessage = WM_TRAY
    user32.LoadIconW.argtypes = [wintypes.HWND, wintypes.LPCWSTR]
    user32.LoadIconW.restype = wintypes.HICON
    icon.hIcon = user32.LoadIconW(None, ctypes.cast(IDI_APPLICATION, wintypes.LPCWSTR))
    icon.szTip = "PhoneProxy · 未连接"
    if not shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(icon)):
        raise ctypes.WinError(ctypes.get_last_error())
    refresh()
    user32.SetTimer(hwnd, 1, 5000, None)
    message = wintypes.MSG()
    while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
        user32.TranslateMessage(ctypes.byref(message))
        user32.DispatchMessageW(ctypes.byref(message))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
