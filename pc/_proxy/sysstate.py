# -*- coding: utf-8 -*-
"""The machine-level switches this folder touches: save once, restore exactly.

Two layers
  * WinINET  HKCU\\...\\Internet Settings  AutoConfigURL / ProxyEnable /
    ProxyServer / ProxyOverride   -> browsers and everything that reads the
    Windows proxy.
  * User env HKCU\\Environment  HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY
    -> git, pip, Codex, curl, npm, huggingface-cli ... (new processes only).

`backup_once()` runs before the first write and stores the *previous* values in
state_backup.json.  `restore_all()` puts them back and removes the file, so the
"关闭代理" button returns the machine to exactly the state it had before.
"""
import ctypes
import io
import json
import os
import time
import winreg

HERE = os.path.dirname(os.path.abspath(__file__))
BACKUP = os.path.join(HERE, "state_backup.json")
LOGDIR = os.path.join(HERE, "logs")
K = winreg.HKEY_CURRENT_USER
IS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
ENVROOT = "Environment"
ENV_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
PAC_URL = "http://127.0.0.1:8891/proxy.pac"
PAC_URL_FILE = os.path.join(HERE, "pac_url.txt")


def pac_url():
    """实际生效的 PAC 地址：apply 时可能因 8891 被占而换端口。"""
    try:
        with io.open(PAC_URL_FILE, "r", encoding="utf-8") as f:
            u = f.read().strip()
        if u.startswith("http://127.0.0.1:"):
            return u
    except OSError:
        pass
    return PAC_URL


# ------------------------------------------------------------------ notify
def notify_wininet():
    try:
        wininet = ctypes.WinDLL("wininet")
        wininet.InternetSetOptionW(0, 39, 0, 0)   # SETTINGS_CHANGED
        wininet.InternetSetOptionW(0, 37, 0, 0)   # REFRESH
    except Exception:
        pass


def broadcast_env():
    """Tell Explorer (and anything listening) that the user environment changed."""
    try:
        res = ctypes.c_ulong()
        ctypes.windll.user32.SendMessageTimeoutW(
            0xFFFF, 0x001A, 0, "Environment", 0x0002, 3000, ctypes.byref(res))
    except Exception:
        pass


# ------------------------------------------------------------------ registry
def inet_get(name):
    try:
        with winreg.OpenKey(K, IS) as k:
            return winreg.QueryValueEx(k, name)[0]
    except FileNotFoundError:
        return None


def inet_set(name, value, kind=winreg.REG_SZ):
    with winreg.CreateKeyEx(K, IS, 0, winreg.KEY_SET_VALUE) as k:
        if value is None:
            try:
                winreg.DeleteValue(k, name)
            except FileNotFoundError:
                pass
        else:
            winreg.SetValueEx(k, name, 0, kind, value)


def env_get(name):
    try:
        with winreg.OpenKey(K, ENVROOT) as k:
            return winreg.QueryValueEx(k, name)[0]
    except FileNotFoundError:
        return None


def env_set(name, value):
    with winreg.CreateKeyEx(K, ENVROOT, 0, winreg.KEY_SET_VALUE) as k:
        if value is None:
            try:
                winreg.DeleteValue(k, name)
            except FileNotFoundError:
                pass
        else:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)


# ------------------------------------------------------------------ desired state
def desired_env(cli_port=2090):
    ep = "127.0.0.1:%d" % int(cli_port)
    return {
        "HTTP_PROXY": "http://" + ep,
        "HTTPS_PROXY": "http://" + ep,
        "ALL_PROXY": "socks5://" + ep,
        # 本机 / 局域网 / Kaggle / 国内域名不绕代理（sing-box 里也配了直连规则，
        # 这里再兜一层：万一 2090 挂了，国内站点和 Kaggle 仍然能直连）。
        # 补全 RFC1918 / 链路本地 / 内网后缀：遵守 NO_PROXY 的 Go/Rust/Python CLI
        # 在内网开发时不该绕道代理（原来只写了 localhost 和 .cn）
        "NO_PROXY": ("localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,"
                     "192.168.0.0/16,169.254.0.0/16,.local,.internal,.lan,"
                     ".corp,.home.arpa,*.cn,.cn,"
                     "kaggle.com,kaggleusercontent.com"),
    }


def apply_env(cli_port=2090):
    """Idempotently export the proxy variables; returns what was written."""
    want = desired_env(cli_port)
    changed = False
    for name, value in want.items():
        if env_get(name) != value:
            env_set(name, value)
            changed = True
    if changed:
        broadcast_env()
    return want


def env_ok(cli_port=2090):
    want = desired_env(cli_port)
    return all(env_get(n) == v for n, v in want.items())


def clear_env():
    changed = False
    for name in ENV_NAMES:
        if env_get(name) is not None:
            env_set(name, None)
            changed = True
    if changed:
        broadcast_env()


def clear_env_ours(cli_port=2090):
    """Delete only the variables whose current value is exactly what we write.

    The no-backup restore path must not wipe a proxy the user configured
    elsewhere (review C8).
    """
    changed = False
    for name, value in desired_env(cli_port).items():
        if env_get(name) == value:
            env_set(name, None)
            changed = True
    if changed:
        broadcast_env()
    return changed


# ------------------------------------------------------------------ backup / restore
def backup_once():
    """Capture the pre-existing state; never overwrite an existing backup."""
    if os.path.isfile(BACKUP):
        return False
    data = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "inet": {
            "AutoConfigURL": inet_get("AutoConfigURL"),
            "ProxyEnable": inet_get("ProxyEnable"),
            "ProxyServer": inet_get("ProxyServer"),
            "ProxyOverride": inet_get("ProxyOverride"),
        },
        "env": {n: env_get(n) for n in ENV_NAMES},
    }
    with io.open(BACKUP, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    return True


def read_backup():
    try:
        with io.open(BACKUP, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def restore_inet(snap):
    for name in ("AutoConfigURL", "ProxyServer", "ProxyOverride"):
        inet_set(name, snap.get(name))
    pe = snap.get("ProxyEnable")
    if pe is None:
        inet_set("ProxyEnable", None)
    else:
        inet_set("ProxyEnable", int(pe), winreg.REG_DWORD)
    notify_wininet()


def restore_env(snap):
    for name in ENV_NAMES:
        env_set(name, snap.get(name))
    broadcast_env()


def restore_all():
    """Put the machine back.  Falls back to 'direct + no env proxy' when there
    is no backup (a stop with no recorded start)."""
    snap = read_backup()
    if snap:
        try:
            os.makedirs(LOGDIR, exist_ok=True)
            with io.open(os.path.join(LOGDIR, "state_restored.json"), "w",
                         encoding="utf-8", newline="\n") as f:
                json.dump(dict(snap, restored_at=time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
                    f, ensure_ascii=False, indent=1)
        except OSError:
            pass
        restore_inet(snap.get("inet") or {})
        restore_env(snap.get("env") or {})
        try:
            os.remove(BACKUP)
        except OSError:
            pass
        return {"backup": True, "restored": snap}
    # No backup: only undo what can be proven to be ours (review C8).
    # ProxyEnable is deliberately left alone: without a backup we cannot know
    # whether the user turned it on for some other proxy.
    touched = []
    try:
        if (inet_get("AutoConfigURL") or "") == pac_url():
            inet_set("AutoConfigURL", None)
            touched.append("AutoConfigURL")
            notify_wininet()
    except Exception:
        pass
    if clear_env_ours():
        touched.append("env")
    return {"backup": False, "restored": None, "touched": touched}


def current():
    return {
        "pac": inet_get("AutoConfigURL"),
        "proxy_enable": inet_get("ProxyEnable"),
        "proxy_server": inet_get("ProxyServer"),
        "env": {n: env_get(n) for n in ENV_NAMES},
    }
