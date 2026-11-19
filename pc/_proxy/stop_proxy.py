# -*- coding: utf-8 -*-
"""One click: stop everything this folder started and go back to direct.

Order matters: the ENABLED flag is removed first (so neither the keeper nor the
PAC guard can resurrect a proxy), then the keeper is killed, then the PAC, then
every listener / process this folder owns (PID-targeted AND command-line
checked), then the WinINET / environment snapshot taken by 启动代理.bat is put
back verbatim.

At the end it proves direct connectivity with a real request and prints a
per-item checklist, so "关闭" is not a promise, it is a measured state.
"""
import glob
import io
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pacroute            # noqa: E402
import proxyctl as P       # noqa: E402
import sysstate            # noqa: E402

PORTS_SING = (2100, 2101, 2102, 2103, 2090, 2085, 2086, 2087,
              2096, 2097, 2160, 2161, 9089, 9092, 9093, 9094)
PORTS_PAC = tuple(range(8891, 8901))
PORTS_OTHER = ((8891, ("python.exe", "pythonw.exe")),)
WATCH_PID = os.path.join(HERE, "watchdog.pid")
WATCH_STOP = os.path.join(HERE, "STOP_WATCHDOG")
START_LOCK = os.path.join(HERE, "start.lock")
ENABLED = os.path.join(HERE, "ENABLED")
TUN_ACTIVE = os.path.join(HERE, "TUN_ACTIVE")


def log(*a):
    print(*a, flush=True)


def kill_tree(pid, expect_prefix=("python",)):
    img = P.pid_image(pid).lower()
    if not img:
        return False
    if not img.startswith(tuple(expect_prefix)):
        log("  [跳过] pid=%d 是 %s，不是本文件夹的进程" % (pid, img))
        return False
    subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                   capture_output=True, creationflags=0x08000000)
    return True


# ---------------------------------------------------------- process scan
# Signature of this project, independent of where the folder sits.  Desktop
# copies (代理便携版, 代理便携版_backup_*, the git repo's pc/_proxy, a renamed
# copy a user dragged elsewhere) all launch the same script names, so matching
# on the signature is what lets "关闭" really close *everything*.  Matching on
# THIS folder alone was the hole that let an old copy keep the proxy alive.
SIG_RE = (r"_proxy\\(watchdog|pacroute|tun_mode|start_proxy|stop_proxy)\.py"
          r"|_proxy\\singbox_[a-z0-9_]+\.json")


def our_processes(include_copies=True):
    """Every process that belongs to this project, wherever the folder lives.

    One CIM query instead of per-PID calls: `wmic` is gone on Win11 and a
    PowerShell round-trip per PID would take longer than the shutdown itself.
    Returns [(pid, image_lower, cmdline)].
    """
    here = HERE.lower().replace("'", "''")
    script = ("$OutputEncoding=[Text.Encoding]::UTF8;"
              "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
              "$here='%s';$sig='%s';"
              "@(Get-CimInstance Win32_Process | Where-Object {"
              " $_.CommandLine -and ( $_.CommandLine.ToLower().Contains($here)"
              " -or ($sig -and $_.CommandLine.ToLower() -match $sig) ) }) |"
              " Select-Object ProcessId,Name,CommandLine | ConvertTo-Json -Compress"
              % (here, SIG_RE if include_copies else ""))
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                            "-ExecutionPolicy", "Bypass", "-Command", script],
                           capture_output=True, timeout=30,
                           creationflags=0x08000000)
        raw = (p.stdout or b"").decode("utf-8", "replace").strip()
        data = json.loads(raw) if raw else []
        if isinstance(data, dict):
            data = [data]
        out = []
        for r in data:
            try:
                pid, img = int(r.get("ProcessId")), (r.get("Name") or "").lower()
            except (TypeError, ValueError):
                continue
            # The scanner's own powershell.exe matches the signature text in its
            # command line; only our real stack (sing-box + python helpers) counts.
            if img != "sing-box.exe" and not img.startswith("python"):
                continue
            out.append((pid, img, r.get("CommandLine") or ""))
        return out
    except Exception:
        return []


SCRIPTS_OURS = ("watchdog.py", "pacroute.py", "tun_mode.py",
                "start_proxy.py", "bestroute.py")


def _prio(img, cmd):
    """Kill order: the thing that can resurrect the stack must die first."""
    low = (cmd or "").lower()
    if "watchdog.py" in low:
        return 0
    if "tun_mode.py" in low:
        return 1
    if "pacroute.py" in low:
        return 2
    if img == "sing-box.exe":
        return 3
    return 4


def kill_foreign_copies():
    """Kill copies of this project living outside THIS folder.

    The desktop keeps a `代理便携版_backup_*` rollback copy.  Double-clicking
    its 启动代理.bat starts a whole second stack; a per-folder kill would walk
    right past it and its watchdog would keep re-installing the PAC after we
    clean up — exactly the "关了又自己开" symptom.  Two rounds, because a
    keeper can respawn a child in the milliseconds between scan and kill.
    """
    me, parent = os.getpid(), os.getppid()
    here = HERE.lower()
    killed = []
    for _ in range(2):
        foreign = [(p, i, c) for p, i, c in our_processes()
                   if p not in (me, parent) and here not in (c or "").lower()
                   and p not in killed]
        if not foreign:
            break
        foreign.sort(key=lambda t: _prio(t[1], t[2]))
        for pid, img, cmd in foreign:
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           capture_output=True, creationflags=0x08000000)
            killed.append(pid)
        time.sleep(0.6)
    return killed


def kill_our_stack(procs=None):
    """Kill this folder's sing-box and helper scripts, whatever ports they use.

    Catches the experimental leftovers (2160/2161/9089...) that a fixed port
    list missed, without ever touching a user-owned sing-box.
    """
    me, parent = os.getpid(), os.getppid()
    procs = procs if procs is not None else our_processes()
    killed = []
    for pid, img, cmd in procs:
        if pid in (me, parent):
            continue
        ours = img == "sing-box.exe"
        if not ours and img.startswith("python"):
            low = cmd.lower()
            ours = any(s in low for s in SCRIPTS_OURS)
        if not ours:
            continue
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                       capture_output=True, creationflags=0x08000000)
        killed.append(pid)
    return killed


def stop_watchdog():
    # Sentinel first: a live keeper that sees it exits cleanly on its next tick.
    try:
        with io.open(WATCH_STOP, "w", encoding="utf-8", newline="\n") as f:
            f.write("stop")
    except OSError:
        pass
    pid = None
    try:
        pid = int(io.open(WATCH_PID).read().strip())
    except Exception:
        pass
    killed = False
    if pid:
        killed = kill_tree(pid)
    # wait for the tree to die (a rebuild child may hold sing-box)
    t0 = time.time()
    while pid and P.pid_alive(pid) and time.time() - t0 < 6:
        time.sleep(0.3)
    if pid and P.pid_alive(pid):
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                       capture_output=True, creationflags=0x08000000)
    for name in (WATCH_PID, WATCH_STOP):
        try:
            os.remove(name)
        except OSError:
            pass
    return bool(pid) and killed


def stop_tun():
    """TUN needs admin; its own module asks for elevation only when active.

    A TUN started from an older copy leaves no marker in THIS folder, yet its
    pcproxy adapter keeps hijacking every packet (and holds the clash_api
    port), which looks exactly like "all nodes died".  So ask the TUN module
    whether the adapter is up, not just whether our marker file exists.
    """
    tun_py = os.path.join(HERE, "tun_mode.py")
    marker = os.path.isfile(TUN_ACTIVE)
    foreign = False
    if not marker and os.path.isfile(tun_py):
        try:
            import tun_mode as T
            foreign = bool(T.foreign_tun_pids()) or T.adapter_present()
        except Exception:
            foreign = False
    if not marker and not foreign:
        return "未启用"
    if not os.path.isfile(tun_py):
        return "标记存在但脚本缺失"
    if foreign and not marker:
        log("      检测到别的副本留下的 TUN（pcproxy 网卡还在），需要管理员权限清理；")
        log("      马上会弹一次 UAC，请点「是」。")
    try:
        r = subprocess.run([sys.executable, tun_py, "stop"], cwd=HERE, timeout=180)
        return ("已停止" if r.returncode == 0 else "停止失败 rc=%d" % r.returncode)
    except Exception as e:
        return "停止失败 %r" % (e,)


def stop_pinned():
    killed = []
    try:
        pids = json.load(io.open(os.path.join(HERE, "pinned_pids.json"), encoding="utf-8"))
    except Exception:
        pids = []
    for pid in pids:
        try:
            pid = int(pid)
        except Exception:
            continue
        # 三元组核验：镜像名 + 命令行含本目录。PID 会被内核复用，只比镜像名
        # 可能把用户自己的 sing-box 或别的进程误杀。
        if P.pid_image(pid).lower() == "sing-box.exe":
            cmd = P.pid_cmdline(pid)
            if cmd and HERE.lower() not in cmd.lower():
                continue
            subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                           capture_output=True, creationflags=0x08000000)
            killed.append(pid)
    for path in glob.glob(os.path.join(HERE, "one_*.pid")):
        try:
            pid = int(io.open(path).read().strip())
        except Exception:
            continue
        if P.pid_image(pid).lower() == "sing-box.exe":
            cmd = P.pid_cmdline(pid)
            if cmd and HERE.lower() not in cmd.lower():
                continue
            subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                           capture_output=True, creationflags=0x08000000)
            killed.append(pid)
        try:
            os.remove(path)
        except OSError:
            pass
    try:
        os.remove(os.path.join(HERE, "pinned_pids.json"))
    except OSError:
        pass
    return killed


def _other_ports():
    """静态 8891 + apply 时因端口被占而换用的实际 PAC 端口。"""
    out = list(PORTS_OTHER)
    try:
        u = sysstate.pac_url()          # e.g. http://127.0.0.1:8892/proxy.pac
        port = int(u.rsplit(":", 1)[1].split("/")[0])
        if port not in [p for p, _ in out] and port not in PORTS_SING:
            out.append((port, ("python.exe", "pythonw.exe")))
    except Exception:
        pass
    return tuple(out)


def free_ports():
    killed = []
    for port in PORTS_SING:
        # Only processes whose command line points into this folder are ours
        # (review C3): a user-owned sing-box on the same port is left alone.
        killed += P.kill_port(port, expect=("sing-box.exe",), expect_cmd=HERE, log=log)
    others = _other_ports()
    for port, imgs in others:
        killed += P.kill_port(port, expect=imgs, expect_cmd=HERE, log=log)
    # re-check: a rebuild tree killed a moment ago may still be releasing
    for _ in range(6):
        busy = [p for p in PORTS_SING + tuple(p for p, _ in others)
                if P.listen_ok(p)]
        if not busy:
            break
        for port in busy:
            expect = ("sing-box.exe",) if port in PORTS_SING else ("python.exe", "pythonw.exe")
            killed += P.kill_port(port, expect=expect, expect_cmd=HERE, log=log)
        time.sleep(0.5)
    return killed


# ---------------------------------------------------- stale proxy remnants
def _dead_local(v):
    """True when an env/registry proxy value points at a dead 127.0.0.1 port."""
    try:
        s = str(v)
        for scheme in ("http://", "https://", "socks5://", "socks5h://", "socks4://"):
            if s.lower().startswith(scheme):
                s = s[len(scheme):]
                break
        host, port = s.rsplit(":", 1)
        port = int(port.split("/")[0])
        if host.strip("[]") not in ("127.0.0.1", "localhost", "::1"):
            return False
        return not P.listen_ok(port)
    except Exception:
        return False


def drop_stale_ours():
    """Clear proxy values that survived a past run and now point at nothing.

    The snapshot restores "what was there before", which may itself be a dead
    2086/8891 from an older version of this tool.  Restoring it would leave the
    machine looking "proxied" with no listener -- the exact broken state the
    user hit.  Only values pointing at a *dead loopback* port are touched.
    """
    touched = []
    st = sysstate.current()
    srv = st.get("proxy_server") or ""
    if srv and not st.get("proxy_enable"):
        parts = [x.split("=", 1)[-1] for x in srv.split(";") if x]
        if parts and all(_dead_local(x) for x in parts):
            sysstate.inet_set("ProxyServer", None)
            sysstate.inet_set("ProxyOverride", None)
            sysstate.notify_wininet()
            touched.append("ProxyServer(dead %s)" % srv)
    for name in sysstate.ENV_NAMES:
        v = st["env"].get(name)
        if v and _dead_local(v):
            sysstate.env_set(name, None)
            touched.append("%s(dead %s)" % (name, v))
    if any(t.startswith(tuple(sysstate.ENV_NAMES)) for t in touched):
        sysstate.broadcast_env()
    return touched


def curl_direct(url, timeout=10):
    env = {k: v for k, v in os.environ.items()
           if k.upper() not in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")}
    try:
        p = subprocess.run(["curl", "-sS", "--ssl-no-revoke", "--max-time", str(timeout),
                            "-o", "NUL", "-w", "%{http_code}", url],
                           capture_output=True, text=True, errors="replace",
                           timeout=timeout + 5, env=env,
                           creationflags=0x08000000)
        return (p.stdout or "").strip()
    except Exception:
        return "000"


def main():
    log("=" * 68)
    log("  便携代理 · 一键关闭（恢复直连）")
    log("=" * 68)

    # 0) The kill-switch: once this file is gone nothing may re-install a proxy.
    try:
        os.remove(ENABLED)
    except OSError:
        pass

    # 0b) Other copies first.  A backup folder started from Explorer keeps its
    # own watchdog, which would rewrite the PAC seconds after we clean up.
    copies = kill_foreign_copies()
    if copies:
        log("[!] 清理了其他副本的进程: " + ", ".join(map(str, copies))
            + "（多半是旧备份目录被启动过）")

    tun = stop_tun()
    tun_ok = tun in ("已停止", "未启用")
    log("[0/4] 全局 TUN 模式: " + tun)

    wd = stop_watchdog()
    log("[1/4] 看门狗: " + ("已停止" if wd else "本来就没在跑"))

    pacroute.clear_pac()
    P.stop_gateway()
    log("[2/4] PAC 已撤下，PAC 服务已停止")

    stack = kill_our_stack()
    pid_kills = stop_pinned()
    port_kills = free_ports()
    all_kills = sorted(set(stack + pid_kills + port_kills))
    log("[3/4] 出口进程已关闭" + (("，结束 PID: " + ", ".join(map(str, all_kills)))
                                 if all_kills else "（没有残留）"))

    sysstate.restore_all()
    touched = drop_stale_ours()
    log("[4/4] 系统代理与命令行变量已还原"
        + (("；顺手清掉指向死端口的旧值: " + ", ".join(touched)) if touched else ""))

    for path in (START_LOCK, os.path.join(HERE, "pac_server.pid"),
                 os.path.join(HERE, "watchdog_guard.json")):
        try:
            os.remove(path)
        except OSError:
            pass

    # ---------------------------------------------------------- verify
    log("")
    log("================ 关闭结果（逐项验证）================")
    all_ports = PORTS_SING + PORTS_PAC + tuple(p for p, _ in _other_ports())
    busy = []
    for p in all_ports:
        if P.listen_ok(p):
            pids = P.port_pids(p)
            busy.append((p, P.pid_image(pids[0]) if pids else "?"))
    if busy:
        log("[!!] 仍有端口在监听: " + ", ".join("%d(%s)" % b for b in busy))
    else:
        log("[OK] 所有代理端口已关闭: " + " ".join(str(p) for p in all_ports))

    procs_left = [(pid, img) for pid, img, _ in our_processes()
                  if img == "sing-box.exe" or img.startswith("python")]
    if procs_left:
        log("[!!] 仍有本目录进程: " + ", ".join("%d(%s)" % x for x in procs_left))
    else:
        log("[OK] 没有本目录的 sing-box / 看门狗 / PAC 进程残留")

    st = sysstate.current()
    log("[%s] 系统代理: AutoConfigURL=%s ProxyEnable=%s" % (
        "OK" if not st["pac"] else "!!",
        st["pac"] if st["pac"] else "（无，直连）", st["proxy_enable"]))
    if st["proxy_server"]:
        log("     （保留了启动前的 ProxyServer=%s，但 ProxyEnable=0，不生效）"
            % st["proxy_server"])
    env_left = [n for n in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
                if st["env"].get(n)]
    if env_left:
        log("[!!] 环境变量仍存在: "
            + ", ".join("%s=%s" % (n, st["env"][n]) for n in env_left))
    else:
        log("[OK] 命令行代理变量已清除")

    code = curl_direct("https://www.baidu.com")
    log("[%s] 直连测试: https://www.baidu.com -> %s" % ("OK" if code == "200" else "!!", code))
    code2 = curl_direct("https://www.gstatic.com/generate_204", timeout=15)
    log("[%s] 直连国际测试: gstatic -> %s（直连国际线路慢不算失败，能通即可）"
        % ("OK" if code2 in ("204", "200") else "!!", code2))

    if os.path.isfile(TUN_ACTIVE):
        log("[!!] TUN 标记仍在：全局模式没停干净（UAC 被取消？），请再关一次。")
    if P.listen_ok(9910):
        log("[提示] 迷雾通客户端仍在本地 9910 待命；它不是系统代理，不影响直连。")
        log("       想彻底退出请手动关掉迷雾通窗口。")
    log("")
    log("[OK] 现在已恢复为直连上网。浏览器不用重开，新请求立即走直连；")
    log("     若个别页面还走旧代理，把那个浏览器窗口完全关掉再开即可。")
    return (0 if not busy and not procs_left and not env_left and tun_ok
            and code == "200" else 2)


if __name__ == "__main__":
    raise SystemExit(main())