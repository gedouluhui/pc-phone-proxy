# -*- coding: utf-8 -*-
"""One click: stop everything this folder started and go back to direct.

Order matters: the keeper is stopped first (kill its whole process tree, so a
rebuild that is halfway through cannot resurrect sing-box afterwards), then the
PAC, then every listener this folder owns (PID-targeted, image-checked), then
the WinINET / environment snapshot taken by 启动代理.bat is put back verbatim.

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

PORTS_SING = (2100, 2101, 2102, 2103, 2090, 2085, 2086, 2087, 2096, 2097, 9090)
PORTS_OTHER = ((8891, ("python.exe", "pythonw.exe")),)
WATCH_PID = os.path.join(HERE, "watchdog.pid")
WATCH_STOP = os.path.join(HERE, "STOP_WATCHDOG")
START_LOCK = os.path.join(HERE, "start.lock")


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
    return bool(pid) and (killed or True)


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
        if P.pid_image(pid).lower() == "sing-box.exe":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                           capture_output=True, creationflags=0x08000000)
            killed.append(pid)
    for path in glob.glob(os.path.join(HERE, "one_*.pid")):
        try:
            pid = int(io.open(path).read().strip())
        except Exception:
            continue
        if P.pid_image(pid).lower() == "sing-box.exe":
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

    wd = stop_watchdog()
    log("[1/4] 看门狗: " + ("已停止" if wd else "本来就没在跑"))

    pacroute.clear_pac()
    P.stop_gateway()
    log("[2/4] PAC 已撤下，PAC 服务已停止")

    pid_kills = stop_pinned()
    port_kills = free_ports()
    all_kills = sorted(set(pid_kills + port_kills))
    log("[3/4] 出口进程已关闭" + (("，结束 PID: " + ", ".join(map(str, all_kills)))
                                 if all_kills else "（没有残留）"))

    snap = sysstate.restore_all()
    log("[4/4] 系统代理与命令行变量已还原")

    # ---------------------------------------------------------- verify
    log("")
    log("================ 关闭结果（逐项验证）================")
    others = _other_ports()
    busy = []
    for p in PORTS_SING + tuple(p for p, _ in others):
        if P.listen_ok(p):
            pids = P.port_pids(p)
            busy.append((p, P.pid_image(pids[0]) if pids else "?"))
    if busy:
        log("[!!] 仍有端口在监听: " + ", ".join("%d(%s)" % b for b in busy))
    else:
        log("[OK] 所有代理端口已关闭: "
            + " ".join(str(p) for p in PORTS_SING + tuple(p for p, _ in others)))

    st = sysstate.current()
    log("[OK] 系统代理: AutoConfigURL=%s ProxyEnable=%s" % (
        st["pac"] if st["pac"] else "（无，直连）", st["proxy_enable"]))
    if st["proxy_server"]:
        log("     （保留了启动前的 ProxyServer=%s，但 ProxyEnable=0，不生效）"
            % st["proxy_server"])
    left = [n for n in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
            if st["env"].get(n)]
    if left:
        log("[!!] 环境变量仍存在: " + ", ".join("%s=%s" % (n, st["env"][n]) for n in left))
    else:
        log("[OK] 命令行代理变量已清除")

    code = curl_direct("https://www.baidu.com")
    log("[%s] 直连测试: https://www.baidu.com -> %s" % ("OK" if code == "200" else "!!", code))

    if P.listen_ok(9910):
        log("[提示] 迷雾通客户端仍在本地 9910 待命；它不是系统代理，不影响直连。")
        log("       想彻底退出请手动关掉迷雾通窗口。")
    try:
        if os.path.isfile(START_LOCK):
            os.remove(START_LOCK)
    except OSError:
        pass
    log("")
    log("[OK] 现在已恢复为直连上网。浏览器不用重开，新请求立即走直连；")
    log("     若个别页面还走旧代理，把那个浏览器窗口完全关掉再开即可。")
    return 0 if not busy and code == "200" else 2


if __name__ == "__main__":
    raise SystemExit(main())
