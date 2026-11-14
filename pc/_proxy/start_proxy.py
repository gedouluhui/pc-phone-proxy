# -*- coding: utf-8 -*-
"""One click: pick the best exits, wire every program to them, prove it works.

  1. HK single node on 2086          (Reddit only; warning if it fails)
  2. pinned urltest group            (2101 ChatGPT, 2103 web/Git, 2090 CLI)
     rebuilt from node_deep.json when a port is dead or the running config has
     no clash API (i.e. it was started by an older build)
  3. split-routing PAC               (all browsers / WinINET apps)
  4. HTTP(S)_PROXY / ALL_PROXY / NO_PROXY -> 127.0.0.1:2090
     (Codex CLI, git, pip, curl, npm, huggingface-cli ... new windows only)
  5. verify every role, print latency / measured download / exit IP
  6. start watchdog.py hidden        (ports, ChatGPT gate, PAC/env drift,
     automatic switch logging, rebuild, last-resort rescan)

Exit 0 only when the ChatGPT gate passes on the live general port.
"""
import io
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pacroute            # noqa: E402
import proxyctl as P       # noqa: E402
import sysstate            # noqa: E402

GEN, FAST, CLI, HK = 2101, 2103, 2090, 2086
STEAM = 2096          # 美国出口：Steam 商店/社区（外区商店）
DEEP = os.path.join(HERE, "node_deep.json")
PINNED = os.path.join(HERE, "pinned.json")
WATCH_PID = os.path.join(HERE, "watchdog.pid")
WATCH_STOP = os.path.join(HERE, "STOP_WATCHDOG")
LOCK = os.path.join(HERE, "start.lock")

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def log(*a):
    print(*a, flush=True)


def up(port):
    s = socket.socket()
    s.settimeout(0.4)
    try:
        return s.connect_ex(("127.0.0.1", int(port))) == 0
    finally:
        s.close()


def run(script, *args):
    cmd = [sys.executable, os.path.join(HERE, script)] + list(args)
    log("  $ " + " ".join(cmd[1:]))
    return subprocess.call(cmd, cwd=HERE)


def http_json(url, timeout=2.5):
    with _OPENER.open(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def clash_ok():
    try:
        j = http_json("http://127.0.0.1:9090/proxies/grp-general")
        return bool(j.get("now") is not None)
    except Exception:
        return False


# ------------------------------------------------------------------ HK node
def best_hk_uri():
    try:
        rows = json.load(open(DEEP, encoding="utf-8"))["rows"]
    except Exception:
        return None
    hk = [r for r in rows if (r.get("loc") or "").upper() in ("HK", "HKG", "HONG KONG")]
    hk = [r for r in hk if r.get("uri")]
    hk.sort(key=lambda r: -(r.get("dl_kbps") or 0))
    return hk[0]["uri"] if hk else None


def hk_ours():
    """2086 is ours only when the recorded PID still owns it and its command
    line points at our singbox_one.json (review C3)."""
    if not up(HK):
        return False
    try:
        pid = int(io.open(os.path.join(HERE, "one_%d.pid" % HK)).read().strip())
    except Exception:
        return False
    if P.pid_image(pid).lower() != "sing-box.exe":
        return False
    return "singbox_one.json" in P.pid_cmdline(pid).lower()


def ensure_hk():
    if hk_ours():
        return True
    if up(HK):
        log("  [警告] 2086 被其他程序占用（不是本工具启动的），Reddit 走快速出口")
        return False
    uri = best_hk_uri()
    if not uri:
        log("  [警告] 深测结果里没有香港节点，Reddit 将走快速出口（可能 403）")
        return False
    log("  启动香港单节点（Reddit 专用）...")
    try:
        ok = P.start_singbox_node(uri, socks_port=2085, http_port=HK)
    except Exception as e:
        log("  [警告] 香港节点启动异常: %r" % (e,))
        return False
    if not ok:
        log("  [警告] 香港节点没起来，Reddit 会走快速出口（可能 403）")
    return ok


# ------------------------------------------------------------------ steam
def _steam_ok(port=STEAM, timeout=15):
    ep = "http://127.0.0.1:%d" % int(port)
    op = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": ep, "https": ep}))
    try:
        with op.open("https://store.steampowered.com/", timeout=timeout) as r:
            body = r.read(300000).decode("utf-8", "replace")
        return '"countrycode":"US"' in body
    except Exception:
        return False


def _kill_one(port=STEAM):
    path = os.path.join(HERE, "one_%d.pid" % int(port))
    try:
        pid = int(io.open(path).read().strip())
    except Exception:
        return
    # 不裸 taskkill：先证明这个 PID 还是本目录拉起的 sing-box。
    # PID 复用时会打到别人的进程上。
    if P.pid_image(pid).lower() != "sing-box.exe":
        try:
            os.remove(path)
        except OSError:
            pass
        return
    cmd = P.pid_cmdline(pid)
    if cmd and HERE.lower() not in cmd.lower():
        try:
            os.remove(path)
        except OSError:
            pass
        return
    subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                   capture_output=True, creationflags=0x08000000)
    try:
        os.remove(path)
    except OSError:
        pass


def ensure_steam():
    """Steam store/community must exit from a US IP (user asked for the
    non-HK foreign store).  Independent sing-box instance on 2096, so it can
    never disturb the pinned general/fast groups."""
    if up(STEAM) and _steam_ok():
        return True
    cands = [r for r in node_rows() if (r.get("loc") or "").upper() in ("US", "USA")]
    cands.sort(key=lambda r: -(r.get("dl_kbps") or 0))
    for r in cands[:3]:
        uri = r.get("uri")
        if not uri:
            continue
        log("  starting Steam US exit (%s %s) ..." % (r.get("tag"), r.get("server")))
        try:
            ok = P.start_singbox_node(uri, socks_port=2097, http_port=STEAM)
        except Exception as e:
            log("  [warn] Steam exit start failed: %r" % (e,))
            continue
        if ok and _steam_ok():
            return True
        log("  [warn] US node cannot open Steam store, trying next")
        _kill_one()
    log("  [warn] no usable US exit; Steam store falls back to the normal line")
    return False


# ------------------------------------------------------------------ display
def node_rows():
    try:
        return json.load(open(DEEP, encoding="utf-8")).get("rows", [])
    except Exception:
        return []


def fmt_speed(k):
    if not k:
        return "-"
    return "%s kB/s (%.1f Mbps)" % (format(int(k), ","), float(k) * 8 / 1024.0)


def fmt_ms(v):
    return ("%d ms" % int(v)) if v else "-"


def exit_ip(port, timeout=8):
    ep = "http://127.0.0.1:%d" % int(port)
    op = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": ep, "https": ep}))
    try:
        with op.open("http://ip-api.com/json/?fields=status,country,countryCode,query",
                     timeout=timeout) as r:
            j = json.loads(r.read().decode("utf-8", "replace"))
        if j.get("status") == "success":
            return "%s (%s %s)" % (j.get("query"), j.get("country"), j.get("countryCode"))
    except Exception:
        pass
    return "-"


def collect_groups():
    rows = node_rows()
    by_uri = {r.get("uri"): r for r in rows if r.get("uri")}
    try:
        pinned = json.load(open(PINNED, encoding="utf-8"))
    except Exception:
        pinned = {}
    uri_by_tag = {t: u for u, t in (pinned.get("members") or {}).items()}
    out = {}
    for role, grp in (("general", "grp-general"), ("fast", "grp-fast")):
        info = {"now": None, "delay": None, "all": []}
        try:
            g = http_json("http://127.0.0.1:9090/proxies/" + grp)
            info["now"] = g.get("now")
            h = g.get("history") or []
            if h:
                info["delay"] = h[-1].get("delay")
            for tag in (g.get("all") or []):
                d = None
                try:
                    pj = http_json("http://127.0.0.1:9090/proxies/" + tag, timeout=1.5)
                    ph = pj.get("history") or []
                    if ph:
                        d = ph[-1].get("delay")
                except Exception:
                    pass
                uri = uri_by_tag.get(tag)
                info["all"].append({"tag": tag, "delay": d,
                                    "row": by_uri.get(uri) if uri else None})
        except Exception:
            pass
        out[role] = info
    return out


def label(row):
    if not row:
        return "内置兜底（迷雾通/直连）"
    return "%s %s %s:%s" % (row.get("loc") or "??", row.get("proto") or "?",
                            row.get("server") or "?", row.get("port") or "?")


# ------------------------------------------------------------------ watchdog
def ensure_watchdog():
    pid = None
    try:
        pid = int(io.open(WATCH_PID).read().strip())
    except Exception:
        pass
    if pid and P.pid_alive(pid):
        img = P.pid_image(pid).lower()
        if img.startswith("python") and "watchdog.py" in P.pid_cmdline(pid).lower():
            return pid, False
    try:
        os.remove(WATCH_STOP)
    except OSError:
        pass
    pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    exe = pyw if os.path.isfile(pyw) else sys.executable
    logp = os.path.join(HERE, "logs", "watchdog.out")
    os.makedirs(os.path.dirname(logp), exist_ok=True)
    with open(logp, "ab") as logf:
        p = subprocess.Popen([exe, os.path.join(HERE, "watchdog.py")], cwd=HERE,
                             stdout=logf, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL,
                             creationflags=0x00000008 | 0x08000000)  # DETACHED|NO_WINDOW
    with io.open(WATCH_PID, "w", encoding="utf-8", newline="\n") as f:
        f.write(str(p.pid))
    time.sleep(1.0)
    return p.pid, True


# ------------------------------------------------------------------ lock
def take_lock():
    for _ in range(2):
        try:
            fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            return 0
        except FileExistsError:
            pid = 0
            try:
                pid = int(io.open(LOCK).read().strip())
            except Exception:
                pass
            if pid and P.pid_alive(pid):
                log("另一个启动程序正在运行 (pid=%d)，请稍候再试。" % pid)
                return 3
            try:
                os.remove(LOCK)
            except OSError:
                pass
    return 3


def release_lock():
    try:
        os.remove(LOCK)
    except OSError:
        pass


# ------------------------------------------------------------------ fallback
def fallback():
    log("[!] 深测出口组没起来，回退到通用选路（可能要几分钟）...")
    rc = run("proxyctl.py", "enable")
    if rc == 0:
        port = 2087 if up(2087) else (9910 if up(9910) else HK)
        try:
            sysstate.backup_once()
            sysstate.apply_env(port)
        except Exception as e:
            log("  [警告] 命令行代理变量没写进去: %r" % (e,))
        log("[OK] 已用通用选路启用，命令行指向 127.0.0.1:%d" % port)
        log("     报告: " + os.path.join(HERE, "report.html"))
    else:
        log("[失败] 没有任何可用出口。确认本机联网后重试；日志在 _proxy\\logs\\")
    return rc


# ------------------------------------------------------------------ main
def banner():
    log("=" * 68)
    log("  便携代理 · 一键启动    " + HERE)
    log("=" * 68)


def main():
    t0 = time.time()
    banner()
    rc = take_lock()
    if rc:
        return rc
    try:
        # Capture the pre-existing system state BEFORE touching anything --
        # otherwise the PAC we are about to install would be saved as
        # "the state to restore" and 关闭代理 would restore a dead PAC.
        try:
            sysstate.backup_once()
        except Exception as e:
            # Without a backup, 关闭代理 cannot restore the user's own proxy.
            log("  [错误] 备份系统代理状态失败: %r（中止启动，避免关闭时无法还原）" % (e,))
            return 3

        ensure_hk()
        ensure_steam()

        # ---- exits -------------------------------------------------
        if up(GEN) and up(FAST) and up(CLI) and clash_ok():
            log("[1/3] 出口组已在运行，复用（组内每 90 秒自动重测、自动换节点）")
        else:
            log("[1/3] 出口组不在线或配置过期，按深测库重建 ...")
            if run("bestroute.py", "--apply") != 0:
                return fallback()

        # ---- PAC ---------------------------------------------------
        info = pacroute.apply_pac("127.0.0.1:%d" % GEN, "127.0.0.1:%d" % FAST)
        if not info.get("ok"):
            log("[失败] PAC 安装失败: %s" % info.get("err"))
            return 1
        vg = P.verify_applied("127.0.0.1:%d" % GEN)
        if not vg.get("ok"):
            # 复验要从 speed.cloudflare.com 下 1 MB，单次非 200 或刚换出口时
            # 的 TLS 抖动都算失败。重建一次要 90 秒且会拆掉在线栈，先原地
            # 重试一次（2026-11-10 实发：重建后首验假失败，紧接着重测即绿）。
            log("      ChatGPT 出口复验未过，2 秒后原地重试一次 …")
            time.sleep(2)
            vg = P.verify_applied("127.0.0.1:%d" % GEN)
        if not vg.get("ok"):
            log("      ChatGPT 出口复验失败，按深测库强制重建一次 ...")
            if run("bestroute.py", "--apply") != 0:
                return fallback()
            pacroute.apply_pac("127.0.0.1:%d" % GEN, "127.0.0.1:%d" % FAST)
            vg = P.verify_applied("127.0.0.1:%d" % GEN)

        # ---- CLI env ----------------------------------------------
        try:
            sysstate.apply_env(CLI)
        except Exception as e:
            log("  [警告] 命令行代理变量写入失败: %r" % (e,))

        vf = P.verify_applied("127.0.0.1:%d" % FAST)
        vc = P.verify_applied("127.0.0.1:%d" % CLI)

        # ---- report ------------------------------------------------
        log("[2/3] 浏览器分流 PAC: " + info["url"])
        log("      ChatGPT/Claude -> %d   网页/Git/HF -> %d   Reddit -> %s"
            % (GEN, FAST, ("%d" % HK) if info.get("hk") else "未启用"))
        log("      Steam store -> %s" % (("127.0.0.1:%d (US)" % STEAM) if info.get("steam") else "normal line"))
        log("      命令行环境变量: HTTP(S)_PROXY -> 127.0.0.1:%d（新开的终端生效）" % CLI)
        log("")
        groups = collect_groups()
        for role, title, port, v in (
                ("general", "ChatGPT/Claude", GEN, vg),
                ("fast", "网页/Git/HF", FAST, vf)):
            g = groups.get(role, {})
            now_tag = g.get("now") or "?"
            row = None
            for m in g.get("all", []):
                if m["tag"] == now_tag:
                    row = m.get("row")
            delay = g.get("delay") or v.get("ttfb_ms")
            log("  %-14s 端口 %d  当前节点 %s  %s  延迟 %s  实测下载 %s" % (
                title, port, now_tag, label(row), fmt_ms(delay),
                fmt_speed(v.get("speed_kbps"))))
        log("  %-14s 端口 %d  按域名自动走上面两条出口  探测 %s" % (
            "命令行/Codex", CLI, fmt_ms(vc.get("ttfb_ms"))))
        if up(HK):
            log("  %-14s 端口 %d  香港单节点（Reddit 专用）" % ("Reddit", HK))

        log("")
        log("  出口 IP: ChatGPT %s | 网页 %s" % (exit_ip(GEN), exit_ip(FAST)))
        members = groups.get("general", {}).get("all", [])
        if members:
            bits = []
            for m in members[:8]:
                r = m.get("row") or {}
                bits.append("%s %s/%s" % (
                    m["tag"],
                    ("%sms" % m["delay"]) if m.get("delay") else "?",
                    ("%skB/s" % int(r.get("dl_kbps") or 0)) if r else "-"))
            log("  组内候选: " + "  ".join(bits))

        # ---- keeper ------------------------------------------------
        pid, fresh = ensure_watchdog()
        log("")
        log("[3/3] 兜底已就位: 看门狗 pid=%d%s" % (pid, "（新启动）" if fresh else "（已在运行）"))
        log("      1) 组内节点掉线/变慢: urltest 每 90 秒重测，自动切到组内最快")
        log("      2) 端口掉线 / ChatGPT 打不开: 看门狗自动从深测库重建（60 秒巡检）")
        log("      3) 整个池子失效: 自动重扫公共源（10-40 分钟，12 小时最多一次）")
        log("      4) PAC 或命令行变量被别的软件改掉: 看门狗自动写回")
        log("")
        report = P.render_report()
        log("[OK] 用时 %.1fs   报告: %s" % (time.time() - t0, report))
        log("     浏览器若还打不开，请完全退出再打开一次（让它重新读取 PAC）。")
        return 0 if vg.get("ok") else 2
    finally:
        release_lock()


if __name__ == "__main__":
    raise SystemExit(main())
