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
GAI = 2098            # Google AI 专用出口（需过 Google 地区闸门）
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
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
        j = http_json("http://127.0.0.1:19090/proxies/grp-general")
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
    us = [r for r in node_rows() if (r.get("loc") or "").upper() in ("US", "USA")]
    # 只按下载排序会选中上传为 0 的坏节点：192.220.47.85 dl=1898kB/s 但
    # ul=0、github_ok=False，当时能过 Steam 的 countrycode 检查，跑一阵后
    # 整个出口 reset，2096 变成「端口活着、上游死」。PAC 里 STEAM 和
    # ChatGPT/OpenAI 都首选 2096，于是每次请求先吃一次连接重置再回退。
    good = [r for r in us if r.get("github_ok") and (r.get("ul_kbps") or 0) > 0]
    cands = good or us
    cands.sort(key=lambda r: -(r.get("dl_kbps") or 0))
    for r in cands[:5]:
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
def _gai_ok(timeout=8):
    """Google AI Studio is region-gated by exit IP.

    Some free nodes are refused outright: notebooklm answers
    `notebook.google/?location=unsupported` while the landing page still
    returns 200, which is why 体检 looked green and the browser still showed
    "Available regions".  Probe the thing Google actually gates.
    """
    try:
        op = urllib.request.build_opener(urllib.request.ProxyHandler(
            {"http": "http://127.0.0.1:%d" % GAI, "https": "http://127.0.0.1:%d" % GAI}))
        req = urllib.request.Request("https://notebooklm.google.com/",
                                     headers={"User-Agent": UA})
        with op.open(req, timeout=timeout) as r:
            return "unsupported" not in r.geturl().lower()
    except Exception:
        return False


def _write_gai_config(uris):
    """2098 serves a urltest group, not a single node.

    A free node passed the Google probe at 06:07 and was dead by 06:15 (SSL
    EOF) -- exactly the failure users see as "AI Studio 又打不开".  urltest
    re-probes every member and moves to a live one on its own, so one dead
    node no longer takes the whole AI path down.
    """
    import nodes as N
    outs = []
    for uri in uris:
        ob, _ = N.parse_uri(uri)
        if not ob:
            continue
        ob["tag"] = "n%d" % len(outs)
        outs.append(ob)
    if not outs:
        return None
    if len(outs) > 1:
        outs.append({"type": "urltest", "tag": "grp",
                     "outbounds": [o["tag"] for o in outs],
                     "url": "https://www.gstatic.com/generate_204",
                     "interval": "60s", "tolerance": 300})
        final = "grp"
    else:
        final = outs[0]["tag"]
    return {"log": {"level": "error"},
            "inbounds": [{"type": "socks", "tag": "in-s", "listen": "127.0.0.1",
                          "listen_port": GAI + 1},
                         {"type": "http", "tag": "in-h", "listen": "127.0.0.1",
                          "listen_port": GAI}],
            "outbounds": outs,
            "route": {"final": final}}


def _start_gai(uris):
    if isinstance(uris, str):
        uris = [uris]
    cfg = _write_gai_config(uris)
    if not cfg:
        return False
    path = os.path.join(HERE, "singbox_gai.json")
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f)
    if not P.wait_port_free([GAI + 1, GAI], timeout=6.0, expect_cmd="singbox_gai.json"):
        return False
    logp = os.path.join(HERE, "logs", "singbox_gai.log")
    with io.open(logp, "ab") as lf:
        proc = subprocess.Popen([P.SING_EXE, "run", "-c", path], cwd=HERE,
                                stdout=lf, stderr=subprocess.STDOUT,
                                creationflags=0x00000008 | 0x08000000)
    for _ in range(24):
        if proc.poll() is not None:
            return False
        if up(GAI) and up(GAI + 1):
            with io.open(os.path.join(HERE, "one_%d.pid" % GAI), "w") as f:
                f.write(str(proc.pid))
            return True
        time.sleep(0.5)
    return False


def _google_bad():
    """Servers Google itself refused (notebooklm -> location=unsupported)."""
    try:
        with io.open(os.path.join(HERE, "google_bad.json"), encoding="utf-8") as f:
            return {str(x).lower() for x in (json.load(f) or [])}
    except Exception:
        return set()


def _remember_google_bad(server):
    bad = _google_bad()
    if server and server.lower() not in bad:
        bad.add(server.lower())
        try:
            with io.open(os.path.join(HERE, "google_bad.json"), "w",
                         encoding="utf-8", newline="\n") as f:
                json.dump(sorted(bad), f, ensure_ascii=False, indent=1)
        except OSError:
            pass


def ensure_gai():
    """Dedicated exit for Google AI sites, built from the nodes actually in use.

    Two lessons from the field:
    * the stale deep pool is full of placeholder rows and public HTTP proxies
      that refuse connections within minutes -- building the AI path from it
      produced a one-member group that was already dead;
    * probing every candidate at startup costs a minute and still picks a node
      that dies by the time the tunnel is up.
    So: take the live pinned members, drop the ones Google refused, and let
    urltest fail over between the rest.
    """
    if up(GAI) and _gai_ok():
        return True
    bad = _google_bad()
    import nodes as N
    uris = []
    try:
        with io.open(os.path.join(HERE, "pinned.json"), encoding="utf-8") as f:
            p = json.load(f)
        for u in (p.get("members") or {}):
            ob, _ = N.parse_uri(u)
            if not ob:
                continue
            if (ob.get("server") or "").lower() in bad:
                continue
            uris.append(u)
            if len(uris) >= 10:
                break
    except Exception as e:
        log("  [warn] 读 pinned.json 失败: %r" % (e,))
    if not uris:
        rows = [r for r in node_rows() if r.get("uri")]
        rows.sort(key=lambda r: -(r.get("score") or 0))
        uris = [r["uri"] for r in rows[:3]]
    if not uris or not _start_gai(uris):
        log("  [warn] Google AI 专用出口没起来；AI 站点回退到快速出口")
        return False
    log("  Google AI 专用出口: %d 颗节点自动切换 (2098)" % len(uris))
    return _gai_ok(timeout=6)


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
    # HTTPS only: the pinned route sends port 80 straight out, so an http
    # lookup would always report the local ISP address.
    try:
        with op.open("https://ipinfo.io/json", timeout=timeout) as r:
            j = json.loads(r.read(4000).decode("utf-8", "replace"))
        if j.get("ip"):
            return "%s (%s)" % (j.get("ip"), j.get("country") or "?")
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
            g = http_json("http://127.0.0.1:19090/proxies/" + grp)
            info["now"] = g.get("now")
            h = g.get("history") or []
            if h:
                info["delay"] = h[-1].get("delay")
            for tag in (g.get("all") or []):
                d = None
                try:
                    pj = http_json("http://127.0.0.1:19090/proxies/" + tag, timeout=1.5)
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
                             # DETACHED|NEW_PROCESS_GROUP，与 pacroute 的 PAC 服务一致。
                             # 原来用 DETACHED|CREATE_NO_WINDOW 是自相矛盾的组合：
                             # NO_WINDOW 会给子进程建控制台，宿主控制台一销毁，看门狗
                             # 就无声消失（不写日志、不跑 finally）。2026-11-18 实测。
                             creationflags=0x00000008 | 0x00000200)
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
        # proxyctl 的候选里混着公网 HTTP 代理。把系统代理指向陌生人的服务器
        # 既慢又不可信（还能看到明文流量），所以只接受本机端口。
        try:
            srv = (sysstate.current().get("proxy_server") or "")
        except Exception:
            srv = ""
        if srv and "127.0.0.1" not in srv and "localhost" not in srv:
            log("[失败] 兜底选到了公网代理 %s —— 不可信且不稳，已撤销，保持直连。" % srv)
            try:
                sysstate.restore_all()
            except Exception:
                pass
            log("       请双击 重新扫描节点.bat 重扫节点（10-40 分钟）。")
            return 1
        port = 2087 if up(2087) else (9910 if up(9910) else HK)
        try:
            sysstate.backup_once()
            sysstate.apply_env(port)
        except Exception as e:
            log("  [警告] 命令行代理变量没写进去: %r" % (e,))
        v = P.verify_applied("127.0.0.1:%d" % port)
        if not v.get("ok"):
            # 静态代理已指向这个端口；不留一个“看起来已开、实际断网”的状态。
            log("[失败] 兜底出口 %d 实测打不开外网: %s" % (port, v.get("err") or "超时"))
            log("       已撤销代理设置恢复直连。请双击 重新扫描节点.bat 重扫节点。")
            try:
                sysstate.restore_all()
            except Exception:
                pass
            return 1
        log("[OK] 已用通用选路启用，命令行指向 127.0.0.1:%d" % port)
        log("     报告: " + os.path.join(HERE, "report.html"))
        return 0
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
        # A second copy (old backup folder, a copy dragged to another disk)
        # fights us for 2090/2101/2103 and would make us snapshot its dead PAC
        # as "the state to restore".  Close it first, then snapshot.
        copies = []
        try:
            import stop_proxy as _S
            copies = _S.kill_foreign_copies()
        except Exception as e:
            log("  [警告] 检查其他代理副本失败: %r" % (e,))
        if copies:
            log("[0/3] 发现另一份代理副本在运行（多为旧备份目录），已先关闭: "
                + ", ".join(map(str, copies)))
            pacroute.clear_pac()
        # A live TUN owns the default route and the controller port; starting
        # split mode underneath it makes sing-box exit rc=1 and the launcher
        # fall back to some random public HTTP proxy.  Close TUN first.
        try:
            import tun_mode as _T
            if _T.adapter_present():
                log("[0/3] 检测到 TUN 虚拟网卡仍在接管流量，先关闭（需要管理员，"
                    "可能弹一次 UAC）...")
                subprocess.run([sys.executable, os.path.join(HERE, "tun_mode.py"),
                                "stop"], cwd=HERE, timeout=180)
        except Exception as e:
            log("  [警告] 关闭 TUN 失败: %r（若随后出口起不来，请手动关 TUN）" % (e,))
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
        # Google AI 专用出口要在渲染 PAC 之前就位，否则 GOOGLE_APP 只能落到
        # 快速组，而快速组最快的那颗节点经常正是 Google 拒绝的那颗。
        try:
            ensure_gai()
        except Exception as e:
            log("  [警告] Google AI 专用出口启动失败: %r" % (e,))
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

        # ---- static fallback for apps that ignore PAC -----------------
        # NVIDIA / 打印机安装器 / 部分 UWP 只读 ProxyServer。PAC 仍然优先，
        # 浏览器分流不受影响；这类程序拿静态值走 2090，由 sing-box 再分流。
        try:
            sysstate.apply_static(CLI)
        except Exception as e:
            log("  [警告] 静态代理写入失败: %r（下载器可能仍会绕过 PAC）" % (e,))

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
        log("      不认 PAC 的程序(驱动下载器/UWP) -> 静态代理 127.0.0.1:%d" % CLI)
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
        # ENABLED is the keeper's permission slip: no file -> it exits and
        # never re-installs the PAC.  Written only after the exits and the
        # system proxy are actually in place.
        try:
            with io.open(os.path.join(HERE, "ENABLED"), "w",
                         encoding="utf-8", newline="\n") as f:
                f.write("1")
        except OSError as e:
            log("  [警告] 无法写入 ENABLED 标志: %r" % (e,))
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


def gai_only():
    """只重建 Google AI 专用出口（2098），不动隧道和其余出口。

    TUN 里的 AI 域名是通过 127.0.0.1:2098 转发的，所以换掉 2098 就等于给正在
    运行的隧道换了一条 AI 线路，不需要重启网卡、不打断其它流量。
    """
    log("=" * 68)
    log("  只重建 Google AI 专用出口（2098）")
    log("=" * 68)
    ok = ensure_gai()
    log("")
    if ok:
        log("[OK] AI 出口已就绪。浏览器刷新即可，不需要重开代理。")
        return 0
    log("[失败] 没找到可用节点。可先跑 重新扫描节点.bat，或用分流模式。")
    return 1


if __name__ == "__main__":
    if "--gai-only" in sys.argv[1:]:
        raise SystemExit(gai_only())
    raise SystemExit(main())
