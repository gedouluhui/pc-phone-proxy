# -*- coding: utf-8 -*-
"""Optional TUN global mode: every app, including ones that ignore PAC/WinINET.

Split mode (default) covers browsers and CLI tools.  UWP apps, some launchers
and Windows services only use WinHTTP/raw sockets and can never see 127.0.0.1
proxies (AppContainer loopback restriction), so they need a real virtual
adapter.  This module:

  start   build sing-box_tun.json from the pinned exits, ask for UAC once,
          launch sing-box with a Wintun adapter, prove the adapter exists
  stop    kill that sing-box (after image+cmdline checks), remove markers
  status  one line for the doctor

The split-mode stack is stopped first, so the two modes never fight over the
same ports.  Everything TUN changes (adapter + routes) is owned by the
sing-box process and disappears with it.
"""
import ctypes
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

PINNED = os.path.join(HERE, "singbox_pinned.json")
CFG = os.path.join(HERE, "singbox_tun.json")
PID = os.path.join(HERE, "tun.pid")
ACTIVE = os.path.join(HERE, "TUN_ACTIVE")
RESULT = os.path.join(HERE, "tun_result.json")
STARTED = os.path.join(HERE, "tun_started.txt")
LOG = os.path.join(HERE, "logs", "tun.log")
SB_LOG = os.path.join(HERE, "logs", "tun_singbox.log")
IFACE = "pcproxy"
TUN_ADDR = "172.19.0.1/30"
# Project-owned controller port.  9090 is the Clash default and is routinely
# taken by Clash Verge / mihomo / an older TUN copy; sharing it made our exits
# die at startup with a message that looked exactly like "every node is dead".
CLASH_PORT = 19091
CREATE_NO_WINDOW = 0x08000000


def log(*a):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + " ".join(str(x) for x in a)
    # Write the file FIRST: an elevated child may inherit a console handle it
    # cannot print to, and a failing print() used to abort log() before the
    # line ever reached the file, leaving the parent with nothing to show.
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with io.open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass
    try:
        print(line, flush=True)
    except Exception:
        pass


def write_result(rc, msg):
    try:
        with io.open(RESULT, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"rc": int(rc), "msg": msg, "at": time.time()}, f,
                      ensure_ascii=False)
    except OSError:
        pass


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate(args, wait=90):
    """Re-run ourselves elevated; the child writes tun_result.json.

    The child runs in its own (elevated) console, so without streaming its log
    the user stares at an empty window for a minute and cannot tell whether it
    is working or stuck.  Tail logs/tun.log and print it live, the same way
    split mode shows its progress.
    """
    try:
        os.remove(RESULT)
    except OSError:
        pass
    try:
        os.remove(STARTED)
    except OSError:
        pass
    exe = sys.executable
    params = subprocess.list2cmdline([os.path.join(HERE, "tun_mode.py")]
                                     + list(args) + ["--admin",
                                                     "--result", RESULT])
    # Start from the current end of file: only show what this run produces.
    try:
        pos = os.path.getsize(LOG)
    except OSError:
        pos = 0
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params,
                                             HERE, 0)
    if rc <= 32:
        return 1, "UAC 被取消或无法提权 (ShellExecute=%d)" % rc

    # ShellExecuteW also returns >32 when the user cancels UAC (1223), so the
    # return code alone cannot tell "running" from "never started".  The child
    # drops a marker as its first action; no marker in 12s means UAC was not
    # confirmed, and waiting the full timeout would just hide the real problem.
    t_start = time.time()
    while time.time() - t_start < 12 and not os.path.isfile(STARTED):
        time.sleep(0.3)
    if not os.path.isfile(STARTED):
        return 1, ("UAC 未确认：12 秒内没有提权进程启动。若没看到弹窗，"
                   "请看任务栏闪烁的盾牌图标并点「是」，然后重试。")

    def pump():
        nonlocal pos
        try:
            with io.open(LOG, "r", encoding="utf-8", errors="replace") as f:
                f.seek(pos)
                chunk = f.read()
                pos = f.tell()
        except OSError:
            return
        if not chunk:
            return
        try:
            sys.stdout.write(chunk)
            sys.stdout.flush()
        except UnicodeEncodeError:
            enc = sys.stdout.encoding or "gbk"
            sys.stdout.write(chunk.encode(enc, "replace").decode(enc, "replace"))
            sys.stdout.flush()

    t0 = time.time()
    while time.time() - t0 < wait:
        pump()
        if os.path.isfile(RESULT):
            time.sleep(0.2)
            pump()
            try:
                with io.open(RESULT, encoding="utf-8") as f:
                    j = json.load(f)
                return int(j.get("rc") or 0), j.get("msg") or ""
            except Exception:
                break
        time.sleep(0.4)
    pump()
    return 1, "提权后的进程没有回报结果（%.0fs），请看 logs/tun.log" % wait


# ------------------------------------------------------------------ config
def build_config():
    try:
        with io.open(PINNED, encoding="utf-8") as f:
            base = json.load(f)
    except Exception as e:
        raise SystemExit("读不到 singbox_pinned.json: %r（先跑一次启动代理）" % (e,))
    outbounds = base.get("outbounds") or []
    tags = {o.get("tag") for o in outbounds}
    for need in ("grp-general", "grp-any", "direct"):
        if need not in tags:
            raise SystemExit("singbox_pinned.json 缺少出口 %s，先跑一次启动代理" % need)

    # Google AI 的地区闸门跟 IP 走：TUN 若只把 AI 域名丢进 grp-general，最快
    # 那颗节点可能正是 Google 拒绝的。2098 是 启动代理 起的专用出口（已经过
    # 地区判定），TUN 通过一个本地 http outbound 串上去，规则与分流模式一致。
    gai_tag = None
    try:
        if P.listen_ok(2098):
            outbounds = outbounds + [{"type": "http", "tag": "gai",
                                      "server": "127.0.0.1", "server_port": 2098}]
            gai_tag = "gai"
    except Exception:
        gai_tag = None

    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:19091"}},
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "interface_name": IFACE,
            "address": [TUN_ADDR],
            "mtu": 1500,
            "auto_route": True,
            "strict_route": True,
            "stack": "gvisor",
        }],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": True,
            "final": "grp-any",
            "rules": [
                # 先嗅探域名：后面的 domain_suffix 才能命中 TLS/HTTP 目标
                {"action": "sniff", "inbound": ["tun-in"],
                 "sniffer": ["http", "tls", "quic"], "timeout": "500ms"},
                # 隐私与国内直连：与分流模式完全一致的优先级
                {"domain_suffix": pacroute.DOMESTIC, "outbound": "direct"},
                {"domain_suffix": pacroute.SENSITIVE, "outbound": "direct"},
                {"ip_is_private": True, "outbound": "direct"},
                # 系统 DNS 走本机网络；UDP/QUIC 直连（经节点不可靠，浏览器会回落 TCP）
                {"port": 53, "outbound": "direct"},
                {"network": "udp", "outbound": "direct"},
                # 明文 HTTP 不经免费节点（与分流模式一致）
                {"port": 80, "outbound": "direct"},
                {"domain_suffix": pacroute.DIRECT, "outbound": "direct"},
                {"domain_suffix": pacroute.STEAM_DIRECT, "outbound": "direct"},
                # AI 站必须走合格出口；其余默认走合并组
                {"domain_suffix": pacroute.GOOGLE_APP,
                 "outbound": gai_tag or "grp-general"},
                {"domain_suffix": pacroute.GENERAL, "outbound": "grp-general"},
            ],
        },
    }
    return cfg


def check_config(path):
    r = subprocess.run([P.SING_EXE, "check", "-c", path],
                       capture_output=True, text=True, errors="replace",
                       timeout=60, creationflags=CREATE_NO_WINDOW)
    return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()


# ------------------------------------------------------------------ process
def read_pid():
    try:
        return int(io.open(PID, encoding="utf-8").read().strip())
    except Exception:
        return 0


def ours(pid):
    if pid <= 0:
        return False
    if not P.pid_image(pid).lower().startswith("sing-box"):
        return False
    cmd = P.pid_cmdline(pid) or ""
    return CFG.lower() in cmd.lower() or "singbox_tun" in cmd.lower()


def alive(pid):
    return pid > 0 and ours(pid)


def tun_pids():
    """PID list of sing-box processes running *this* TUN config."""
    here = HERE.lower().replace("'", "''")
    script = ("$OutputEncoding=[Text.Encoding]::UTF8;"
              "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
              "$here='%s';"
              "@(Get-CimInstance Win32_Process -Filter \"Name='sing-box.exe'\" |"
              " Where-Object { $_.CommandLine -and"
              " $_.CommandLine.ToLower().Contains($here) -and"
              " $_.CommandLine.ToLower().Contains('singbox_tun') }) |"
              " Select-Object -ExpandProperty ProcessId" % here)
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                            "-ExecutionPolicy", "Bypass", "-Command", script],
                           capture_output=True, timeout=25,
                           creationflags=CREATE_NO_WINDOW)
        out = (r.stdout or b"").decode("utf-8", "replace")
        return [int(x) for x in out.split() if x.strip().isdigit()]
    except Exception:
        return []


def foreign_tun_pids():
    """sing-box processes that hold the TUN adapter but belong to another copy.

    An elevated process hides its command line from a non-admin query, so
    `tun_pids()` cannot see a TUN started from an older folder -- yet that
    instance keeps the pcproxy adapter up, hijacks every packet and squats on
    the clash_api port, which makes the current folder look like "all nodes are
    dead".  Match on what it holds instead of on its command line.
    """
    pids = set()
    for port in (CLASH_PORT, 9090):
        try:
            for pid in P.port_pids(port):
                if P.pid_image(pid).lower().startswith("sing-box"):
                    pids.add(pid)
        except Exception:
            pass
    if adapter_present():
        # No readable command line + a live pcproxy adapter = our own TUN.
        for pid, img, cmd in _singbox_procs():
            if img.startswith("sing-box") and not (cmd or "").strip():
                pids.add(pid)
    return pids


def _singbox_procs():
    script = ("$OutputEncoding=[Text.Encoding]::UTF8;"
              "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
              "@(Get-CimInstance Win32_Process -Filter \"Name='sing-box.exe'\" |"
              " Select-Object ProcessId,Name,CommandLine) | ConvertTo-Json -Compress")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                            "-ExecutionPolicy", "Bypass", "-Command", script],
                           capture_output=True, timeout=25,
                           creationflags=CREATE_NO_WINDOW)
        data = json.loads((r.stdout or b"").decode("utf-8", "replace").strip() or "[]")
        if isinstance(data, dict):
            data = [data]
        return [(int(d.get("ProcessId")), (d.get("Name") or "").lower(),
                 d.get("CommandLine") or "") for d in data]
    except Exception:
        return []


def stop_stack():
    pids = set(tun_pids()) | set(foreign_tun_pids())
    # The Google-AI exit started for TUN is a plain sing-box on 2098; it has no
    # TUN marker, so collect it by port or it outlives the tunnel.
    try:
        for pid in P.port_pids(2098):
            if P.pid_image(pid).lower().startswith("sing-box"):
                pids.add(pid)
    except Exception:
        pass
    if alive(read_pid()):
        pids.add(read_pid())
    for pid in pids:
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                       capture_output=True, creationflags=CREATE_NO_WINDOW)
    t0 = time.time()
    while time.time() - t0 < 8 and any(P.pid_alive(x) for x in pids):
        time.sleep(0.3)
    for p in (PID, ACTIVE):
        try:
            os.remove(p)
        except OSError:
            pass
    left = set(tun_pids())
    return not left and not any(alive(x) for x in pids)


def adapter_present():
    try:
        r = subprocess.run(["netsh", "interface", "ipv4", "show", "addresses",
                            IFACE], capture_output=True, text=True,
                           errors="replace", timeout=10,
                           creationflags=CREATE_NO_WINDOW)
        return r.returncode == 0
    except Exception:
        return False


def start_admin():
    if alive(read_pid()):
        return 0, "TUN 已在运行 (pid=%d)" % read_pid()
    wintun = os.path.join(HERE, "bin", "wintun.dll")
    if not os.path.isfile(wintun):
        return 1, "缺少 bin\\wintun.dll（TUN 必需）。断开重扫后重新下载，或改用分流模式。"

    log("[1/6] wintun 驱动就绪，准备接管流量")

    # 分流模式的栈必须先让路：端口、PAC、静态代理都归零
    log("[2/6] 停止分流模式的栈（端口 / PAC / 静态代理）…")
    try:
        import stop_proxy
        stop_proxy.main()
    except SystemExit:
        pass
    except Exception as e:
        log("停止分流模式时出错（继续尝试 TUN）: %r" % (e,))

    # 分流模式停止时会把 2098 一起收掉；TUN 需要它来承载 Google AI 域名。
    log("[3/6] 挑选能过 Google 地区判定的节点（最多试 3 颗）…")
    try:
        import start_proxy as S
        if S.ensure_gai():
            log("Google AI 专用出口已就绪 (2098)，TUN 内 AI 域名走它")
    except Exception as e:
        log("Google AI 专用出口启动失败（AI 域名回退到节点组）: %r" % (e,))

    log("[4/6] 生成 TUN 配置并做 sing-box check …")
    cfg = build_config()
    with io.open(CFG, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=1)
    rc, out = check_config(CFG)
    if rc != 0:
        return 1, "sing-box check 失败: " + out[:500]

    log("[5/6] 启动 sing-box，创建 %s 虚拟网卡 …" % IFACE)
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    # sing-box 自己的 ERROR 流单独写文件：混进 tun.log 会淹没进度输出。
    logf = io.open(SB_LOG, "ab")
    try:
        p = subprocess.Popen([P.SING_EXE, "run", "-c", CFG], cwd=HERE,
                             stdout=logf, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    finally:
        logf.close()
    time.sleep(2.0)
    if p.poll() is not None:
        return 1, "sing-box 启动后立即退出 (%s)，见 logs/tun.log" % p.returncode
    with io.open(PID, "w", encoding="utf-8") as f:
        f.write(str(p.pid))
    with io.open(ACTIVE, "w", encoding="utf-8", newline="\n") as f:
        f.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    log("[6/6] 等待 %s 网卡接管流量（最长 15 秒）…" % IFACE)
    t0 = time.time()
    while time.time() - t0 < 15 and p.poll() is None and not adapter_present():
        time.sleep(0.5)
    if p.poll() is not None:
        stop_stack()
        return 1, "Wintun 适配器创建失败，sing-box 退出 (%s)" % p.returncode
    return 0, "TUN 已接管全部流量 (pid=%d, %s)" % (p.pid, IFACE)


def stop_admin():
    ok = stop_stack()
    return (0 if ok else 2), ("TUN 已停止，适配器随进程释放" if ok
                              else "仍有 sing-box 进程没退出，请看 logs/tun.log")


# ------------------------------------------------------------------ cli
def main(argv):
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    admin = "--admin" in argv
    if admin:
        # First action of the elevated child: let the waiting parent know that
        # elevation actually succeeded (see elevate()).
        try:
            with io.open(STARTED, "w", encoding="utf-8") as f:
                f.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        except OSError:
            pass
    ev = "--result" in argv
    cmd = next((a for a in argv if a in ("start", "stop", "status")), "status")
    if ev:
        i = argv.index("--result")
        globals()["RESULT"] = argv[i + 1]

    if cmd == "status":
        pid = read_pid()
        print(("TUN 运行中 pid=%d 适配器=%s" % (pid, "有" if adapter_present() else "无"))
              if alive(pid) else "TUN 未运行")
        return 0

    if cmd == "stop" and not alive(read_pid()) and not tun_pids() \
            and not foreign_tun_pids() and not adapter_present():
        for p in (PID, ACTIVE):
            try:
                os.remove(p)
            except OSError:
                pass
        print("TUN 本来就没在运行")
        return 0
    if cmd == "start" and alive(read_pid()):
        print("TUN 已在运行 (pid=%d)" % read_pid())
        return 0

    if not admin:
        # TUN start also picks a Google-AI-capable node before building the
        # tunnel, so the elevated child legitimately needs more than 90s; a
        # short wait made the parent declare failure while the child was still
        # working (and the old tunnel kept running, which looked like "TUN 用不了").
        if cmd == "start":
            log("提权后正在挑选 Google AI 节点并创建网卡，最长约 2 分钟，请不要关闭窗口 …")
        rc, msg = elevate([cmd], wait=240 if cmd == "start" else 150)
        print(("[OK] " if rc == 0 else "[失败] ") + msg)
        return rc

    rc, msg = (start_admin() if cmd == "start" else stop_admin())
    log(msg)
    write_result(rc, msg)
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))