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

# 需要用 DoH 解析的域名：Google 全线（污染最严重）+ AI 站。
# 实测吞吐从高到低（2026-11-21 12:05，2MB 上行：547 / 435 / 397 / 322 / 128 KB/s，
# 其余两颗 161 / 128 且延迟 4s）。urltest 只看延迟，会挑到 4s 那颗，
# 所以所有分组都按这张表排序，慢节点排到最后兜底。
NODE_PREFER = ["172.233.129.65", "172.235.37.168", "172.233.129.172",
               "172.233.142.149", "88.216.214.159",
               "172.104.48.194", "172.105.203.15"]

# Amazon / AWS 的下载链路（Quick 安装包、S3、CloudFront）。2026-11-22 实测：
# 同一条 aws.amazon.com 页面，grp-any 挑中的节点只有 10.8 KB/s（30s 还没下完），
# 经专用出口组是 99~129 KB/s。所以这块单独指到 grp-amazon（AWS 同源探针）。
AMAZON_DL = ["amazon.com", "amazonaws.com", "awsstatic.com", "awsstatic.net",
             "aws.dev", "a2z.com", "media-amazon.com", "ssl-images-amazon.com"]

GOOGLE_DNS = ["google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
              "gvt1.com", "ggpht.com", "youtube.com", "ytimg.com", "googlevideo.com",
              "withgoogle.com", "google.dev",
              # 这些域名和 Google 一样被污染（会解析成 Facebook 或 103.252.x 的地址），
              # 必须走 DoH；不在名单里的域名则退回系统解析 —— 见下面 final 的取舍。
              "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
              "anthropic.com", "claude.ai", "huggingface.co", "hf.co",
              "x.ai", "perplexity.ai", "antigravity.google"]
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
# 本次 build_config 的 Google 闸门摘要（供日志/维护线程读）
GATE_SUMMARY = {"ok": 0, "members": 0}
# Google 全家（不含 AI 子站，它们在 pacroute.GOOGLE_APP）。2026-11-23：Gemini 页面会同时请求
# accounts.google.com / www.google.com / gstatic 等，以前这些走 grp-any、和 gemini.google.com
# 走的 grp-google 不是同一个出口；只要其中一个出口在 Google 眼里是「不支持地区」，账号会话
# 和 Gemini 一起被判不支持。现在 Google 全家统一走 grp-google（已过地区闸门的出口）。
GOOGLE_FAMILY = ["google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
                 "gvt1.com", "gvt2.com", "gvt3.com", "ggpht.com", "googlevideo.com",
                 "youtube.com", "ytimg.com", "youtu.be", "youtube-nocookie.com",
                 "withgoogle.com", "google.dev", "goo.gl", "g.co", "google",
                 "google-analytics.com", "googletagmanager.com", "googlesyndication.com",
                 "doubleclick.net", "recaptcha.net", "googleadservices.com",
                 "gemini.google", "notebook.google", "labs.google", "antigravity.google"]
GEOIP_SRS = os.path.join(HERE, "rulesets", "geoip-cn.srs")
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

    # Google AI 的地区闸门跟 IP 走。这里不再串分流模式的 2098 单进程：
    # AI 组直接由 TUN 自己的 pinned 节点组成，urltest 负责探测和切换，
    # 少一个进程、少一个端口，也不会因为 2098 没起来就把 AI 域名全丢给兜底组。
    #
    # Never make the AI path a single outbound: a free node dies within minutes
    # and a direct rule would leave the browser spinning forever (no fallback
    # inside TUN, unlike the PAC chain).  urltest measures every member and
    # skips the ones that stop answering.
    google_bad = set()
    try:
        with io.open(os.path.join(HERE, "google_bad.json"), encoding="utf-8") as f:
            google_bad = {str(x).lower() for x in (json.load(f) or [])}
    except Exception:
        pass
    # “延迟”和“吞吐”在这批免费节点上完全不是一回事：urltest 按延迟挑中的
    # 那颗，实测 1MB 只有 33 KB/s；页面能开，大文件传不动。
    # 吞吐数据来自 rescan.py 的深测（node_deep.json 的 dl_kbps）。用文件而不是
    # 写死 IP：用户每跑一次「重新扫描节点」，这里就自动跟着换，不会失配。
    deep = {}
    try:
        with io.open(os.path.join(HERE, "node_deep.json"), encoding="utf-8") as f:
            for row in (json.load(f) or {}).get("rows") or []:
                if row.get("dl_status") == 200 and (row.get("dl_kbps") or 0) > 0:
                    deep[str(row.get("server") or "").lower()] = float(row["dl_kbps"])
    except Exception:
        deep = {}

    def _speed(o):
        return deep.get((o.get("server") or "").lower(), 0.0)

    def _rank(o):
        """升序：先按深测吞吐降序；没有深测的按静态表，最后按 tag。"""
        speed = _speed(o)
        if speed > 0:
            return (0, -speed, o.get("tag") or "")
        server = (o.get("server") or "").lower()
        try:
            return (1, NODE_PREFER.index(server), o.get("tag") or "")
        except ValueError:
            return (2, 0, o.get("tag") or "")

    # google_bad.json 只对 AI 组生效：它是“Gemini 拒绝”的历史名单，拿来
    # 过滤通用组会误杀后来变快的节点。没有深测数据时，其他组以前也吃这份
    # 名单，现在统一改为只影响 grp-google，行为由下面的探针兜底。
    candidates = [o for o in outbounds
                  if (o.get("tag") or "").startswith("g")
                  and o.get("type") not in ("urltest", "direct")]
    ranked = sorted(candidates, key=_rank)
    google_ranked = [o for o in ranked
                     if (o.get("server") or "").lower() not in google_bad]
    if not google_ranked:
        google_ranked = ranked
    # 2026-11-23：Google 地区闸门（google_gate.py）。Google 用自己的地理库判地区，
    # cloudflare 说 US 的免费节点在 Google 眼里可能是伊朗（Gemini「不支持你所在的地区」）。
    # 有「ok」结论时 grp-google 只用 ok 的节点；没有就至少排除「bad」的。
    try:
        import google_gate
        _gate = google_gate.load()
    except Exception:
        _gate = {}
    _gate_ok = [o for o in google_ranked if _gate.get(google_gate.node_key(o)) == "ok"] if _gate else []
    _gate_not_bad = [o for o in google_ranked if _gate.get(google_gate.node_key(o)) != "bad"] if _gate else google_ranked
    if len(_gate_ok) >= 3:
        google_ranked = _gate_ok
    elif _gate_ok:
        # 只有一两个 ok 时别把组缩成单点：ok 的排前面，后面补上没测出结论的（排除 bad）
        google_ranked = _gate_ok + [o for o in _gate_not_bad if o not in _gate_ok]
    elif _gate_not_bad:
        google_ranked = _gate_not_bad
    GATE_SUMMARY["ok"] = len(_gate_ok)
    GATE_SUMMARY["members"] = len(google_ranked)

    def _usable(pool):
        """深测吞吐前 4 颗，且不低于最快那颗的 1/4（低于这个没有实用价值）。"""
        have = [o for o in pool if _speed(o) > 0]
        if not have:
            return pool[:4]
        best = _speed(have[0])
        keep = [o for o in have if _speed(o) >= best * 0.25][:4]
        return keep if len(keep) >= 2 else have[:2]

    fast_all = _usable(ranked)
    google_fast = _usable(google_ranked)
    gmembers = [o.get("tag") for o in google_fast if o.get("tag")]
    for o in google_ranked:
        tag = o.get("tag")
        if tag and tag not in gmembers:
            gmembers.append(tag)
    if gmembers:
        # 探针必须用 Gemini 自己的地址：gstatic 谁都能过，但 Google 对
        # gemini.google.com 有独立的地区/IP 判定，用 gstatic 探出来的“最快”
        # 节点恰恰可能是被 Gemini 拒绝的那颗（实测 9 颗里有 2 颗是这种）。
        # 2026-11-23：grp-google 改成 selector（默认 = 自动组 grp-google-auto）。这样 Clash API
        # 可以临时把 Google 流量钉到某一个出口上（PUT /proxies/grp-google），用真实浏览器逐个
        # 验证 Gemini 是否「不支持你所在的地区」——这是唯一与用户看到的一致的判据。
        all_tags = [o.get("tag") for o in ranked if o.get("tag")]
        outbounds = outbounds + [
            {"type": "urltest", "tag": "grp-google-auto",
             "outbounds": gmembers[:10],
             "url": "https://gemini.google.com/robots.txt",
             "interval": "60s", "tolerance": 300},
            {"type": "selector", "tag": "grp-google",
             "outbounds": ["grp-google-auto"] + all_tags,
             "default": "grp-google-auto",
             "interrupt_exist_connections": True}]

    # Amazon 单独一组，探针用 aws.amazon.com/robots.txt（13KB）。gstatic 探出来的
    # “最快”节点对 AWS 可能只有 10~17 KB/s，而同一时刻另一颗有 118 KB/s
    # （2026-11-22 实测）—— 探针地址必须跟目标站同源，否则量的是两回事。
    amembers = [o.get("tag") for o in ranked if o.get("tag")]
    am_out = "grp-any"
    if amembers:
        outbounds = outbounds + [{"type": "urltest", "tag": "grp-amazon",
                                  "outbounds": amembers[:10],
                                  "url": "https://aws.amazon.com/robots.txt",
                                  "interval": "120s", "tolerance": 300}]
        am_out = "grp-amazon"

    # DoH 专用组：探测地址是 IP 字面量（https://1.1.1.1/cdn-cgi/trace），
    # urltest 探针因此永远不需要解析域名 —— 这就是「DoH 指 urltest 会死锁」的
    # 根治办法。同时它给 DNS 带来多节点故障转移，不再依赖 2098 单进程。
    dns_members = [o.get("tag") for o in ranked if o.get("tag")][:6]
    if dns_members:
        outbounds = outbounds + [{"type": "urltest", "tag": "grp-dns",
                                  "outbounds": dns_members,
                                  "url": "https://1.1.1.1/cdn-cgi/trace",
                                  "interval": "120s", "tolerance": 200}]

    # 通用分组（grp-any / grp-general / grp-fast）来自 pinned 基线，同样按
    # 吞吐表重排：不然浏览器随手一个请求就落到 4s 延迟那颗节点上。
    by_tag = {o.get("tag"): o for o in outbounds}

    # 通用分组同样只留吞吐靠前的几颗：候选里混着慢节点，它延迟一低就会把
    # 整条浏览拖死（实测 g1 延迟 4004ms 仍被 urltest 选中过）。
    # 快的排前面，其余按顺序垫后：深测数据是"某个时刻"的快照，免费节点
    # 半小时就能死一半（2026-11-22 实测：08:08 深测第一名的 g0，08:59 已经
    # 连不上）。只留 4 颗会在这种时候直接断网，所以慢节点留着当备份 ——
    # urltest 只在快节点全挂时才会轮到它们。
    fast_tags = [o.get("tag") for o in fast_all if o.get("tag")]
    prefer = fast_tags + [o.get("tag") for o in ranked
                          if o.get("tag") and o.get("tag") not in fast_tags]
    for o in outbounds:
        if o.get("type") == "urltest" and o.get("tag") not in ("grp-google", "grp-google-auto"):
            members = [t for t in prefer if t in (o.get("outbounds") or [])]
            o["outbounds"] = members or sorted(o.get("outbounds") or [])
    log_deep = {t: round(_speed(by_tag.get(t) or {}), 0) for t in fast_tags}
    print("[rank] 深测样本 %d 条，入选 %s" % (len(deep), log_deep))

    # DoH 的出口：优先能自动故障转移的 grp-dns；没有成员时才退回 direct。
    # 默认用 grp-dns（多节点故障转移）。但免费节点常见"还在组里、其实连不上
    # 1.1.1.1"的情况，urltest 会卡在坏节点上，表现是 DNS 全超时、整机断网。
    # tun_supervisor 探活失败时会写 dns_detour.txt 指定一颗实测可用的节点。
    _pinned = ""
    try:
        with io.open(os.path.join(HERE, "dns_detour.txt"), encoding="utf-8") as f:
            _pinned = f.read().strip()
    except Exception:
        _pinned = ""
    if _pinned and any(o.get("tag") == _pinned for o in outbounds):
        DNS_DETOUR = _pinned
    else:
        DNS_DETOUR = "grp-dns" if dns_members else "direct"

    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:19091"}},
        # 本机 DNS 对 Google 域名是被污染的：gemini.google.com 会解析成
        # Facebook 的 31.13.x / 2a03:2880::，浏览器拿着假 IP 连过去，TLS 必然
        # 被重置，表现就是“打不开”。TUN 自己用 DoH 取真实地址（DoH 走代理，
        # 避免 53/udp 明文被劫持），其余域名仍交给系统解析。
        "dns": {
            # detour 指 grp-dns（探针是 IP 字面量，不需要 DNS），既不会和
            # urltest 互相等待，也不会像 2098 那样是单点。
            "servers": [
                {"type": "https", "tag": "doh", "server": "1.1.1.1",
                 "detour": DNS_DETOUR},
                {"type": "https", "tag": "doh2", "server": "8.8.8.8",
                 "detour": DNS_DETOUR},
                {"type": "local", "tag": "local"},
            ],
            "rules": [
                # 国内域名交给系统解析（快、且 CDN 就近）；其余一律 DoH。
                # 只放 Google 白名单不够：chatgpt.com / huggingface.co 同样被污染
                # （解析成 Facebook 或 103.252.x 的地址），表现是证书主机名不匹配。
                {"domain_suffix": pacroute.DOMESTIC, "server": "local"},
                {"domain_suffix": GOOGLE_DNS, "server": "doh"},
            ],
            # final 用 local 而不是 doh：DoH 依赖某个节点可达 1.1.1.1，免费池里
            # 经常整组不可达。那时若 final=doh，整机 DNS 全灭；改成 local 后
            # 只有上面那批被污染的域名解析不了，其余照常上网（2026-11-23 实测：
            # DoH 出口挂掉时 GitHub/B站全部打不开，根因就在这一个默认值）。
            "final": "local",
            "strategy": "prefer_ipv4",
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "interface_name": IFACE,
            # 只给 IPv4 的话，双栈网络下 Windows 的 v6 流量与 v6 DNS 会绕过
            # pcproxy 直接出网（真实 IP 泄漏，且部分双栈站点走被污染的 v6 DNS）。
            "address": [TUN_ADDR, "fdfe:dcba:9876::1/126"],
            "mtu": 1400,
            "auto_route": True,
            "strict_route": True,
            # gvisor 是用户态 TCP，上传/大响应会被它的窗口和拷贝拖住
            # （实测同一颗节点：直连 547 KB/s，经 gvisor 只有 236 KB/s）。
            # system 走内核 TCP，吞吐接近直连；回滚只需改回 gvisor。
            "stack": "system",
        }],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": True,
            # sing-box 1.14 起必须显式给出域名解析器；节点服务器多数是 IP，
            # 少数（CDN 域名）用系统解析即可。
            "default_domain_resolver": "local",
            # 直连优先：用中国 IP 段做兜底判断。域名列表只能覆盖已知站点，
            # 大量国内 CDN/下载器用的是陌生域名或纯 IP，只有按目标 IP 判定才
            # 能做到「能直连的一律直连，只有真出国的才走节点」。
            "rule_set": ([{"type": "local", "tag": "geoip-cn", "format": "binary",
                           "path": GEOIP_SRS}] if os.path.isfile(GEOIP_SRS) else []),
            "final": "grp-any",
            "rules": [
                # 2026-11-23：这里曾有 process_name: sing-box.exe/xray.exe -> direct。stack=system 时 Windows 上
                # 所有 TUN 连接都归属 sing-box.exe 自己，这条规则等于全局直连（17:34-18:02、18:13-18:18 两次外网全断）。
                # 测速/闸门/预筛进程改为自己绕开 TUN（nodes.bypass_route，守护自检通过才用），这里绝不能再加进程规则。
                # 先嗅探域名：后面的 domain_suffix 才能命中 TLS/HTTP 目标
                {"action": "sniff", "inbound": ["tun-in"],
                 "sniffer": ["http", "tls", "quic"], "timeout": "500ms"},
                # 隐私与国内直连：与分流模式完全一致的优先级
                # Steam / 壁纸引擎要外区商店与创意工坊，必须在直连判定之前
                # 显式拦下来走代理（steamcontent 等下载 CDN 已在 DIRECT 里，
                # 命中上一条，不受影响）。
                {"domain_suffix": pacroute.STEAM, "outbound": "grp-any"},
                {"domain_suffix": pacroute.DOMESTIC, "outbound": "direct"},
                {"domain_suffix": pacroute.SENSITIVE, "outbound": "direct"},
                {"ip_is_private": True, "outbound": "direct"},
                # DNS 交给上面的 doh 解析器（见 dns 段），UDP/QUIC 仍直连
                {"protocol": "dns", "action": "hijack-dns"},
                # QUIC(UDP/443) 直连在国内是黑洞：浏览器先发 QUIC、等超时才回落
                # TCP，页面就"一直转圈"。直接拒绝，让它立刻走 TCP。
                {"network": "udp", "port": 443, "action": "reject"},
                {"network": "udp", "outbound": "direct"},
                # 被墙站点的明文 HTTP（Google 的 http:// 跳转、连通性检查等）直连必然超时
                # （2026-11-23 日志：142.251.x:80 走 direct 全部 i/o timeout），交给代理；
                # 其余明文 HTTP 仍按下一条直连，不经过免费节点。
                {"domain_suffix": GOOGLE_FAMILY, "port": 80,
                 "outbound": "grp-google" if gmembers else "grp-any"},
                {"domain_suffix": GOOGLE_DNS, "port": 80, "outbound": "grp-any"},
                # 明文 HTTP 不经免费节点（与分流模式一致）
                {"port": 80, "outbound": "direct"},
                {"domain_suffix": pacroute.DIRECT, "outbound": "direct"},
                {"domain_suffix": pacroute.STEAM_DIRECT, "outbound": "direct"},
                # AI 站必须走合格出口；其余默认走合并组
                {"domain_suffix": pacroute.GOOGLE_APP,
                 "outbound": "grp-google" if gmembers else "grp-general"},
                # Google 全家与 AI 子站同一个出口（见 GOOGLE_FAMILY 注释）
                {"domain_suffix": GOOGLE_FAMILY,
                 "outbound": "grp-google" if gmembers else "grp-any"},
                # Amazon 系下载走同源探针的 Amazon 组；没有成员时退回合并组。
                {"domain_suffix": AMAZON_DL, "outbound": am_out},
                {"domain_suffix": pacroute.GENERAL, "outbound": "grp-general"},
                # 目标 IP 在中国境内 -> 直连。放在最后，前面显式规则优先。
                *([{"rule_set": "geoip-cn", "outbound": "direct"}]
                  if os.path.isfile(GEOIP_SRS) else []),
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
    if not cmd.strip():
        # An elevated process hides its command line from a non-admin query.
        # Without this fallback the waiting parent concluded "TUN 没在跑" while
        # the elevated child (which can read the line) concluded "已在跑" and
        # returned without writing a result -- the parent then waited forever.
        try:
            return pid in P.port_pids(CLASH_PORT)
        except Exception:
            return False
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
    # A split-mode Google-AI exit on 2098 has no TUN marker; collect it by port
    # so it cannot outlive the tunnel when both modes were started in a row.
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
    # 2026-11-23：先生成并校验新配置，校验通过才动正在跑的隧道。
    # 以前是先停旧隧道（[0/6]、[2/5]）再生成配置，新配置一旦过不了 sing-box check，
    # 用户就从「能上网」直接变成「断网」。现在校验失败时旧隧道原样保留。
    try:
        pre = build_config()
        pre_path = CFG + ".precheck"
        with io.open(pre_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(pre, f, ensure_ascii=False, indent=1)
        rc0, out0 = check_config(pre_path)
        try:
            os.remove(pre_path)
        except OSError:
            pass
        if rc0 != 0:
            log("新配置没通过 sing-box check，保留当前隧道不动: " + out0[:300])
            return 1, "新配置没通过 sing-box check（当前网络未改动）: " + out0[:300]
    except SystemExit as e:
        return 1, "生成配置失败（当前网络未改动）: %s" % e
    except Exception as e:
        log("预检新配置时出错（继续按原流程）: %r" % (e,))

    if alive(read_pid()):
        # 启动按钮的语义是"按当前配置生效"，不是"已经在跑就算了"：旧隧道可能
        # 还挂在死节点上（AI 出口就是这样失效的），所以先拆再建。
        log("[0/6] 检测到已有 TUN 在运行 (pid=%d)，按新配置重建 …" % read_pid())
        try:
            stop_stack()
        except Exception as e:
            log("停止旧 TUN 失败: %r" % (e,))
    wintun = os.path.join(HERE, "bin", "wintun.dll")
    if not os.path.isfile(wintun):
        return 1, "缺少 bin\\wintun.dll（TUN 必需）。断开重扫后重新下载，或改用分流模式。"

    log("[1/6] wintun 驱动就绪，准备接管流量")

    # 分流模式的栈必须先让路：端口、PAC、静态代理都归零
    log("[2/5] 停止分流模式的栈（端口 / PAC / 静态代理）…")
    try:
        import stop_proxy
        stop_proxy.main()
    except SystemExit:
        pass
    except Exception as e:
        log("停止分流模式时出错（继续尝试 TUN）: %r" % (e,))

    # AI 出口现在直接内建在 TUN 配置里（pinned 节点 + urltest），不再启动 2098。
    log("[3/5] 生成 TUN 配置并做 sing-box check …")
    cfg = build_config()
    with io.open(CFG, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=1)
    rc, out = check_config(CFG)
    if rc != 0:
        return 1, "sing-box check 失败: " + out[:500]

    log("[4/5] 启动 sing-box，创建 %s 虚拟网卡 …" % IFACE)
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    # sing-box 自己的 ERROR 流单独写文件：混进 tun.log 会淹没进度输出。
    logf = io.open(SB_LOG, "ab")
    try:
        # 注意：不要加 CREATE_BREAKAWAY_FROM_JOB。这份作业不允许 breakaway，
        # 加上后 Popen 直接抛 OSError，隧道根本建不起来（12:30 那次实测）。
        # DETACHED_PROCESS 必不可少：CREATE_NO_WINDOW 仍挂在这个控制台上，
        # 一旦启动它的窗口关闭（用户点了叉、或父进程是脚本），sing-box 会被
        # 一起收走，网卡随之消失 —— 表现为"刚配好就断网"。
        p = subprocess.Popen([P.SING_EXE, "run", "-c", CFG], cwd=HERE,
                             stdout=logf, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL,
                             creationflags=(0x00000008 | 0x00000200))
    finally:
        logf.close()
    time.sleep(2.0)
    if p.poll() is not None:
        return 1, "sing-box 启动后立即退出 (%s)，见 logs/tun.log" % p.returncode
    with io.open(PID, "w", encoding="utf-8") as f:
        f.write(str(p.pid))
    with io.open(ACTIVE, "w", encoding="utf-8", newline="\n") as f:
        f.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    start_supervisor()
    register_guard_task()

    log("[5/5] 等待 %s 网卡接管流量（最长 15 秒）…" % IFACE)
    t0 = time.time()
    while time.time() - t0 < 15 and p.poll() is None and not adapter_present():
        time.sleep(0.5)
    if p.poll() is not None:
        stop_stack()
        return 1, "Wintun 适配器创建失败，sing-box 退出 (%s)" % p.returncode
    return 0, "TUN 已接管全部流量 (pid=%d, %s)" % (p.pid, IFACE)


SUP_PID = os.path.join(HERE, "tun_supervisor.pid")
SUP_LOG = os.path.join(HERE, "logs", "tun_supervisor.log")


def start_supervisor():
    """拉起自愈守护：它监控 tun.pid，隧道进程消失时用同一份配置重建。

    必须在成功建立网卡之后启动，且它自己也是 DETACHED —— 否则用户关掉启动
    窗口，守护跟着一起死，等于没有。
    """
    try:
        if os.path.isfile(SUP_PID):
            old = 0
            try:
                with io.open(SUP_PID, encoding="utf-8") as f:
                    old = int(f.read().strip() or 0)
            except Exception:
                old = 0
            if old and P.pid_alive(old):
                return
        os.makedirs(os.path.dirname(SUP_LOG), exist_ok=True)
        logf = io.open(SUP_LOG, "ab")
        try:
            subprocess.Popen([sys.executable, os.path.join(HERE, "tun_supervisor.py")],
                             cwd=HERE, stdout=logf, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL,
                             creationflags=(0x00000008 | 0x00000200))
        finally:
            logf.close()
    except Exception as exc:
        log("启动看门狗失败（不影响本次隧道）: %s" % exc)


GUARD_TASK = "PhoneProxyTunGuard"


def register_guard_task():
    """注册一个每分钟跑一次的提权计划任务（比长驻进程更抗清理）。"""
    try:
        # 必须用 pythonw：计划任务每分钟跑一次，python.exe 是控制台程序，
        # 每次执行都会闪一个黑框。
        py = sys.executable
        cand = os.path.join(os.path.dirname(py), "pythonw.exe")
        if os.path.isfile(cand):
            py = cand
        elif not py.lower().endswith("pythonw.exe"):
            guess = os.path.join(HERE, "..", "runtime", "python", "pythonw.exe")
            if os.path.isfile(guess):
                py = guess
        py = os.path.abspath(py)
        script = os.path.join(HERE, "tun_supervisor.py")
        cmd = '"%s" "%s" --once' % (py, script)
        r = subprocess.run(["schtasks", "/Create", "/TN", GUARD_TASK, "/TR", cmd,
                            "/SC", "MINUTE", "/MO", "1", "/RL", "HIGHEST", "/F"],
                           capture_output=True, text=True, errors="replace",
                           creationflags=0x08000000)
        # 失败不影响本次隧道（还有常驻 supervisor），但要留痕，别假装成功。
        if r.returncode != 0:
            log("注册自愈计划任务失败（rc=%s）：%s" % (r.returncode, (r.stderr or r.stdout).strip()[:160]))
    except Exception as exc:
        log("注册自愈计划任务失败: %s" % exc)


def unregister_guard_task():
    try:
        subprocess.run(["schtasks", "/Delete", "/TN", GUARD_TASK, "/F"],
                       capture_output=True, creationflags=0x08000000)
    except Exception:
        pass


def stop_supervisor():
    """停掉守护进程：先杀进程再删 pid，否则它可能把刚停的隧道又拉起来。"""
    try:
        sp = 0
        if os.path.isfile(SUP_PID):
            with io.open(SUP_PID, encoding="utf-8") as f:
                sp = int(f.read().strip() or 0)
        if sp and P.pid_alive(sp) and "tun_supervisor" in P.pid_cmdline(sp).lower():
            subprocess.run(["taskkill", "/PID", str(sp), "/T", "/F"],
                           capture_output=True, creationflags=0x08000000)
        if os.path.isfile(SUP_PID):
            os.remove(SUP_PID)
    except Exception:
        pass


def stop_admin():
    stop_supervisor()
    unregister_guard_task()
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
    cmd = next((a for a in argv if a in ("start", "stop", "status", "guard")), "status")
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
        if admin:
            # The waiting parent only learns the outcome through this file.
            write_result(0, "TUN 本来就没在运行")
        return 0

    if not admin:
        # Starting TUN stops the split-mode stack, builds the config and waits
        # for the adapter; a short wait made the parent declare failure while
        # the child was still working (the old tunnel kept running, which
        # looked like "TUN 用不了").
        if cmd == "start":
            log("提权后正在生成配置并创建网卡，最长约 2 分钟，请不要关闭窗口 …")
        rc, msg = elevate([cmd], wait=240 if cmd == "start" else 150)
        print(("[OK] " if rc == 0 else "[失败] ") + msg)
        return rc

    if cmd == "guard":
        # 只重写自愈计划任务（改解释器/周期时用），不动正在跑的隧道。
        register_guard_task()
        msg = "自愈计划任务已更新"
        log(msg)
        write_result(0, msg)
        print(msg)
        return 0

    rc, msg = (start_admin() if cmd == "start" else stop_admin())
    log(msg)
    write_result(rc, msg)
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))