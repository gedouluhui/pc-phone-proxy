"""Turn the deep-test winners into one self-healing sing-box exit pair.

  general -> 127.0.0.1:2101 (http) / 2100 (socks)   must pass the ChatGPT gate
  fast    -> 127.0.0.1:2103 (http) / 2102 (socks)   bulk download
  cli     -> 127.0.0.1:2090 (mixed)                 Codex/pip/git: routes by hostname

Each port is backed by a `urltest` group over the top throughput-tested nodes,
with Geph as the last member, so a node dying does not break the port: sing-box
re-probes every member and switches within one interval.

Usage:
  python bestroute.py            # dry: show who would be picked
  python bestroute.py --apply    # start the pinned process and install PAC
"""
import argparse
import json
import os
import socket
import subprocess
import time

import diagnostics as D
import nodes as N
import pacroute
import proxyctl as P

HERE = os.path.dirname(os.path.abspath(__file__))
DEEP = os.path.join(HERE, "node_deep.json")
PINNED = os.path.join(HERE, "pinned.json")
PIN_PIDS = os.path.join(HERE, "pinned_pids.json")
CFG = os.path.join(HERE, "singbox_pinned.json")
GENERAL_HTTP, GENERAL_SOCKS = 2101, 2100
FAST_HTTP, FAST_SOCKS = 2103, 2102
CLI_MIXED = 2090
# 必须 HTTPS：route 里 {"port": 80, "outbound": "direct"} 会把 http 探测强制直连，
# urltest 等于在测本地网络，于是所有节点都被判"通"，选出来的可能是完全不能用的节点。
HEALTH_URL = "https://www.gstatic.com/generate_204"
HEALTH = os.path.join(HERE, "pinned_health.json")

_health_bad = None


def health_bad():
    """server:port pairs whose newest probe measured no throughput.

    node_deep.json is a snapshot from one measurement pass; pinned_health.json
    re-probes the *current* group members.  When the health file is newer, a
    member that just failed (dl<=50) must not be re-picked from the stale deep
    rows -- otherwise every re-apply resurrects the same dead exits.
    """
    global _health_bad
    if _health_bad is not None:
        return _health_bad
    _health_bad = set()
    try:
        if os.path.getmtime(HEALTH) >= os.path.getmtime(DEEP):
            d = json.load(open(HEALTH, encoding="utf-8"))
            for r in d.get("rows", []):
                if (r.get("dl_kbps") or 0) <= 50:
                    _health_bad.add((str(r.get("server", "")).lower(),
                                     str(r.get("port"))))
    except Exception:
        pass
    return _health_bad


def log(*a):
    print(*a, flush=True)


def lok(port):
    s = socket.socket()
    s.settimeout(0.4)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def stop_pinned():
    # Ownership-checked (image + command line points at singbox_pinned.json)
    # in proxyctl; a same-named sing-box started by the user is left alone.
    P.stop_pinned()


def score(r):
    dl = r.get("dl_kbps") or 0
    ul = r.get("ul_kbps") or 0
    ttfb = r.get("cg_ttfb_ms") or 3000
    return dl + 1.5 * ul - max(0, ttfb - 400) / 20.0


def _prefix(server):
    """Coarse provider fingerprint: /24 for IPs, last two labels for domains.

    Seven nodes on 202.50.253.x are one SS panel, not seven independent exits;
    a group full of them goes down together.  Cap each prefix so the group
    keeps real diversity.
    """
    s = str(server).lower()
    if s.count(".") == 3 and all(p.isdigit() for p in s.split(".")):
        return ".".join(s.split(".")[:3])
    parts = s.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else s


def pick(rows, need_cg, min_dl, min_ul, k, max_per_prefix=2):
    bad = health_bad()
    cand = [r for r in rows
            if (r.get("dl_kbps") or 0) >= min_dl and (r.get("ul_kbps") or 0) >= min_ul
            and r.get("github_ok")
            and (str(r.get("server", "")).lower(), str(r.get("port"))) not in bad]
    if need_cg:
        cand = [r for r in cand if r.get("chatgpt_ok")]
    cand.sort(key=lambda r: -score(r))
    out, seen, pref = [], set(), {}
    for r in cand:
        key = r["server"].lower()
        if key in seen:
            continue
        p = _prefix(r["server"])
        if pref.get(p, 0) >= max_per_prefix:
            continue
        seen.add(key)
        pref[p] = pref.get(p, 0) + 1
        out.append(r)
        if len(out) >= k:
            break
    return out


def pinned_fallback_rows():
    """Reuse the last applied URIs when the deep pool has too few survivors.

    node_deep.json is a one-shot measurement; when nearly every free node died
    it can end up with 1-2 rows and rebuild refuses to apply, leaving a dead
    machine.  The previously pinned nodes are a legitimate second candidate
    set -- urltest health-checks them anyway, and a dead one is just skipped.
    """
    try:
        p = json.load(open(PINNED, encoding="utf-8"))
    except Exception:
        return []
    out = []
    for uri in (p.get("members") or {}):
        ob, _ = N.parse_uri(uri)
        if not ob:
            continue
        out.append({"server": ob.get("server"), "port": ob.get("server_port"),
                    "proto": ob.get("type") or "?", "uri": uri,
                    "dl_kbps": 400, "ul_kbps": 120, "github_ok": True,
                    "chatgpt_ok": True, "loc": "旧", "cg_ttfb_ms": 1500})
    return out


def build_config(gen, fast):
    outbounds, used = [], {}
    parse_fail = []

    def node_tag(r, prefix):
        uri = r["uri"]
        if uri in used:
            return used[uri]
        ob, meta = N.parse_uri(uri)
        if not ob:
            # A truncated/unknown URI used to disappear silently (review C7).
            parse_fail.append((prefix, uri[:100]))
            return None
        tag = f"{prefix}{len([t for t in used.values() if t.startswith(prefix)])}"
        ob["tag"] = tag
        outbounds.append(ob)
        used[uri] = tag
        return tag

    gtags = [t for t in (node_tag(r, "g") for r in gen) if t]
    ftags = [t for t in (node_tag(r, "f") for r in fast) if t]
    # 迷雾通做最后的兜底成员（ChatGPT 能过，但慢）；便携版机器可能没装迷雾通
    if lok(9910):
        geph = {"type": "http", "tag": "geph", "server": "127.0.0.1", "server_port": 9910}
        outbounds.append(geph)
        gtags = gtags + ["geph"]
        ftags = ftags + ["geph"]
    # 合并组成员去重（同一节点可能同时进 general/fast 两组，重复 tag 会让 sing-box 校验失败）
    anytags = list(dict.fromkeys(gtags + ftags))
    cfg = {
        "log": {"level": "error"},
        # 注意：不要在这里加 dns 段。本机 sing-box 是 1.12+，
        # {"address": "..."} 的旧格式会在 config check 阶段直接 FATAL
        # （legacy DNS server formats removed），整个出口组起不来、回退到 2086，
        # ChatGPT/Claude 就会全挂。要加必须用 1.12 的新格式：
        # {"type": "udp", "server": "223.5.5.5"} / {"type": "https", "server": "1.1.1.1"}。
        "experimental": {
            # read-only local API: lets 启动/看门狗 read which member urltest is
            # using right now, plus its live delay history.
            "clash_api": {"external_controller": "127.0.0.1:19090"}
        },
        "inbounds": [
            {"type": "http", "tag": "in-h-g", "listen": "127.0.0.1", "listen_port": GENERAL_HTTP},
            {"type": "socks", "tag": "in-s-g", "listen": "127.0.0.1", "listen_port": GENERAL_SOCKS},
            {"type": "http", "tag": "in-h-f", "listen": "127.0.0.1", "listen_port": FAST_HTTP},
            {"type": "socks", "tag": "in-s-f", "listen": "127.0.0.1", "listen_port": FAST_SOCKS},
            {"type": "mixed", "tag": "in-cli", "listen": "127.0.0.1", "listen_port": CLI_MIXED},
        ],
        # tolerance 必须大于节点间正常的延迟抖动：免费节点延迟常在 300~1500ms
    # 之间抖动，150ms 的容差会让 urltest 每分钟都换节点，换的瞬间正在进行的
    # 下载/TLS 连接全部断掉（用户看到的就是「用着用着网断了」）。400ms 仍然
    # 能在一颗节点明显变慢时切走，但不会因为抖动来回横跳。
    "outbounds": ([{"type": "urltest", "tag": "grp-general", "outbounds": gtags,
                        "url": HEALTH_URL, "interval": "60s", "tolerance": 400},
                       {"type": "urltest", "tag": "grp-fast", "outbounds": ftags,
                        "url": HEALTH_URL, "interval": "60s", "tolerance": 400},
                       # 2026-11-11 WorkBuddy privacy: 合并组兜底——当某一组挑到坏节点时，
                       # 命令行/快速门仍能挑到两组里当前可用的最快成员（避免整路超时）。
                       {"type": "urltest", "tag": "grp-any", "outbounds": anytags,
                        "url": HEALTH_URL, "interval": "60s", "tolerance": 400}]
                      + outbounds + [{"type": "direct", "tag": "direct"}]),
        "route": {"rules": [
            # 2026-11-11 WorkBuddy hotfix: 国内域名在所有门强制直连（含米哈游全家桶）。
            # PAC 只管浏览器；游戏/CLI 走 env 或缓存 PAC 时会把登录请求送进 2103/2090，
            # 海外节点到不了国服登录接口（实测 000）。此规则在任何 inbound 判定前生效。
            {"domain_suffix": pacroute.DOMESTIC, "outbound": "direct"},
            # 2026-11-11 WorkBuddy privacy: 敏感域（银行/支付/政务/教育）永不经免费节点。
            {"domain_suffix": pacroute.SENSITIVE, "outbound": "direct"},
            # 明文 HTTP(80) 与 DNS(53) 不经节点：HTTP 内容对节点明文可见，DNS 可被节点篡改。
            {"port": 80, "outbound": "direct"},
            {"port": 53, "outbound": "direct"},
            # UDP(QUIC/WebRTC) 经代理会被节点看到且绕过 TLS 保护 => 拒绝；浏览器自动回落 TCP。
            {"network": "udp", "action": "reject"},
            {"inbound": ["in-h-g", "in-s-g"], "outbound": "grp-general"},
            {"inbound": ["in-h-f", "in-s-f"], "outbound": "grp-any"},
            {"inbound": ["in-cli"], "domain_suffix": [
                "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
                "anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com"],
             "outbound": "grp-general"},
            {"inbound": ["in-cli"], "domain_suffix": ["kaggle.com", "kaggleusercontent.com"],
             "outbound": "direct"},
            # 国内站点直连，别为了 git/pip/Codex 把国内流量也绕出去
            {"inbound": ["in-cli"], "domain_suffix": pacroute.DOMESTIC,
             "outbound": "direct"},
            {"inbound": ["in-cli"], "ip_is_private": True, "outbound": "direct"},
            {"inbound": ["in-cli"], "outbound": "grp-any"},
        ]},
    }
    if parse_fail:
        print("[bestroute] WARNING: %d node URI(s) could not be parsed and were dropped:"
              % len(parse_fail))
        for pfx, u in parse_fail[:10]:
            # 只打码后的 URI：原文前 60 字符就含 uuid/password，日志会被看门狗收走
            print("  %s %s" % (pfx, N.redact_uri(u)))
    return cfg, gtags, ftags, used


def start(cfg):
    with open(CFG, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f)
    r = subprocess.run([P.SING_EXE, "check", "-c", CFG], capture_output=True, text=True,
                       creationflags=0x08000000)
    if r.returncode != 0:
        log("config check failed: " + ((r.stderr or r.stdout or "").strip()[-400:]))
        return None
    logp = os.path.join(HERE, "logs", "singbox_pinned.log")
    with open(logp, "ab") as logf:
        p = subprocess.Popen([P.SING_EXE, "run", "-c", CFG], stdout=logf,
                             stderr=subprocess.STDOUT, creationflags=0x08000000)
    for _ in range(40):
        if lok(GENERAL_HTTP) and lok(FAST_HTTP) and lok(CLI_MIXED):
            owners = set()
            for port in (GENERAL_HTTP, FAST_HTTP, CLI_MIXED):
                owners.update(P.port_pids(port))
            if owners and p.pid not in owners:
                # A foreign listener already owns the ports: do not pretend our
                # new process is serving them (review C9).
                log("ports are held by pid(s) %s, not the process we just started (%d)"
                    % (sorted(owners), p.pid))
                try:
                    p.terminate()
                except Exception:
                    pass
                return None
            return p
        if p.poll() is not None:
            log(f"sing-box exited rc={p.returncode}; see logs/singbox_pinned.log")
            return None
        time.sleep(0.25)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--min-dl", type=float, default=300)
    ap.add_argument("--min-ul", type=float, default=80)
    ap.add_argument("--top", type=int, default=10)
    args = ap.parse_args()

    rows = json.load(open(DEEP, encoding="utf-8"))["rows"]
    fallback = pinned_fallback_rows()
    seen = {(str(r.get("server", "")).lower(), str(r.get("port"))) for r in rows}
    fallback = [r for r in fallback
                if (str(r.get("server", "")).lower(), str(r.get("port"))) not in seen]
    if fallback:
        log(f"deep pool thin; %d previously pinned URI(s) join the candidates"
            % len(fallback))
    pool = rows + fallback
    gen = pick(pool, True, args.min_dl, args.min_ul, args.top)
    if not gen:
        log("no ChatGPT-capable node above thresholds; lowering to 80/20")
        gen = pick(pool, True, 80, 20, args.top)
    fast = pick(pool, False, max(args.min_dl, 600), args.min_ul, args.top)
    if len(fast) < 3:
        # A one-member group is the most fragile part of the stack: when that
        # single node blips, 2103 dies outright and the browser/CLI lose the
        # internet until the keeper notices.  urltest health-checks every
        # member and simply skips the dead ones, so widening the list is free.
        for r in pick(pool, False, args.min_dl, args.min_ul, args.top):
            if all(r["uri"] != f["uri"] for f in fast):
                fast.append(r)
            if len(fast) >= 3:
                break
    log(f"deep rows {len(rows)} (+{len(fallback)} pinned), "
        f"chatgpt-ok {sum(1 for r in rows if r.get('chatgpt_ok'))}")
    log("\n== general group (ChatGPT) ==")
    for r in gen:
        log(f"  {r.get('loc','??'):2s} {r['proto']:6s} {r['server']}:{r['port']} "
            f"dl={r.get('dl_kbps')} ul={r.get('ul_kbps')} ttfb={r.get('cg_ttfb_ms')}ms")
    log("\n== fast group (bulk) ==")
    for r in fast:
        log(f"  {r.get('loc','??'):2s} {r['proto']:6s} {r['server']}:{r['port']} "
            f"dl={r.get('dl_kbps')} ul={r.get('ul_kbps')} ttfb={r.get('cg_ttfb_ms')}ms")
    if not gen or not fast:
        log("not enough winners; nothing applied")
        return 1
    if not args.apply:
        return 0

    cfg, gtags, ftags, used = build_config(gen, fast)
    log(f"\ngroups: general={gtags} fast={ftags}")
    stop_pinned()
    # A previous process can hold the ports without a usable pid file (stale
    # pid after a crash, or an instance started by an older build).  Free them
    # by PID (image-checked) before binding, otherwise the new process dies and
    # the gates silently test the old one.
    P.wait_port_free([GENERAL_HTTP, GENERAL_SOCKS, FAST_HTTP, FAST_SOCKS, CLI_MIXED],
                     timeout=6.0, expect_cmd="singbox_pinned.json", log=log)
    proc = start(cfg)
    if not proc:
        return 1
    log(f"pinned sing-box pid={proc.pid}")

    # ---- fresh, independent gate on the actual pinned ports ----
    gates = []
    for name, ep in (("general", f"127.0.0.1:{GENERAL_HTTP}"),
                     ("fast", f"127.0.0.1:{FAST_HTTP}"),
                     ("cli", f"127.0.0.1:{CLI_MIXED}")):
        g = P.gate_one(ep)
        g["role"] = name
        gates.append(g)
        log(f"  gate {name:7s} {ep} " + "  ".join(f"{k}:{v['verdict']}" for k, v in g["sites"].items()))
    gg = [g for g in gates if g["role"] == "general"][0]
    gf = [g for g in gates if g["role"] == "fast"][0]
    if not gg["general"]:
        # 2026-11-10 hotfix2: stop_pinned() 在本函数开头已经把旧栈拆掉了，
        # 所以"拒绝应用"根本保不住旧代理，实际效果 = 整机断网（自举失败）。
        # 先给候选栈一次重试机会，仍失败也保留它：urltest 每 60s 重探，
        # geph 兜底成员还在组里，比杀掉唯一活着的进程严格更优。
        time.sleep(4)
        gg = P.gate_one(f"127.0.0.1:{GENERAL_HTTP}")
        gg["role"] = "general"
        gates[0] = gg
        log("  gate general retry " +
            "  ".join(f"{k}:{v['verdict']}" for k, v in gg["sites"].items()))
    if not gg["general"]:
        log("general port failed the ChatGPT gate after retry; "
            "KEEPING the new process and applying PAC in degraded mode")
    fast_degraded = False
    if not gf["fast"]:
        # 2026-11-10 WorkBuddy hotfix: fast 节点没过站点检测时，之前是直接拒绝应用
        # （previous PAC kept）——但旧栈此时已被拆掉，结果 = 整机无代理。
        # 现改为降级：fast 角色改走已通过检测的 general 门，保住在线状态。
        log("fast port failed the site gate; DEGRADING fast role to general gate (still applying)")
        fast_degraded = True

    with open(PIN_PIDS, "w", encoding="utf-8", newline="\n") as fp:
        # Record what the PID must look like; a recycled PID must not be killed.
        json.dump([{"pid": proc.pid, "exe": "sing-box.exe",
                    "cmd": "singbox_pinned.json"}], fp)
    general_ep = f"127.0.0.1:{GENERAL_HTTP}"
    fast_ep = f"127.0.0.1:{GENERAL_HTTP}" if fast_degraded else f"127.0.0.1:{FAST_HTTP}"
    pac_info = pacroute.apply_pac(general_ep, fast_ep)
    if not pac_info.get("ok"):
        log("PAC failed: " + str(pac_info.get("err")))
        return 1
    vg = P.verify_applied(general_ep)
    vf = P.verify_applied(fast_ep)
    ver = {"ok": bool(vg["ok"] and vf["ok"]), "ttfb_ms": vg.get("ttfb_ms"),
           "speed_kbps": vg.get("speed_kbps"), "plain_http": vg.get("plain_http"),
           "err": vg.get("err", ""),
           "fast": {"endpoint": fast_ep, "ttfb_ms": vf.get("ttfb_ms"),
                    "speed_kbps": vf.get("speed_kbps"), "ok": vf.get("ok")}}
    rows_out = []
    for r in rows:
        safe = D.row(r)
        rows_out.append(dict(safe, id=r["tag"],
                             label=f"{r.get('loc','??')} {r['proto']} {r['server']}:{r['port']}",
                             kind="node", ttfb_ms=r.get("cg_ttfb_ms"),
                             speed_kbps=r.get("dl_kbps"),
                             ok_both=bool(r.get("chatgpt_ok") and (r.get("dl_kbps") or 0) > 0),
                             score=round(score(r), 1),
                             err=(r.get("chatgpt_verdict") or "") if not r.get("chatgpt_ok") else ""))
    best_row = dict(D.row(gen[0]), id="pinned-general", kind="local",
                    label=f"固定出口组 general（首选 {gen[0]['server']}:{gen[0]['port']} {gen[0].get('loc','')}）",
                    ttfb_ms=gen[0].get("cg_ttfb_ms"), speed_kbps=gen[0].get("dl_kbps"),
                    ok_both=True, score=round(score(gen[0]), 1))
    act_old = {}
    try:
        act_old = json.load(open(P.ACTIVE, encoding="utf-8"))
    except Exception:
        pass
    with open(P.ACTIVE, "w", encoding="utf-8", newline="\n") as fp:
        json.dump(D.state({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "chosen": best_row, "rows": rows_out[:150], "applied": "PAC " + pac_info["url"],
                   "dead_summary": {}, "previous": act_old.get("previous", {}),
                   "baseline": act_old.get("baseline", {}),
                   "endpoint": general_ep, "verify": ver, "mode": "pac",
                   "pac": pac_info, "general": general_ep, "fast": fast_ep,
                   "gates": gates, "pinned": True,
                   "groups": {"general": gtags, "fast": ftags},
                   "cli": f"127.0.0.1:{CLI_MIXED}"}),
                  fp, indent=1, ensure_ascii=False)
    with open(PINNED, "w", encoding="utf-8", newline="\n") as fp:
        json.dump({"general": general_ep, "fast": fast_ep, "cli": f"127.0.0.1:{CLI_MIXED}",
                   "groups": {"general": gtags, "fast": ftags},
                   "members": used},
                  fp, indent=1)
    p = P.render_report()
    log(f"\n[OK] general={general_ep} fast={fast_ep} cli={CLI_MIXED}")
    log(f"     verify ok={ver['ok']} ttfb={ver.get('ttfb_ms')}ms speed={ver.get('speed_kbps')}kB/s")
    log(f"     report {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
