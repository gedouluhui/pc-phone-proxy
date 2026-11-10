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
HEALTH_URL = "http://www.gstatic.com/generate_204"
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
    try:
        pids = json.load(open(PIN_PIDS))
    except Exception:
        pids = []
    for pid in pids:
        if P.pid_alive(int(pid)):
            subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                           capture_output=True, creationflags=0x08000000)
    try:
        os.remove(PIN_PIDS)
    except OSError:
        pass


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


def build_config(gen, fast):
    outbounds, used = [], {}

    def node_tag(r, prefix):
        uri = r["uri"]
        if uri in used:
            return used[uri]
        ob, meta = N.parse_uri(uri)
        if not ob:
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
    cfg = {
        "log": {"level": "error"},
        "experimental": {
            # read-only local API: lets 启动/看门狗 read which member urltest is
            # using right now, plus its live delay history.
            "clash_api": {"external_controller": "127.0.0.1:9090"}
        },
        "inbounds": [
            {"type": "http", "tag": "in-h-g", "listen": "127.0.0.1", "listen_port": GENERAL_HTTP},
            {"type": "socks", "tag": "in-s-g", "listen": "127.0.0.1", "listen_port": GENERAL_SOCKS},
            {"type": "http", "tag": "in-h-f", "listen": "127.0.0.1", "listen_port": FAST_HTTP},
            {"type": "socks", "tag": "in-s-f", "listen": "127.0.0.1", "listen_port": FAST_SOCKS},
            {"type": "mixed", "tag": "in-cli", "listen": "127.0.0.1", "listen_port": CLI_MIXED},
        ],
        "outbounds": ([{"type": "urltest", "tag": "grp-general", "outbounds": gtags,
                        "url": HEALTH_URL, "interval": "60s", "tolerance": 150},
                       {"type": "urltest", "tag": "grp-fast", "outbounds": ftags,
                        "url": HEALTH_URL, "interval": "60s", "tolerance": 150}]
                      + outbounds + [{"type": "direct", "tag": "direct"}]),
        "route": {"rules": [
            {"inbound": ["in-h-g", "in-s-g"], "outbound": "grp-general"},
            {"inbound": ["in-h-f", "in-s-f"], "outbound": "grp-fast"},
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
            {"inbound": ["in-cli"], "outbound": "grp-fast"},
        ]},
    }
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
    gen = pick(rows, True, args.min_dl, args.min_ul, args.top)
    if not gen:
        log("no ChatGPT-capable node above thresholds; lowering to 80/20")
        gen = pick(rows, True, 80, 20, args.top)
    fast = pick(rows, False, max(args.min_dl, 600), args.min_ul, args.top) or \
        pick(rows, False, args.min_dl, args.min_ul, args.top)
    log(f"deep rows {len(rows)}, chatgpt-ok {sum(1 for r in rows if r.get('chatgpt_ok'))}")
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
                     timeout=6.0, log=log)
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
        json.dump([proc.pid], fp)
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
        rows_out.append(dict(r, id=r["tag"],
                             label=f"{r.get('loc','??')} {r['proto']} {r['server']}:{r['port']}",
                             kind="node", ttfb_ms=r.get("cg_ttfb_ms"),
                             speed_kbps=r.get("dl_kbps"),
                             ok_both=bool(r.get("chatgpt_ok") and (r.get("dl_kbps") or 0) > 0),
                             score=round(score(r), 1),
                             err=(r.get("chatgpt_verdict") or "") if not r.get("chatgpt_ok") else ""))
    best_row = dict(gen[0], id="pinned-general", kind="local",
                    label=f"固定出口组 general（首选 {gen[0]['server']}:{gen[0]['port']} {gen[0].get('loc','')}）",
                    ttfb_ms=gen[0].get("cg_ttfb_ms"), speed_kbps=gen[0].get("dl_kbps"),
                    ok_both=True, score=round(score(gen[0]), 1))
    act_old = {}
    try:
        act_old = json.load(open(P.ACTIVE, encoding="utf-8"))
    except Exception:
        pass
    with open(P.ACTIVE, "w", encoding="utf-8", newline="\n") as fp:
        json.dump({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "chosen": best_row, "rows": rows_out[:150], "applied": "PAC " + pac_info["url"],
                   "dead_summary": {}, "previous": act_old.get("previous", {}),
                   "baseline": act_old.get("baseline", {}),
                   "endpoint": general_ep, "verify": ver, "mode": "pac",
                   "pac": pac_info, "general": general_ep, "fast": fast_ep,
                   "gates": gates, "pinned": True,
                   "groups": {"general": gtags, "fast": ftags},
                   "cli": f"127.0.0.1:{CLI_MIXED}"},
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
