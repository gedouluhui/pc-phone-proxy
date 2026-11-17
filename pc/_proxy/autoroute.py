# -*- coding: utf-8 -*-
"""按站点组实测各出口延迟，选出当前最快的出口，写 route_map.json 并重建 PAC。

设计目标：用户不想每次网慢都来找人改代码。这个脚本把「哪个域名走哪条线」
从手工维护变成定期自动测量——每个出口对每个站点组各测 3 次取中位数，
只接受 2xx/3xx 的结果（403/挑战页不给分），最后把结果写进 PAC。

用法：
    python autoroute.py            # 只测速 + 写 route_map.json，不重建 PAC
    python autoroute.py --apply    # 测完直接重建 PAC
看板：
    python autoroute.py --show     # 打印当前映射与延迟
"""
import argparse
import io
import json
import os
import socket
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "route_map.json")
NOWIN = 0x08000000

EXITS = {
    "general": 2101,
    "fast": 2103,
    "hk": 2086,
    "us": 2096,
}

# 站点组：name -> (探测 URL, 域名列表)
# 域名列表会直接写进 PAC，探测 URL 用来判断「这个出口现在能不能用、有多快」。
GROUPS = {
    "google": (
        "https://www.gstatic.com/generate_204",
        # 只放静态资源。google.com / gemini.google.com / aistudio.google.com
        # 不能进这个组：香港 IP 不在 AI Studio 的支持地区列表里，会被强制跳到
        # "Available regions" 文档页，连对话都开不了。它们必须走西班牙/美国出口。
        ["gstatic.com", "googleapis.com", "googleusercontent.com",
         "gvt1.com", "ggpht.com", "withgoogle.com"],
    ),
    "openai": (
        "https://chatgpt.com/",
        ["chatgpt.com", "openai.com", "chatgpt.livekit.cloud", "sora.chatgpt.com",
         "platform.openai.com", "oaistatic.com", "oaiusercontent.com",
         "auth.openai.com", "auth0.openai.com"],
    ),
    "anthropic": (
        "https://claude.ai/",
        ["claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com"],
    ),
    "github": (
        "https://github.com/",
        ["github.com", "githubusercontent.com", "githubassets.com", "github.io",
         "githubcopilot.com", "ghcr.io"],
    ),
    "huggingface": (
        "https://huggingface.co/",
        ["huggingface.co", "hf.co", "hfusercontent.com", "cdn-lfs.huggingface.co"],
    ),
}

OK_CODES = {"200", "204", "301", "302", "304"}
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
# 见 probe()：Cloudflare 挑战页的判定不只看 UA。
HDRS = ["-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "-H", "Accept-Language: en-US,en;q=0.9",
        "-H", 'sec-ch-ua: "Chromium";v="131", "Not_A Brand";v="24"',
        "-H", 'sec-ch-ua-platform: "Windows"',
        "-H", "Upgrade-Insecure-Requests: 1"]


def probe(url, port, timeout=15):
    """返回 (ok, ttfb_seconds)。只有 2xx/3xx 才算可用。

    只带 UA 不够：claude.ai 对「只有 UA 的 curl」返回 403 Cloudflare 挑战，
    而带完整浏览器头的同一个出口是 302。结果是 anthropic 组每个周期都被判
    「所有出口不可用」而消失，claude.ai 掉回静态 GENERAL 规则。
    这里补齐 Accept / Accept-Language / sec-ch-ua 三个必需的挑战门槛。
    """
    args = ["curl", "-s", "-o", "NUL", "-m", str(timeout), "-A", UA] + HDRS + [
            "-x", "http://127.0.0.1:%d" % port,
            "-w", "%{http_code} %{time_starttransfer}", url]
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           errors="replace", timeout=timeout + 6,
                           creationflags=NOWIN)
        parts = (p.stdout or "").split()
        code = parts[0] if parts else "000"
        ttfb = float(parts[1]) if len(parts) > 1 else 99.0
        return (code in OK_CODES and ttfb < float(timeout)), ttfb
    except Exception:
        return False, 99.0


def active_exits():
    """只保留真的能把 HTTPS 送出去的出口。

    端口在监听 != 上游活着：2096 的 singbox_one.json 只有一个死掉的 http
    上游，TCP 连得上但每个请求都 reset；2086 在 pinned 配置里已无 inbound。
    不过滤就会每组白测 3 次，还可能把死出口选成 best。
    """
    live = {}
    for name, port in EXITS.items():
        s = socket.socket()
        s.settimeout(0.4)
        try:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                continue
        finally:
            s.close()
        ok, _ = probe("https://www.gstatic.com/generate_204", port, timeout=10)
        if ok:
            live[name] = port
        else:
            print("[exit %s:%d] 上游不可用，跳过" % (name, port))
    return live


def measure_group(url, exits):
    """对每个出口测 3 次，返回 {exit_name: median_ttfb} 与可用标记。"""
    res = {}
    for name, port in exits.items():
        samples = []
        for _ in range(3):
            ok, ttfb = probe(url, port)
            if ok:
                samples.append(ttfb)
        if samples:
            res[name] = round(statistics.median(samples), 3)
    return res


def build():
    exits = active_exits()
    if not exits:
        print("没有任何可用出口，保留旧 route_map.json")
        try:
            return (json.load(io.open(OUT, encoding="utf-8")) or {}).get("groups") or {}
        except Exception:
            return {}
    try:
        old = (json.load(io.open(OUT, encoding="utf-8")) or {}).get("groups") or {}
    except Exception:
        old = {}
    groups = {}
    for name, (url, domains) in GROUPS.items():
        res = measure_group(url, exits)
        if not res:
            # 403 挑战页不计分是对的，但"不计分"不等于"这个组消失"。
            # 旧版这里 groups={} 重建后直接跳过，anthropic 组因此从
            # route_map 里蒸发，claude.ai 落回静态 GENERAL 规则。
            if name in old:
                groups[name] = old[name]
                print("[%s] 全部出口被挑战/不可用，沿用旧路由 %s"
                      % (name, old[name].get("proxy")))
            else:
                print("[%s] 所有出口都不可用且无旧配置，交给 PAC 静态规则" % name)
            continue
        best = min(res, key=res.get)
        groups[name] = {
            "proxy": "127.0.0.1:%d" % exits[best],
            "exit": best,
            "ttfb": res[best],
            "samples": res,
            "domains": domains,
        }
        print("[%s] -> %s %.2fs  (%s)" % (
            name, best, res[best],
            "  ".join("%s=%.2f" % (k, v) for k, v in sorted(res.items(), key=lambda kv: kv[1]))))
    data = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "groups": groups}
    with io.open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    print("saved", OUT)
    return groups


def show():
    try:
        data = json.load(io.open(OUT, encoding="utf-8"))
    except Exception:
        print("还没有 route_map.json，先跑一次 python autoroute.py")
        return 1
    print("generated_at", data.get("generated_at"))
    for name, g in (data.get("groups") or {}).items():
        print("  %-12s -> %-6s %.2fs  %s"
              % (name, g.get("exit"), g.get("ttfb", 0), " ".join(
                  "%s=%.2f" % (k, v) for k, v in sorted(
                      (g.get("samples") or {}).items(), key=lambda kv: kv[1]))))
    return 0


LOCK = os.path.join(HERE, "autoroute.lock")


def _acquire():
    """单实例锁。返回文件句柄（保活即持锁），拿不到返回 None。

    看门狗每小时跑一次 --apply，用户也可能同时在终端手动跑。两个实例会同时
    打同一批出口：互相抢带宽把 TTFB 抬到超时，anthropic 组因此被判「全灭」，
    后跑完的那个用降级结果覆盖 route_map.json —— 2026-11-18 实测撞过一次。
    msvcrt 的锁随进程退出自动释放，不会留下需要人工清的 stale lock。
    """
    try:
        import msvcrt
        f = open(LOCK, "a+")
        msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        return f
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="测完重建 PAC")
    ap.add_argument("--show", action="store_true", help="只看当前映射")
    a = ap.parse_args()
    if a.show:
        return show()
    lock = _acquire()
    if lock is None:
        print("另一个 autoroute 正在跑，本次跳过（避免两个实例互相抢带宽）")
        return 0
    try:
        build()
        if a.apply:
            import pacroute
            # 必须显式传活着的端口。无参 apply_pac() 会落到 DEFAULT_GENERAL=9910
            # (Geph 未运行) / DEFAULT_FAST=2086 (pinned 已无此 inbound)，把
            # fail-closed 的 GENERAL 规则指向两个死端口，Claude 直接打不开。
            info = pacroute.apply_pac(pacroute.resolve_ep(None, "general"),
                                      pacroute.resolve_ep(None, "fast"))
            print("pac", info.get("ok"), info.get("url"), info.get("err", ""),
                  "general=%s fast=%s" % (info.get("general"), info.get("fast")))
            return 0 if info.get("ok") else 1
        return 0
    finally:
        try:
            import msvcrt
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception:
            pass
        try:
            lock.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
