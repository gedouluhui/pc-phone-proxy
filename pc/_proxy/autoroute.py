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


def probe(url, port, timeout=15):
    """返回 (ok, ttfb_seconds)。只有 2xx/3xx 才算可用。"""
    args = ["curl", "-s", "-o", "NUL", "-m", str(timeout), "-A", UA,
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


def measure_group(url):
    """对每个出口测 3 次，返回 {exit_name: median_ttfb} 与可用标记。"""
    res = {}
    for name, port in EXITS.items():
        samples = []
        for _ in range(3):
            ok, ttfb = probe(url, port)
            if ok:
                samples.append(ttfb)
        if samples:
            res[name] = round(statistics.median(samples), 3)
    return res


def build():
    groups = {}
    for name, (url, domains) in GROUPS.items():
        res = measure_group(url)
        if not res:
            print("[%s] 所有出口都不可用，保留旧配置" % name)
            continue
        best = min(res, key=res.get)
        groups[name] = {
            "proxy": "127.0.0.1:%d" % EXITS[best],
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="测完重建 PAC")
    ap.add_argument("--show", action="store_true", help="只看当前映射")
    a = ap.parse_args()
    if a.show:
        return show()
    build()
    if a.apply:
        import pacroute
        info = pacroute.apply_pac()
        print("pac", info.get("ok"), info.get("url"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
