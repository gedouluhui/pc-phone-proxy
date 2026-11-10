# -*- coding: utf-8 -*-
"""Pick the phone app's embedded node pool out of node_deep.json rows.

The phone app does its own health checking (Xray observatory, 30s), so what it
needs is *breadth*: a mix of ChatGPT-capable exits plus the fastest remaining
bulk exits.  Every picked node keeps its original share URI; the Android side
parses URIs with the exact same parser it uses for user imports, so there is
only one protocol implementation to trust.

Selection rules (learned the hard way):
  * today's deep-test rows are the core; yesterday's rows only top up
  * throughput floors: fresh dl>=250 & ul>=60 kB/s, prev dl>=150 & ul>=30
  * never embed CN/IR exits
  * max 2 nodes per host and per /24 (or domain suffix)
  * Xray rejects plaintext VLESS, so vless without tls/reality is excluded

Output: assets/nodes.json  [{tag, name, uri, cg}]

Credentials (UUIDs / passwords) stay inside this file and the assets file;
the console only prints host:port and measured speeds.
"""
import json
import os
import re
import sys
import urllib.parse

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
# 默认读仓库里电脑端的 _proxy（它生成 node_deep.json）；也可用 PROXY_DIR 指向别处。
PROXY = os.environ.get("PROXY_DIR") or os.path.join(HERE, "..", "pc", "_proxy")
PROXY = os.path.abspath(PROXY)
FRESH = os.path.join(PROXY, "node_deep.json")
PREV = os.path.join(PROXY, "node_deep_prev.json")
OUT = os.path.join(HERE, "assets", "nodes.json")

N_CG = 14          # ChatGPT-capable members (drive both the general balancer
                   # and the cg-balancer for openai/anthropic domains)
MAX_TOTAL = 24     # observatory pings every member every 30s on mobile data
TARGET_MIN = 16    # below this, top up from yesterday's rows
MAX_PER_HOST = 2   # one dead host should not gut the pool
MAX_PER_PREFIX = 2 # same for one /24 or registrable-domain suffix

MIN_DL_FRESH = 250.0
MIN_UL_FRESH = 60.0
MIN_DL_PREV = 150.0
MIN_UL_PREV = 30.0
BAD_LOCS = {"CN", "IR"}


def fnum(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def truthy(v):
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "ok")


def score(r):
    dl = fnum(r.get("dl_kbps"))
    ul = fnum(r.get("ul_kbps"))
    ttfb = fnum(r.get("cg_ttfb_ms"), 3000.0)
    return dl + 1.5 * ul - max(0.0, ttfb - 400.0) / 20.0


def net_prefix(server):
    host = (server or "").lower()
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return ".".join(host.split(".")[:3])
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def load_rows():
    """(fresh rows, prev-only rows); fresh wins when the same URI appears twice."""
    fresh, prev, order = {}, {}, []
    for path, dest in ((PREV, prev), (FRESH, fresh)):
        if not os.path.isfile(path):
            continue
        try:
            d = json.load(open(path, encoding="utf-8"))
        except Exception as e:
            print("skip %s: %r" % (os.path.basename(path), e))
            continue
        for r in d.get("rows", []):
            uri = (r.get("uri") or "").strip()
            if not uri:
                continue
            if uri not in order:
                order.append(uri)
            dest[uri] = r
    fresh_rows = [fresh[u] for u in order if u in fresh]
    prev_only = [prev[u] for u in order if u in prev and u not in fresh]
    return fresh_rows, prev_only


def usable(r):
    uri = (r.get("uri") or "").strip()
    if not uri:
        return False
    scheme = uri.split("://", 1)[0].lower() if "://" in uri else ""
    if scheme not in ("vless", "vmess", "trojan", "ss", "http", "https",
                      "socks", "socks5"):
        return False
    if scheme == "ss" and "plugin=" in uri:
        return False
    if scheme == "vless":
        # Xray 拒绝「无 TLS 的 VLESS」明文出站（除非目标是私网/域名），
        # 这种节点本来也是明文传 UUID，不进池子
        try:
            q = urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)
            sec = (q.get("security") or ["none"])[0].lower()
            net = (q.get("type") or ["tcp"])[0].lower()
        except Exception:
            sec, net = "none", "tcp"
        if sec in ("", "none"):
            return False
        # Xray v26: REALITY only supports RAW/XHTTP/gRPC transports
        if sec == "reality" and net not in ("", "raw", "tcp", "xhttp", "grpc"):
            return False
    if fnum(r.get("dl_kbps")) < 50:
        return False
    try:
        p = urllib.parse.urlparse(uri)
        if not p.hostname or not p.port:
            return False
    except Exception:
        return False
    # Deep stage only probes rows that already passed a TCP connect, so a row
    # with real throughput numbers is known-reachable at harvest time.
    return True


def by_quality(rows, min_dl, min_ul):
    out = []
    for r in rows:
        if not usable(r):
            continue
        loc = (r.get("loc") or "").strip().upper()
        if loc in BAD_LOCS:
            continue
        if fnum(r.get("dl_kbps")) < min_dl:
            continue
        if fnum(r.get("ul_kbps")) < min_ul:
            continue
        out.append(r)
    return out


def pick(fresh_rows, prev_rows):
    chosen, seen_sp = [], set()
    seen_host, seen_pfx = {}, {}

    def add(r, why):
        host = (r.get("server") or "").lower()
        key = (host, str(r.get("port")))
        pfx = net_prefix(host)
        if key in seen_sp:
            return False
        if seen_host.get(host, 0) >= MAX_PER_HOST:
            return False
        if seen_pfx.get(pfx, 0) >= MAX_PER_PREFIX:
            return False
        seen_sp.add(key)
        seen_host[host] = seen_host.get(host, 0) + 1
        seen_pfx[pfx] = seen_pfx.get(pfx, 0) + 1
        chosen.append((r, why))
        return True

    core = by_quality(fresh_rows, MIN_DL_FRESH, MIN_UL_FRESH)
    core.sort(key=score, reverse=True)

    # 1) ChatGPT-capable exits by score
    for r in core:
        if sum(1 for _, w in chosen if w == "cg") >= N_CG:
            break
        if truthy(r.get("chatgpt_ok")):
            add(r, "cg")

    # 2) fill the rest: fastest bulk exits first, then leftover cg nodes
    bulk = sorted(core, key=lambda r: fnum(r.get("dl_kbps")) + 0.5 * fnum(r.get("ul_kbps")),
                  reverse=True)
    for r in bulk:
        if len(chosen) >= MAX_TOTAL:
            break
        add(r, "cg" if truthy(r.get("chatgpt_ok")) else "fast")
    for r in core:
        if len(chosen) >= MAX_TOTAL:
            break
        add(r, "cg" if truthy(r.get("chatgpt_ok")) else "fast")

    # 3) yesterday's survivors only as a top-up when today's harvest is thin
    if len(chosen) < TARGET_MIN:
        old = by_quality(prev_rows, MIN_DL_PREV, MIN_UL_PREV)
        old.sort(key=score, reverse=True)
        for r in old:
            if len(chosen) >= TARGET_MIN:
                break
            add(r, "cg" if truthy(r.get("chatgpt_ok")) else "fast")

    return chosen[:MAX_TOTAL]


def label(r, fresh):
    loc = (r.get("loc") or "??").strip() or "??"
    if loc in ("??", "None"):
        loc = "??"
    dl = fnum(r.get("dl_kbps"))
    speed = ("%.1fM" % (dl / 1000.0)) if dl >= 1000 else ("%.0fK" % dl)
    proto = (r.get("proto") or "?").strip()
    base = "%s %s %s" % (loc, proto, speed)
    return base if fresh else base + " 昨测"


def main():
    fresh_rows, prev_rows = load_rows()
    chosen = pick(fresh_rows, prev_rows)
    if not chosen:
        print("no usable nodes; refusing to write an empty pool")
        return 1
    fresh_ids = {(r.get("uri") or "").strip() for r in fresh_rows}
    nodes = []
    for i, (r, why) in enumerate(chosen):
        tag = "p%d" % i
        is_fresh = (r.get("uri") or "").strip() in fresh_ids
        name = label(r, is_fresh)
        if why == "cg":
            name += " GPT"
        nodes.append({"tag": tag, "name": name,
                      "uri": r["uri"].strip(), "cg": why == "cg"})
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(nodes, f, ensure_ascii=False, indent=1)

    print("%-4s %-2s %-7s %-28s %-5s %8s %8s %-4s %s"
          % ("tag", "loc", "proto", "server", "port", "dl", "ul", "cg", "src"))
    for (r, why), n in zip(chosen, nodes):
        print("%-4s %-2s %-7s %-28s %-5s %8.0f %8.0f %-4s %s"
              % (n["tag"], (r.get("loc") or "??")[:2], r.get("proto", "?"),
                 str(r.get("server"))[:28], r.get("port"),
                 fnum(r.get("dl_kbps")), fnum(r.get("ul_kbps")),
                 "GPT" if why == "cg" else "-",
                 "fresh" if (r.get("uri") or "").strip() in fresh_ids else "prev"))
    print("wrote %d nodes -> %s (fresh=%d prev=%d)"
          % (len(nodes), OUT,
             sum(1 for r, _ in chosen if (r.get("uri") or "").strip() in fresh_ids),
             sum(1 for r, _ in chosen if (r.get("uri") or "").strip() not in fresh_ids)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
