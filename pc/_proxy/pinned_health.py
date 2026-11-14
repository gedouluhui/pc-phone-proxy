# -*- coding: utf-8 -*-
"""Re-probe the currently pinned nodes exactly the way deep_test does (Go TLS
through sing-box, not Windows schannel) and print a health table.

Reads pinned.json members, spins a throwaway sing-box on spare ports
(2168/2169, clash 9098), runs the full deep probe per node, writes
pinned_health.json.  Never touches the live pinned process (2101/2103/2090).

Usage:  python pinned_health.py [--uris file.txt]   # optional external URI list
"""
import argparse
import asyncio

import nodes as N
import io
import json
import os
import sys
import time

import deep_test as D
import nodes as N

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "pinned_health.json")
SOCKS, HTTP, API = 2168, 2169, 9098


def load_uris(path=None):
    uris = []
    if path:
        with io.open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and "://" in line and not line.startswith("#"):
                    uris.append(line)
    else:
        p = json.load(io.open(os.path.join(HERE, "pinned.json"), encoding="utf-8"))
        for uri, tag in (p.get("members") or {}).items():
            uris.append(uri)
    return uris


def to_nodes(uris):
    out, seen = [], set()
    for i, uri in enumerate(uris):
        ob, meta = N.parse_uri(uri)
        if not ob:
            # 打码：vless://uuid@ / trojan://pwd@ 的凭据全在前 60 字符里
            print(f"  [skip] cannot parse: {N.redact_uri(uri)}")
            continue
        k = (ob["type"], ob["server"], ob["server_port"])
        if k in seen:
            continue
        seen.add(k)
        ob["tag"] = "p%02d" % len(out)
        out.append({"outbound": ob, "meta": meta, "uri": uri})
    return out


async def run(nodes, timeout):
    path, subset = D.prepare(nodes, SOCKS, HTTP, API)
    proc = D.start_singbox(path, extra=8)
    try:
        if not await D.wait_api(API, proc):
            print("  sing-box failed to start")
            return []
        rec = {"proto": "socks5", "host": "127.0.0.1", "port": SOCKS,
               "user": "", "pass": ""}
        rows = []
        for i, n in enumerate(subset, 1):
            st = await D.set_selector(API, n["outbound"]["tag"])
            if st != 204:
                print(f"  [{i}/{len(subset)}] selector {st}")
                continue
            await asyncio.sleep(0.15)
            try:
                r = await asyncio.wait_for(D.deep_probe(rec, timeout), timeout * 4 + 25)
            except Exception as e:
                r = {"err": str(e)[:60], "dl_kbps": 0, "ul_kbps": 0,
                     "chatgpt_ok": False, "chatgpt_verdict": "timeout"}
            r.update({"tag": n["outbound"]["tag"], "proto": n["meta"]["proto"],
                      "server": n["outbound"]["server"],
                      "port": n["outbound"]["server_port"], "uri": n["uri"],
                      "uri_short": n["uri"][:300]})
            rows.append(r)
            print("  [%d/%d] %-6s %-22s loc=%-2s cg=%-7s dl=%7.1f ul=%7.1f kB/s ttfb=%sms"
                  % (i, len(subset), r["proto"], f"{r['server']}:{r['port']}",
                     r.get("loc", "??"), r.get("chatgpt_verdict", "-"),
                     r.get("dl_kbps") or 0, r.get("ul_kbps") or 0,
                     r.get("cg_ttfb_ms", 0)), flush=True)
        return rows
    finally:
        try:
            proc.terminate()
            proc.wait(4)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--uris", default=None)
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()
    D.kill_stale()
    uris = load_uris(args.uris)
    nodes = to_nodes(uris)
    print(f"probing {len(nodes)} nodes with sing-box (ports {SOCKS}/{HTTP})")
    rows = asyncio.run(run(nodes, args.timeout))
    with io.open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "rows": rows}, f, indent=1, ensure_ascii=False)
    ok = [r for r in rows if (r.get("dl_kbps") or 0) > 50 and r.get("github_ok")]
    print("\nusable (dl>50 & github): %d / %d" % (len(ok), len(rows)))
    for r in sorted(ok, key=lambda r: -(r.get("dl_kbps") or 0)):
        print("  %-2s %-6s %-22s dl=%7.1f ul=%7.1f cg=%s"
              % (r.get("loc", "??"), r["proto"], f"{r['server']}:{r['port']}",
                 r.get("dl_kbps") or 0, r.get("ul_kbps") or 0,
                 "ok" if r.get("chatgpt_ok") else r.get("chatgpt_verdict")))
    print("-> " + OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
