"""Deep-test subscription nodes for real usability, not just reachability.

Stages
  filter -> TCP prefilter of every parsed node (candidates.jsonl)
  delay  -> one sing-box holding all survivors; clash-API delay test
  deep   -> N parallel sing-box workers; for each node measure
              * sustained download 4 MB from speed.cloudflare.com
              * upload 1 MB to speed.cloudflare.com   (image upload / Codex)
              * ChatGPT gate (HTTP 200, >50 KB, no unsupported_country)
              * github.com reachable
              * Cloudflare trace loc= country of the exit

Writes node_deep.json.  Never touches the running proxy on 2080/2086.
"""
import argparse
import asyncio
import json
import os
import ssl
import subprocess
import time

import bench
import nodes as N

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "bin", "sing-box.exe")
CFG = os.path.join(HERE, "singbox_deep.json")
ALIVE = os.path.join(HERE, "nodes_alive2.json")
OUT = os.path.join(HERE, "node_deep.json")
PIDS = os.path.join(HERE, "deep_pids.json")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


def log(*a):
    print(*a, flush=True)


def kill_stale():
    try:
        pids = json.load(open(PIDS))
    except Exception:
        return
    for pid in pids:
        subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                       capture_output=True, creationflags=0x08000000)


def save_pids(pids):
    with open(PIDS, "w", encoding="utf-8", newline="\n") as f:
        json.dump(pids, f)


def sanitize(n):
    """Drop fields sing-box 1.14 rejects, so one bad URI cannot kill the batch."""
    ob = n["outbound"]
    if ob.get("type") == "vless" and ob.get("flow") not in (None, "", "xtls-rprx-vision"):
        ob.pop("flow", None)
    tls = ob.get("tls") or {}
    if tls.get("reality") and not tls["reality"].get("public_key"):
        ob.pop("tls", None)
    if ob.get("type") == "trojan" and not ob.get("password"):
        return False
    return True


def build_cfg(subset, socks, http, api):
    tags = [n["outbound"]["tag"] for n in subset]
    return {
        "log": {"level": "error"},
        "inbounds": [
            {"type": "socks", "tag": "in-s", "listen": "127.0.0.1", "listen_port": socks},
            {"type": "http", "tag": "in-h", "listen": "127.0.0.1", "listen_port": http},
        ],
        "outbounds": ([{"type": "selector", "tag": "auto", "outbounds": tags + ["direct"],
                        "default": tags[0]}] + [n["outbound"] for n in subset]
                      + [{"type": "direct", "tag": "direct"}]),
        "experimental": {"clash_api": {"external_controller": f"127.0.0.1:{api}"}},
    }


def cfg_path(api):
    return CFG if api == 9091 else CFG.replace(".json", f"_{api}.json")


def prepare(subset, socks, http, api):
    """Write a config that `sing-box check` accepts, dropping the nodes it blames."""
    subset = [n for n in subset if sanitize(n)]
    path = cfg_path(api)
    for _ in range(80):
        cfg = build_cfg(subset, socks, http, api)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(cfg, f)
        r = subprocess.run([BIN, "check", "-c", path], capture_output=True, text=True,
                           creationflags=0x08000000)
        if r.returncode == 0:
            return path, subset
        out = (r.stderr or "") + (r.stdout or "")
        import re as _re
        m = _re.search(r"outbound\[(\d+)\]", out)
        if not m:
            raise RuntimeError("check failed: " + out.strip()[-300:])
        idx = int(m.group(1)) - 1          # outbounds[0] is the selector
        if not (0 <= idx < len(subset)):
            raise RuntimeError("bad outbound index in " + out.strip()[-200:])
        bad = subset.pop(idx)
        log(f"  drop {bad['outbound']['server']}:{bad['outbound']['server_port']} "
            f"-> {out.strip().splitlines()[-1][:120]}")
    raise RuntimeError("config still invalid after 80 drops")


def start_singbox(path, extra=0):
    logp = os.path.join(HERE, "logs", f"singbox_deep{extra}.log")
    with open(logp, "ab") as logf:
        p = subprocess.Popen([BIN, "run", "-c", path], stdout=logf, stderr=subprocess.STDOUT,
                             creationflags=0x08000000)
    return p


async def wait_api(api, proc, secs=45):
    import aiohttp
    t0 = time.time()
    while time.time() - t0 < secs:
        if proc.poll() is not None:
            return False
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(f"http://127.0.0.1:{api}/version",
                                 timeout=aiohttp.ClientTimeout(total=2)) as r:
                    if r.status == 200:
                        return True
        except Exception:
            await asyncio.sleep(0.6)
    return False


# ------------------------------------------------------------------ HTTP probes
async def open_tunnel(rec, host, timeout):
    return await bench.tunnel(rec, host, 443, timeout)


async def get_probe(rec, host, path, max_bytes, timeout, keep=65536):
    reader = writer = None
    t0 = time.perf_counter()
    try:
        reader, writer, marks = await open_tunnel(rec, host, timeout)
        writer.write((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                      f"User-Agent: {UA}\r\nAccept: */*\r\n"
                      "Accept-Language: en-US,en;q=0.9\r\nConnection: close\r\n\r\n").encode())
        await writer.drain()
        t1 = time.perf_counter()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
        status = int(head.split(b" ", 2)[1])
        hdrs = {}
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                hdrs[k.strip().lower().decode(errors="replace")] = v.strip().decode(errors="replace")
        body = b""
        t_first = None
        t_last = t1
        while len(body) < max_bytes:
            chunk = await asyncio.wait_for(reader.read(65536), max(3.0, timeout))
            if not chunk:
                break
            if t_first is None:
                t_first = time.perf_counter()
            t_last = time.perf_counter()
            body += chunk
        dur = max(0.001, (t_last - t_first)) if t_first else 0.0
        return {"status": status, "bytes": len(body), "headers": hdrs,
                "ttfb_ms": round((t1 - t0) * 1000, 1), "total_ms": round((t_last - t0) * 1000, 1),
                "s": round(dur, 2), "kbps": round(len(body) / 1024 / dur, 1) if dur else 0.0,
                "body": body[:keep]}
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


async def post_upload(rec, host, path, nbytes, timeout):
    reader = writer = None
    t0 = time.perf_counter()
    try:
        reader, writer, _ = await open_tunnel(rec, host, timeout)
        head = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
                f"User-Agent: {UA}\r\nContent-Type: application/octet-stream\r\n"
                f"Content-Length: {nbytes}\r\nConnection: close\r\n\r\n").encode()
        writer.write(head)
        chunk = b"\0" * 65536
        left = nbytes
        while left > 0:
            piece = chunk if left >= len(chunk) else chunk[:left]
            writer.write(piece)
            left -= len(piece)
        t1 = time.perf_counter()
        await writer.drain()
        resp = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
        status = int(resp.split(b" ", 2)[1])
        dur = max(0.001, t1 - t0)
        return {"status": status, "bytes": nbytes, "s": round(dur, 2),
                "kbps": round(nbytes / 1024 / dur, 1)}
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


async def deep_probe(rec, timeout=10.0):
    r = {}
    # 0) exit country
    try:
        tr = await get_probe(rec, "www.cloudflare.com", "/cdn-cgi/trace", 4096, timeout)
        txt = tr["body"].decode(errors="replace")
        loc = ""
        for line in txt.splitlines():
            if line.startswith("loc="):
                loc = line[4:].strip()
        r["loc"] = loc
    except Exception as e:
        r["loc"] = ""
        r["trace_err"] = str(e)[:40]
    # 1) ChatGPT gate
    try:
        cg = await get_probe(rec, "chatgpt.com", "/", 400000, timeout)
        body = cg["body"]
        cf = ("cf-mitigated" in cg["headers"]
              or b"Just a moment" in body or b"challenge-platform" in body
              or b"__cf_chl" in body)
        region = b"unsupported_country" in body
        r.update({"cg_status": cg["status"], "cg_kb": round(cg["bytes"] / 1024, 1),
                  "cg_ttfb_ms": cg["ttfb_ms"]})
        r["chatgpt_ok"] = bool(cg["status"] == 200 and cg["bytes"] > 50000
                               and not region and not cf)
        r["chatgpt_verdict"] = ("ok" if r["chatgpt_ok"] else
                                "region" if region else
                                "cf" if cf or cg["status"] == 403 else
                                f"http{cg['status']}")
    except Exception as e:
        r["chatgpt_ok"] = False
        r["chatgpt_verdict"] = "err:" + str(e)[:30]
    # 2) sustained download 4 MB
    try:
        dl = await get_probe(rec, "speed.cloudflare.com", "/__down?bytes=4000000",
                             4000000, max(timeout, 12.0))
        r.update({"dl_status": dl["status"], "dl_kb": round(dl["bytes"] / 1024, 1),
                  "dl_s": dl["s"], "dl_kbps": dl["kbps"], "dl_ttfb_ms": dl["ttfb_ms"]})
    except Exception as e:
        r.update({"dl_kbps": 0, "dl_err": str(e)[:40]})
    # 3) upload 1 MB
    try:
        ul = await post_upload(rec, "speed.cloudflare.com", "/__up", 1000000, max(timeout, 12.0))
        r.update({"ul_status": ul["status"], "ul_s": ul["s"], "ul_kbps": ul["kbps"]})
    except Exception as e:
        r.update({"ul_kbps": 0, "ul_err": str(e)[:40]})
    # 4) github
    try:
        gh = await get_probe(rec, "github.com", "/", 2000, timeout)
        r["github_ok"] = 200 <= gh["status"] < 400
    except Exception as e:
        r["github_ok"] = False
    return r


# ------------------------------------------------------------------ worker
async def set_selector(api, tag):
    import aiohttp
    async with aiohttp.ClientSession() as s:
        async with s.put(f"http://127.0.0.1:{api}/proxies/auto",
                         json={"name": tag}, timeout=aiohttp.ClientTimeout(total=6)) as r:
            return r.status


async def worker(idx, subset, results, timeout):
    socks = 2180 + idx * 10
    http = 2181 + idx * 10
    api = 9091 + idx
    try:
        path, subset = prepare(subset, socks, http, api)
    except Exception as e:
        log(f"  [w{idx}] {e}")
        return
    proc = start_singbox(path, extra=idx)
    ok = await wait_api(api, proc)
    if not ok:
        log(f"  [w{idx}] sing-box failed to start (rc={proc.poll()})")
        proc.terminate()
        return
    rec = {"proto": "socks5", "host": "127.0.0.1", "port": socks, "user": "", "pass": ""}
    try:
        for i, n in enumerate(subset, 1):
            tag = n["outbound"]["tag"]
            st = await set_selector(api, tag)
            if st != 204:
                results.append({"tag": tag, "ok": False, "err": f"selector{st}"})
                continue
            await asyncio.sleep(0.15)
            try:
                r = await asyncio.wait_for(deep_probe(rec, timeout), timeout * 4 + 25)
            except Exception as e:
                r = {"err": str(e)[:50], "dl_kbps": 0, "ul_kbps": 0,
                     "chatgpt_ok": False, "chatgpt_verdict": "timeout"}
            r.update({"tag": tag, "proto": n["meta"]["proto"],
                      "server": n["outbound"]["server"], "port": n["outbound"]["server_port"],
                      "delay_ms": n.get("delay_ms"), "uri": n["uri"][:300]})
            results.append(r)
            log(f"  [w{idx} {i}/{len(subset)}] {r['proto']:6s} {r['server']}:{r['port']:<6d} "
                f"loc={r.get('loc','??'):2s} cg={r.get('chatgpt_verdict','-'):7s} "
                f"dl={r.get('dl_kbps',0):7.1f} ul={r.get('ul_kbps',0):7.1f} kB/s "
                f"ttfb={r.get('cg_ttfb_ms',0)}ms")
    finally:
        try:
            proc.terminate()
            proc.wait(4)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def load_alive():
    a = json.load(open(ALIVE, encoding="utf-8"))
    rows = a.get("alive") or []
    by = {(r["server"], r["port"], r["proto"]): r for r in rows}
    nodes = []
    for x in N.load_nodes():
        ob = x["outbound"]
        k = (ob["server"], ob["server_port"], x["meta"]["proto"])
        if k in by:
            x["delay_ms"] = by[k]["delay_ms"]
            x["tcp_ms"] = by[k].get("tcp_ms")
            nodes.append(x)
    nodes.sort(key=lambda n: n["delay_ms"])
    return nodes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", default="all", choices=["filter", "delay", "deep", "all"])
    ap.add_argument("--deep-k", type=int, default=96)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--cap", type=int, default=9000, help="max survivors that enter delay test")
    args = ap.parse_args()

    t0 = time.time()
    if not os.path.isfile(BIN):
        log("missing bin/sing-box.exe")
        return 2
    kill_stale()

    if args.stage in ("filter", "delay", "all"):
        nodes = N.load_nodes()
        log(f"parsed {len(nodes)} unique nodes")
        from collections import Counter
        log("  " + str(dict(Counter(n["meta"]["proto"] for n in nodes))))
        nodes = asyncio.run(N.tcp_prefilter(nodes))
        nodes.sort(key=lambda n: n.get("tcp_ms") or 9999)
        if len(nodes) > args.cap:
            log(f"capping {len(nodes)} -> {args.cap} by tcp latency")
            nodes = nodes[: args.cap]
        # delay test in one instance
        path, nodes = prepare(nodes, 2160, 2161, 9089)
        log(f"config ok with {len(nodes)} outbounds")
        proc = start_singbox(path, extra=9)
        try:
            if not asyncio.run(wait_api(9089, proc)):
                log("aggregate sing-box failed to start")
                return 3
            N.API = "http://127.0.0.1:9089"
            tags = [n["outbound"]["tag"] for n in nodes]
            log(f"delay-testing {len(tags)} nodes")
            delays = N.delay_batched(tags, 4000, 120)
            alive = []
            for n in nodes:
                d = delays.get(n["outbound"]["tag"])
                if d:
                    alive.append({"tag": n["outbound"]["tag"], "delay_ms": d,
                                  "proto": n["meta"]["proto"],
                                  "server": n["outbound"]["server"],
                                  "port": n["outbound"]["server_port"],
                                  "net": n["meta"]["net"], "tls": n["meta"]["tls"],
                                  "tcp_ms": n.get("tcp_ms"),
                                  "uri": n["uri"][:300]})
            alive.sort(key=lambda r: r["delay_ms"])
            with open(ALIVE, "w", encoding="utf-8", newline="\n") as f:
                json.dump({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                           "total": len(nodes), "alive": alive}, f, indent=1)
            log(f"alive {len(alive)} -> {ALIVE}")
        finally:
            try:
                proc.terminate()
                proc.wait(4)
            except Exception:
                pass
        if args.stage in ("filter", "delay"):
            log(f"done in {time.time()-t0:.0f}s")
            return 0

    # ---- deep stage ----
    nodes = load_alive()
    top = nodes[: args.deep_k]
    log(f"deep-testing top {len(top)} of {len(nodes)} alive nodes with {args.workers} workers")
    results = []
    procs = []
    # interleave so each worker sees a spread of protocols/latencies
    subsets = [[] for _ in range(args.workers)]
    for i, n in enumerate(top):
        subsets[i % args.workers].append(n)
    asyncio.run(start_workers(subsets, results, args.timeout))
    results.sort(key=lambda r: (-(r.get("dl_kbps") or 0)))
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "deep_k": len(top), "rows": results}, f, indent=1, ensure_ascii=False)
    good = [r for r in results if r.get("chatgpt_ok")]
    log(f"\nchatgpt-ok exits: {len(good)}")
    for r in good[:10]:
        log(f"  {r['loc']} {r['proto']} {r['server']}:{r['port']} "
            f"dl={r.get('dl_kbps')} ul={r.get('ul_kbps')} cg_ttfb={r.get('cg_ttfb_ms')}ms")
    log(f"saved {OUT} in {time.time()-t0:.0f}s")
    return 0


async def start_workers(subsets, results, timeout):
    await asyncio.gather(*(worker(i, subset, results, timeout)
                           for i, subset in enumerate(subsets) if subset))


if __name__ == "__main__":
    raise SystemExit(main())
