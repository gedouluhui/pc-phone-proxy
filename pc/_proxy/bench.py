"""Benchmark public proxies with a real end-to-end HTTPS fetch.

Round 1 (screening): TCP connect -> proxy CONNECT/SOCKS5 -> TLS -> GET
https://www.gstatic.com/generate_204, must return 204.

Round 2 (confirmation): same, 2 more attempts; must pass both.

Round 3 (throughput): fresh tunnel to speed.cloudflare.com, download 1 MB,
measure payload bytes/s.

Output: pool.json (survivors only, ranked), dead.jsonl (reason per dead entry).
"""
import argparse
import asyncio
import base64
import json
import os
import random
import ssl
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK_HOST = "www.gstatic.com"
SPEED_HOST = "speed.cloudflare.com"
SPEED_PATH = "/__down?bytes=1000000"
CTX = ssl.create_default_context()


def load():
    out = []
    with open(os.path.join(HERE, "candidates.jsonl"), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return [x for x in out if x.get("kind") == "proxy" and x["proto"] in ("http", "socks5")]


async def tunnel(rec, host, port, timeout):
    """Open a raw tunnel to host:port through the proxy. Returns (reader, writer, marks)."""
    t0 = time.perf_counter()
    reader, writer = await asyncio.wait_for(asyncio.open_connection(rec["host"], rec["port"]), timeout)
    marks = {"tcp_ms": round((time.perf_counter() - t0) * 1000, 1)}
    t1 = time.perf_counter()
    if rec["proto"] == "http":
        auth = ""
        if rec.get("user"):
            tok = base64.b64encode(f"{rec['user']}:{rec['pass']}".encode()).decode()
            auth = f"Proxy-Authorization: Basic {tok}\r\n"
        writer.write((f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                      f"{auth}User-Agent: curl/8.5.0\r\n\r\n").encode())
        line = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout)
        if b" 200" not in line:
            raise RuntimeError("connect_" + line.split(b" ")[1].decode(errors="replace")[:12])
        while True:
            h = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout)
            if h == b"\r\n":
                break
    else:
        writer.write(b"\x05\x01" + (b"\x02" if rec.get("user") else b"\x00"))
        ver_n = await asyncio.wait_for(reader.readexactly(2), timeout)
        if ver_n[1] == 2:
            u, p = rec["user"].encode(), rec["pass"].encode()
            writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            r = await asyncio.wait_for(reader.readexactly(2), timeout)
            if r[1] != 0:
                raise RuntimeError("socks_auth")
        elif ver_n[1] != 0:
            raise RuntimeError("socks_method%d" % ver_n[1])
        hb = host.encode()
        writer.write(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + int(port).to_bytes(2, "big"))
        r = await asyncio.wait_for(reader.readexactly(4), timeout)
        if r[1] != 0:
            raise RuntimeError("socks_rep%d" % r[1])
        if r[3] == 1:
            await reader.readexactly(4)
        elif r[3] == 3:
            n = (await reader.readexactly(1))[0]
            await reader.readexactly(n)
        else:
            await reader.readexactly(16)
        await reader.readexactly(2)
    marks["setup_ms"] = round((time.perf_counter() - t1) * 1000, 1)
    t2 = time.perf_counter()
    await writer.start_tls(CTX, server_hostname=host)
    marks["tls_ms"] = round((time.perf_counter() - t2) * 1000, 1)
    return reader, writer, marks


async def fetch(rec, host, path, max_bytes, timeout):
    t0 = time.perf_counter()
    async with asyncio.timeout(max(6.0, timeout * 3)):
        return await _fetch_inner(rec, host, path, max_bytes, timeout, t0)


async def _fetch_inner(rec, host, path, max_bytes, timeout, t0):
    reader = writer = None
    try:
        reader, writer, marks = await tunnel(rec, host, 443, timeout)
        t_first = time.perf_counter()
        writer.write((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
                      "Accept: */*\r\nConnection: close\r\n\r\n").encode())
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
        status = int(head.split(b" ", 2)[1])
        body = b""
        if status == 200:
            while len(body) < max_bytes:
                chunk = await asyncio.wait_for(reader.read(65536), timeout * 3)
                if not chunk:
                    break
                body += chunk
        marks.update({"status": status, "bytes": len(body),
                      "ttfb_ms": round((t_first - t0) * 1000, 1),
                      "total_ms": round((time.perf_counter() - t0) * 1000, 1)})
        return marks
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


async def probe_one(rec, timeout=6.0, speed=False):
    m = {"proto": rec["proto"], "host": rec["host"], "port": rec["port"],
         "user": rec.get("user", ""), "pass": rec.get("pass", ""), "source": rec.get("source", "")}
    try:
        marks = await fetch(rec, CHECK_HOST, "/generate_204", 0, timeout)
        m.update(marks)
        m["ok"] = marks["status"] == 204
        if not m["ok"]:
            raise RuntimeError("http_%d" % marks["status"])
        if speed:
            t_s = time.perf_counter()
            sp = await fetch(rec, SPEED_HOST, SPEED_PATH, 8 << 20, timeout * 3)
            dt = time.perf_counter() - t_s
            m["speed_bytes"] = sp["bytes"]
            m["speed_kbps"] = round(sp["bytes"] / 1024 / dt, 1) if dt > 0 else 0
            m["speed_ok"] = sp["status"] == 200 and sp["bytes"] > 0
        return m
    except Exception as e:
        m["ok"] = False
        m["err"] = type(e).__name__ + ":" + str(e)[:60]
        return m


async def run(items, timeout, speed, conc):
    sem = asyncio.Semaphore(conc)
    results = []

    async def guarded(rec):
        async with sem:
            return await probe_one(rec, timeout, speed)

    t0 = time.time()
    done = 0
    for fut in asyncio.as_completed([asyncio.create_task(guarded(r)) for r in items]):
        results.append(await fut)
        done += 1
        if done % 2000 == 0:
            print(f"  {done}/{len(items)} {time.time()-t0:.0f}s", flush=True)
    return results


def key(r):
    return (r["proto"], r["host"], r["port"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--conc", type=int, default=500)
    ap.add_argument("--speed-top", type=int, default=40)
    args = ap.parse_args()

    t0 = time.time()
    items = load()
    random.Random(20261109).shuffle(items)
    if args.limit:
        items = items[: args.limit]
    print(f"round1 screening {len(items)} proxies (conc={args.conc}, timeout={args.timeout}s)", flush=True)
    r1 = asyncio.run(run(items, args.timeout, False, args.conc))
    ok1 = [r for r in r1 if r["ok"]]
    print(f"round1: {len(ok1)} alive / {len(r1)} ({100*len(ok1)/max(1,len(r1)):.1f}%) {time.time()-t0:.0f}s", flush=True)

    print(f"round2 confirm {len(ok1)} survivors x2", flush=True)
    r2 = asyncio.run(run(ok1, args.timeout, False, 100))
    pass2 = {key(r) for r in r2 if r["ok"]}
    r2b = asyncio.run(run([r for r in r2 if r["ok"]], args.timeout, False, 100))
    pass2b = {key(r) for r in r2b if r["ok"]}
    first = {key(r): r for r in r1}
    confirmed = []
    for k in pass2 & pass2b:
        rec = dict(first[k])
        rec["stable"] = True
        rec["best_ms"] = min(r["total_ms"] for r in r2b if key(r) == k)
        confirmed.append(rec)
    print(f"round2: {len(confirmed)} stable / {len(ok1)} ({time.time()-t0:.0f}s)", flush=True)

    confirmed.sort(key=lambda r: r["best_ms"])
    finalists = confirmed[: args.speed_top]
    print(f"round3 speed test top {len(finalists)}", flush=True)
    r3 = asyncio.run(run(finalists, args.timeout, True, 8))
    alive = [r for r in r3 if r["ok"]]
    alive.sort(key=lambda r: (-(r.get("speed_kbps") or 0), r.get("best_ms", 9e9)))

    with open(os.path.join(HERE, "pool.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "screened": len(r1), "alive_r1": len(ok1), "stable": len(confirmed),
                   "kept": alive}, f, indent=1)
    with open(os.path.join(HERE, "dead.jsonl"), "w", encoding="utf-8", newline="\n") as f:
        for r in r1:
            if not r["ok"]:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    errs = {}
    for r in r1:
        if not r["ok"]:
            e = (r.get("err") or "?").split(":")[0]
            errs[e] = errs.get(e, 0) + 1
    print("failure classes:", dict(sorted(errs.items(), key=lambda kv: -kv[1])[:12]))
    print(f"KEPT {len(alive)} proxies -> pool.json ; elapsed {time.time()-t0:.0f}s")
    for r in alive[:20]:
        print(f"  {r['proto']:6s} {r['host']}:{r['port']:<6d} {r.get('best_ms',0):8.0f}ms "
              f"{r.get('speed_kbps',0):9.1f} kB/s  {r.get('source','')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
