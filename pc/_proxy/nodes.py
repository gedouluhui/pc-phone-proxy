"""Parse v2ray-style subscription URIs into sing-box outbounds, run sing-box,
latency-test every node through its clash_api, then throughput-test the best.

Produces: nodes.json (all parsed), nodes_alive.json (delay-passing), and
node_speed.json (top-N with measured kB/s through a local SOCKS5 inbound).
"""
import argparse
import asyncio
import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse as up

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "bin", "sing-box.exe")
CFG = os.path.join(HERE, "singbox.json")
API = "http://127.0.0.1:9090"

SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305", "none", "plain",
}


def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return ""


def parse_uri(uri):
    try:
        scheme = uri.split("://", 1)[0].lower()
        if scheme == "vmess":
            j = json.loads(b64d(uri.split("://", 1)[1]))
            net = (j.get("net") or "tcp").lower()
            tls = str(j.get("tls") or "").lower() in ("tls", "reality", "true", "1")
            ob = {
                "type": "vmess", "server": str(j["add"]).strip("[]"),
                "server_port": int(j["port"]), "uuid": j["id"],
                "alter_id": int(j.get("aid") or 0),
                "security": (j.get("scy") or "auto") or "auto",
            }
            sni = j.get("sni") or j.get("host") or ""
            if tls:
                ob["tls"] = {"enabled": True, "server_name": sni or j["add"],
                             "insecure": bool(j.get("verify_cert", True) is False)}
            if net == "ws":
                ob["transport"] = {"type": "ws", "path": j.get("path") or "/",
                                   "headers": {"Host": j.get("host") or ""} if j.get("host") else {}}
            elif net in ("grpc",):
                ob["transport"] = {"type": "grpc", "service_name": j.get("path") or ""}
            elif net in ("h2", "http"):
                ob["transport"] = {"type": "http", "host": [j["host"]] if j.get("host") else [],
                                   "path": j.get("path") or "/"}
            return ob, {"proto": "vmess", "net": net, "tls": tls}
        if scheme in ("vless", "trojan"):
            u = up.urlsplit(uri)
            q = dict(up.parse_qsl(u.query, keep_blank_values=True))
            ob = {"type": scheme, "server": u.hostname, "server_port": int(u.port)}
            if scheme == "vless":
                ob["uuid"] = up.unquote(u.username or "")
                if q.get("flow"):
                    ob["flow"] = q["flow"]
            else:
                ob["password"] = up.unquote(u.username or "")
            sec = (q.get("security") or "").lower()
            sni = q.get("sni") or q.get("peer") or q.get("host") or u.hostname
            tls = {}
            if sec in ("tls", "reality", "xtls"):
                tls["enabled"] = True
                tls["server_name"] = sni
                if q.get("allowInsecure") == "1" or q.get("insecure") == "1":
                    tls["insecure"] = True
                if sec == "reality":
                    tls["reality"] = {"enabled": True,
                                      "public_key": q.get("pbk", ""),
                                      "short_id": q.get("sid", "")}
                    tls["utls"] = {"enabled": True, "fingerprint": q.get("fp") or "chrome"}
            if tls:
                ob["tls"] = tls
            net = (q.get("type") or "tcp").lower()
            if net == "ws":
                h = {"Host": q["host"]} if q.get("host") else {}
                ob["transport"] = {"type": "ws", "path": q.get("path") or "/", "headers": h}
                if q.get("host"):
                    ob["transport"]["headers"] = {"Host": q["host"]}
            elif net == "grpc":
                ob["transport"] = {"type": "grpc", "service_name": q.get("serviceName") or q.get("path") or ""}
            elif net in ("h2", "http"):
                ob["transport"] = {"type": "http", "host": [q["host"]] if q.get("host") else [],
                                   "path": q.get("path") or "/"}
            elif net == "tcp" and q.get("headerType") == "http":
                pass
            return ob, {"proto": scheme, "net": net, "tls": bool(tls)}
        if scheme == "ss":
            body = uri.split("://", 1)[1]
            body = body.split("#", 1)[0]
            if "@" in body:
                userinfo, hostport = body.rsplit("@", 1)
                if ":" not in userinfo:
                    userinfo = b64d(userinfo)
                method, _, pwd = userinfo.partition(":")
                q = ""
                if "?" in hostport:
                    hostport, q = hostport.split("?", 1)
                host, _, port = hostport.rpartition(":")
                ob = {"type": "shadowsocks", "server": host.strip("[]"),
                      "server_port": int(port), "method": method, "password": pwd}
                return ob, {"proto": "ss", "net": "tcp", "tls": False}
            dec = b64d(body)
            if "@" in dec:
                userinfo, hostport = dec.rsplit("@", 1)
                method, _, pwd = userinfo.partition(":")
                host, _, port = hostport.rpartition(":")
                ob = {"type": "shadowsocks", "server": host.strip("[]"),
                      "server_port": int(port), "method": method, "password": pwd}
                return ob, {"proto": "ss", "net": "tcp", "tls": False}
            return None, None
        if scheme == "http":
            u = up.urlsplit(uri)
            if not u.hostname or not u.port:
                return None, None
            ob = {"type": "http", "server": u.hostname, "server_port": int(u.port),
                  "username": up.unquote(u.username or ""), "password": up.unquote(u.password or "")}
            q = dict(up.parse_qsl(u.query))
            if q.get("tls") in ("true", "1"):
                ob["tls"] = {"enabled": True, "server_name": q.get("sni") or u.hostname,
                             "insecure": True}
            return ob, {"proto": "http", "net": "tcp", "tls": bool(ob.get("tls"))}
    except Exception:
        return None, None
    return None, None


def build_inbounds():
    return [
        {"type": "socks", "tag": "in-socks", "listen": "127.0.0.1", "listen_port": 2080},
        {"type": "http", "tag": "in-http", "listen": "127.0.0.1", "listen_port": 2081},
    ]


def load_nodes():
    out, seen = [], set()
    with open(os.path.join(HERE, "candidates.jsonl"), encoding="utf-8") as f:
        for line in f:
            x = json.loads(line)
            if x.get("kind") != "node":
                continue
            ob, meta = parse_uri(x["uri"])
            if not ob:
                continue
            if ob["type"] == "shadowsocks" and ob["method"] not in SS_CIPHERS:
                continue
            k = (ob["type"], ob["server"], ob["server_port"])
            if k in seen:
                continue
            seen.add(k)
            tag = "n%05d" % len(out)
            ob["tag"] = tag
            out.append({"outbound": ob, "meta": meta, "uri": x["uri"][:300]})
    return out


def write_config(nodes):
    tags = [n["outbound"]["tag"] for n in nodes]
    cfg = {
        "log": {"level": "error", "timestamp": True},
        "inbounds": build_inbounds(),
        "outbounds": ([{"type": "selector", "tag": "auto", "outbounds": tags + ["direct"],
                        "default": tags[0] if tags else "direct"}]
                      + [n["outbound"] for n in nodes] + [{"type": "direct", "tag": "direct"}]),
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}},
    }
    with open(CFG, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f)
    return cfg


async def tcp_prefilter(nodes, timeout=2.5, conc=400):
    """Keep only nodes whose server:port actually accepts a TCP connection.
    Bulk delay-testing 6k nodes deadlocks sing-box's clash API; a cheap connect
    screen cuts the set by an order of magnitude first."""
    sem = asyncio.Semaphore(conc)
    dns = {}
    lock = asyncio.Lock()
    ok = {}

    async def resolve(host):
        async with lock:
            if host in dns:
                return dns[host]
        try:
            infos = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(host, None, family=0, type=1), 4.0)
            ip = infos[0][4][0] if infos else None
        except Exception:
            ip = None
        async with lock:
            dns[host] = ip
        return ip

    async def one(n):
        ob = n["outbound"]
        tag = ob["tag"]
        async with sem:
            host, port = ob["server"], int(ob["server_port"])
            ip = host
            if not re.fullmatch(r"[0-9.]+|[0-9a-fA-F:]+", host):
                ip = await resolve(host)
            if not ip:
                ok[tag] = (False, 0.0)
                return
            t0 = time.perf_counter()
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
                ok[tag] = (True, round((time.perf_counter() - t0) * 1000, 1))
            except Exception:
                ok[tag] = (False, 0.0)

    t0 = time.time()
    await asyncio.gather(*(one(n) for n in nodes))
    alive = [n for n in nodes if ok.get(n["outbound"]["tag"], (False,))[0]]
    for n in alive:
        n["tcp_ms"] = ok[n["outbound"]["tag"]][1]
    print(f"tcp prefilter: {len(alive)} / {len(nodes)} reachable in {time.time()-t0:.0f}s", flush=True)
    return alive


async def delay_all(tags, timeout_ms=4000, conc=120):
    import aiohttp
    sem = asyncio.Semaphore(conc)
    out = {}

    async def one(sess, tag):
        async with sem:
            try:
                async with sess.get(f"{API}/proxies/{tag}/delay",
                                    params={"timeout": timeout_ms,
                                            "url": "http://www.gstatic.com/generate_204"},
                                    timeout=aiohttp.ClientTimeout(total=timeout_ms / 1000 + 3)) as r:
                    j = await r.json(content_type=None)
                    d = j.get("delay")
                    out[tag] = d if isinstance(d, int) and d >= 0 else None
            except Exception:
                out[tag] = None

    async with aiohttp.ClientSession() as sess:
        await asyncio.gather(*(one(sess, t) for t in tags))
    return out


def delay_batched(tags, timeout_ms=3000, conc=100, batch=250):
    """Run delay_all over batches with a hard wall-clock cap per batch, so a
    stuck batch costs `cap` seconds instead of the whole run."""
    out = {}
    n_batch = (len(tags) + batch - 1) // batch
    for i in range(n_batch):
        part = tags[i * batch:(i + 1) * batch]
        t0 = time.time()
        try:
            got = asyncio.run(asyncio.wait_for(
                delay_all(part, timeout_ms, conc),
                timeout=max(30.0, len(part) / conc * (timeout_ms / 1000 + 4) + 25)))
        except Exception:
            got = {t: None for t in part}
        out.update(got)
        n_ok = sum(1 for t in part if got.get(t))
        print(f"  delay batch {i+1}/{n_batch}: {n_ok}/{len(part)} alive in {time.time()-t0:.0f}s",
              flush=True)
    return out


async def set_selector(tag):
    import aiohttp
    async with aiohttp.ClientSession() as sess:
        async with sess.put(f"{API}/proxies/auto", json={"name": tag}) as r:
            return r.status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--delay-top", type=int, default=40)
    ap.add_argument("--delay-ms", type=int, default=4000)
    ap.add_argument("--conc", type=int, default=120)
    ap.add_argument("--skip-speed", action="store_true")
    args = ap.parse_args()

    if not os.path.isfile(BIN):
        print("missing bin/sing-box.exe")
        return 2
    t0 = time.time()
    nodes = load_nodes()
    print(f"parsed {len(nodes)} unique nodes", flush=True)
    from collections import Counter
    print("  ", dict(Counter(n["meta"]["proto"] for n in nodes)))
    nodes = asyncio.run(tcp_prefilter(nodes))
    if not nodes:
        print("no node survived TCP prefilter")
        return 0
    write_config(nodes)
    print(f"config written ({len(nodes)} outbounds)", flush=True)

    log = open(os.path.join(HERE, "logs", "singbox.log"), "wb")
    proc = subprocess.Popen([BIN, "run", "-c", CFG], stdout=log, stderr=subprocess.STDOUT,
                            creationflags=0x08000000)
    try:
        # wait for API
        import aiohttp
        ok = False
        for _ in range(60):
            try:
                async def ping():
                    async with aiohttp.ClientSession() as s:
                        async with s.get(f"{API}/version", timeout=aiohttp.ClientTimeout(total=2)) as r:
                            return await r.text()
                print("sing-box:", asyncio.run(ping()), flush=True)
                ok = True
                break
            except Exception:
                if proc.poll() is not None:
                    print("sing-box exited rc=", proc.returncode, "see logs/singbox.log")
                    return 3
                time.sleep(1)
        if not ok:
            print("API never came up")
            return 4
        tags = [n["outbound"]["tag"] for n in nodes]
        print(f"delay-testing {len(tags)} nodes (conc={args.conc}, {args.delay_ms}ms)", flush=True)
        delays = delay_batched(tags, args.delay_ms, args.conc)
        alive = [(t, d) for t, d in delays.items() if d]
        alive.sort(key=lambda kv: kv[1])
        print(f"alive {len(alive)} / {len(tags)}", flush=True)
        by_tag = {n["outbound"]["tag"]: n for n in nodes}
        rows = []
        for tag, d in alive:
            n = by_tag[tag]
            rows.append({"tag": tag, "delay_ms": d, "proto": n["meta"]["proto"],
                         "server": n["outbound"]["server"], "port": n["outbound"]["server_port"],
                         "net": n["meta"]["net"], "tls": n["meta"]["tls"], "uri": n["uri"]})
        with open(os.path.join(HERE, "nodes_alive.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "total": len(nodes), "alive": rows}, f, indent=1)
        print(f"saved nodes_alive.json ({len(rows)}) elapsed {time.time()-t0:.0f}s")

        if args.skip_speed or not rows:
            return 0
        # speed test top-N through a selector
        import bench
        top = rows[: args.delay_top]
        # add selector group by rewriting config? sing-box needs it at startup.
        print(f"speed-testing top {len(top)} sequentially via socks5 127.0.0.1:2080", flush=True)
        res = []
        for i, r in enumerate(top, 1):
            async def run_one():
                st = await set_selector(r["tag"])
                if st != 204:
                    return None
                rec = {"proto": "socks5", "host": "127.0.0.1", "port": 2080, "user": "", "pass": ""}
                return await bench.probe_one(rec, timeout=8.0, speed=True)
            m = asyncio.run(run_one())
            r2 = dict(r)
            if m and m.get("ok"):
                r2["speed_kbps"] = m.get("speed_kbps", 0)
                r2["speed_bytes"] = m.get("speed_bytes", 0)
                r2["ttfb_ms"] = m.get("ttfb_ms")
                r2["total_ms"] = m.get("total_ms")
                r2["works"] = True
            else:
                r2["works"] = False
                r2["err"] = (m or {}).get("err", "selector")
            res.append(r2)
            print(f"  [{i}/{len(top)}] {r['proto']:7s} {r['server']}:{r['port']:<6d} "
                  f"delay={r['delay_ms']:>5d}ms speed={r2.get('speed_kbps',0):8.1f} kB/s "
                  f"{'OK' if r2['works'] else 'FAIL ' + r2.get('err','')[:40]}", flush=True)
        with open(os.path.join(HERE, "node_speed.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "rows": res}, f, indent=1)
        print(f"elapsed {time.time()-t0:.0f}s")
        return 0
    finally:
        try:
            proc.terminate()
            proc.wait(5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        log.close()


if __name__ == "__main__":
    sys.exit(main())
