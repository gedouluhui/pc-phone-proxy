"""Proxy control: test every known candidate now, keep the best, set it system-wide,
and render a visible report.

Usage:
  python proxyctl.py status            # what is in use right now + pool summary
  python proxyctl.py select            # benchmark all candidates, write ACTIVE.json
  python proxyctl.py enable [--show]   # select (or reuse fresh result) + apply system proxy
  python proxyctl.py disable           # turn the system proxy off
  python proxyctl.py report [--show]   # regenerate report.html from the trial log

Candidates come from three places:
  * pool.json        - public HTTP/SOCKS5 proxies that already survived bench.py
  * local clients    - Geph 5 (127.0.0.1:9910/9909), warp-plus (127.0.0.1:8086),
                       sing-box single-node (127.0.0.1:2080)
  * any --add target - ad-hoc "proto://host:port" for a manual try
"""
import argparse
import asyncio
import ctypes
import io
import json
import os
import subprocess
import sys
import time
import winreg

HERE = os.path.dirname(os.path.abspath(__file__))
KAGGLE = os.path.dirname(HERE)
K = winreg.HKEY_CURRENT_USER
IS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
ACTIVE = os.path.join(HERE, "ACTIVE.json")
PINNED = os.path.join(HERE, "pinned.json")
PIN_PIDS = os.path.join(HERE, "pinned_pids.json")
TRIALS = os.path.join(HERE, "trials.json")
REPORT = os.path.join(HERE, "report.html")
GEPH_EXE = os.path.join(KAGGLE, "_ref_out", "geph5-client.exe")
GEPH_CFG = os.path.join(KAGGLE, "_ref_out", "geph_standalone.yaml")
WARP_EXE = os.path.join(HERE, "bin", "warp-plus.exe")   # 已删除（本机不可用），保留常量仅为兼容
SING_EXE = os.path.join(HERE, "bin", "sing-box.exe")
# Any console child (tasklist/netstat/taskkill/curl/sing-box) launched from a
# windowless parent (pythonw, DETACHED) gets a fresh Windows Terminal window
# unless this flag is set.  Set it on every spawn: the helper jobs are silent.
NOWIN = 0x08000000


# ---------------------------------------------------------------- wininet
def wget(name, default=None):
    try:
        with winreg.OpenKey(K, IS) as k:
            v, _ = winreg.QueryValueEx(k, name)
            return v
    except FileNotFoundError:
        return default


def wset(name, value, kind=winreg.REG_SZ):
    with winreg.CreateKeyEx(K, IS, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, name, 0, kind, value)
    notify()


def notify():
    try:
        ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)   # SETTINGS_CHANGED
        ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)   # REFRESH
    except Exception:
        pass


def current_proxy():
    return {"enabled": bool(wget("ProxyEnable", 0)), "server": wget("ProxyServer", ""),
            "pac": wget("AutoConfigURL", ""), "override": wget("ProxyOverride", "")}


def listen_ok(port):
    import socket
    with socket.socket() as s:
        s.settimeout(0.4)
        return s.connect_ex(("127.0.0.1", port)) == 0


# ---------------------------------------------------------------- processes
# All kills are PID-targeted after checking the image name.  Never by image
# name in bulk: this machine runs a user-owned Geph client and possibly other
# sing-box instances we must not touch.
def pid_image(pid):
    """Image name for a PID ('' when the PID is gone)."""
    try:
        out = subprocess.run(["tasklist", "/FI", "PID eq %d" % int(pid),
                              "/FO", "CSV", "/NH"], capture_output=True,
                             text=True, errors="replace", timeout=10,
                             creationflags=NOWIN).stdout
    except Exception:
        return ""
    out = out.strip()
    return out.split('"')[1] if out.startswith('"') else ""


def pid_alive(pid):
    return bool(pid_image(pid))


def port_pids(port):
    """PIDs listening on <port> (netstat; no psutil in the portable runtime)."""
    try:
        out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True,
                             text=True, errors="replace", timeout=10,
                             creationflags=NOWIN).stdout
    except Exception:
        return []
    pids = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        if parts[1].lower().endswith(":%d" % int(port)) and parts[-1].isdigit():
            pid = int(parts[-1])
            if pid and pid not in pids:
                pids.append(pid)
    return pids


def kill_port(port, expect=("sing-box.exe",), log=print):
    """Free a port we own: enumerate its listener, verify the image, kill by PID."""
    expect = tuple(e.lower() for e in expect)
    killed = []
    for pid in port_pids(port):
        img = pid_image(pid).lower()
        if img in expect:
            subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                           capture_output=True, creationflags=NOWIN)
            killed.append(pid)
            try:
                log("  killed %s pid=%d (port %d)" % (img, pid, port))
            except Exception:
                pass
    return killed


def wait_port_free(ports, timeout=5.0, expect=("sing-box.exe",), log=print):
    t0 = time.time()
    while time.time() - t0 < timeout:
        busy = [p for p in ports if listen_ok(p)]
        if not busy:
            return True
        for p in busy:
            kill_port(p, expect=expect, log=log)
        time.sleep(0.3)
    return not any(listen_ok(p) for p in ports)


def pinned_pair():
    """Endpoints installed by bestroute.py (deep-tested winners), if still alive."""
    try:
        p = json.load(open(PINNED, encoding="utf-8"))
    except Exception:
        return {}
    out = {}
    for k in ("general", "fast"):
        ep = p.get(k)
        try:
            port = int(str(ep).rsplit(":", 1)[1])
        except Exception:
            continue
        if listen_ok(port):
            out[k] = ep
    return out


def pinned_eps():
    p = pinned_pair()
    return [p[k] for k in ("general", "fast") if k in p]


def stop_pinned():
    try:
        pids = json.load(open(PIN_PIDS))
    except Exception:
        return
    for pid in pids:
        subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                       capture_output=True, creationflags=NOWIN)
    try:
        os.remove(PIN_PIDS)
    except OSError:
        pass


# ---------------------------------------------------------------- clients
def start_geph():
    if listen_ok(9910):
        return True
    if not (os.path.isfile(GEPH_EXE) and os.path.isfile(GEPH_CFG)):
        return False
    logp = os.path.join(HERE, "logs", "geph_client.log")
    with open(logp, "ab") as log:
        subprocess.Popen([GEPH_EXE, "--config", GEPH_CFG], stdout=log, stderr=subprocess.STDOUT,
                         creationflags=0x00000008 | 0x08000000)   # DETACHED | NO_WINDOW
    for _ in range(40):
        if listen_ok(9910):
            return True
        time.sleep(0.5)
    return False


def start_warp(port=8086):
    if listen_ok(port):
        return True
    if not os.path.isfile(WARP_EXE):
        return False
    logp = os.path.join(HERE, "logs", "warp.log")
    with open(logp, "ab") as log:
        subprocess.Popen([WARP_EXE, "-b", f"127.0.0.1:{port}"], stdout=log, stderr=subprocess.STDOUT,
                         creationflags=0x00000008 | 0x08000000)
    for _ in range(40):
        if listen_ok(port):
            return True
        time.sleep(0.5)
    return False


def start_singbox_node(uri, socks_port=2080, http_port=2086):
    """Start sing-box with one parsed node. Exposes BOTH socks5 and http inbounds
    (WinINET / Chromium are only guaranteed to honour the http one)."""
    import nodes as N
    ob, meta = N.parse_uri(uri)
    if not ob:
        return False
    ob["tag"] = "node"
    cfg = {"log": {"level": "error"},
           "inbounds": [{"type": "socks", "tag": "in-s", "listen": "127.0.0.1", "listen_port": socks_port},
                        {"type": "http", "tag": "in-h", "listen": "127.0.0.1", "listen_port": http_port}],
           "outbounds": [ob]}
    path = os.path.join(HERE, "singbox_one.json")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f)
    logp = os.path.join(HERE, "logs", "singbox_one.log")
    with open(logp, "ab") as log:
        proc = subprocess.Popen([SING_EXE, "run", "-c", path], stdout=log, stderr=subprocess.STDOUT,
                                creationflags=0x00000008 | 0x08000000)
    for _ in range(30):
        if listen_ok(socks_port) and listen_ok(http_port):
            try:
                with open(os.path.join(HERE, "one_%d.pid" % int(http_port)), "w") as f:
                    f.write(str(proc.pid))
            except OSError:
                pass
            return True
        time.sleep(0.5)
    return False


GATEWAY_PID = os.path.join(HERE, "gateway.pid")
GATEWAY_PORT = 2087


def stop_gateway():
    """Kill the previous gateway by its recorded PID (never by image name)."""
    try:
        pid = int(open(GATEWAY_PID).read().strip())
    except Exception:
        return
    subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                   capture_output=True, creationflags=NOWIN)
    try:
        os.remove(GATEWAY_PID)
    except OSError:
        pass


def start_gateway(rec, port=GATEWAY_PORT):
    """Expose ANY upstream (http or socks5, local or remote) as a local HTTP proxy.

    WinINET can only be trusted to speak HTTP to the system proxy, so a SOCKS5
    upstream must never be written into the registry as `http=`.  The gateway keeps
    the applied endpoint local and uniform: 127.0.0.1:2087."""
    stop_gateway()
    ob = {"type": "socks" if rec["proto"] == "socks5" else "http", "tag": "up",
          "server": rec["host"], "server_port": int(rec["port"])}
    if rec.get("user"):
        ob["username"] = rec["user"]
        ob["password"] = rec.get("pass", "")
    cfg = {"log": {"level": "error"},
           "inbounds": [{"type": "http", "tag": "in-h", "listen": "127.0.0.1", "listen_port": port}],
           "outbounds": [ob]}
    path = os.path.join(HERE, "singbox_gateway.json")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f)
    logp = os.path.join(HERE, "logs", "gateway.log")
    with open(logp, "ab") as log:
        p = subprocess.Popen([SING_EXE, "run", "-c", path], stdout=log, stderr=subprocess.STDOUT,
                             creationflags=0x00000008 | 0x08000000)
    for _ in range(30):
        if listen_ok(port):
            with open(GATEWAY_PID, "w") as f:
                f.write(str(p.pid))
            return True
        if p.poll() is not None:
            return False
        time.sleep(0.5)
    return False


def local_endpoint(rec):
    """Map a winning candidate to the endpoint the system proxy should use.

    HTTP upstreams go in DIRECTLY (a browser-style system proxy works for both
    http:// and https://), because routing them through sing-box's http outbound
    breaks plain-HTTP requests.  SOCKS5 upstreams must be wrapped: WinINET is not
    trusted to speak SOCKS, so they get a local HTTP gateway on 127.0.0.1:2087."""
    if rec["kind"] == "local":
        if rec["port"] in (2086, 9910):
            return f"127.0.0.1:{rec['port']}"
        if rec["port"] == 9909:
            return "127.0.0.1:9910" if listen_ok(9910) else None
        if rec["port"] == 2080:
            return "127.0.0.1:2086" if listen_ok(2086) else None
        return f"127.0.0.1:{rec['port']}"
    if rec["proto"] == "http":
        stop_gateway()
        return f"{rec['host']}:{rec['port']}"
    return f"127.0.0.1:{GATEWAY_PORT}" if start_gateway(rec) else None


def best_node():
    p = os.path.join(HERE, "node_speed.json")
    if not os.path.isfile(p):
        return None
    try:
        rows = json.load(open(p, encoding="utf-8")).get("rows", [])
    except Exception:
        return None
    ok = [r for r in rows if r.get("works") and (r.get("speed_kbps") or 0) > 0]
    ok.sort(key=lambda r: -(r.get("speed_kbps") or 0))
    return ok[0] if ok else None


# ---------------------------------------------------------------- candidates
def candidates(include_local=True):
    out = []
    if include_local:
        if listen_ok(9910):
            out.append({"id": "geph-http", "label": "迷雾通 Geph5（HTTP 9910）", "kind": "local",
                        "proto": "http", "host": "127.0.0.1", "port": 9910, "weight": 1.0})
        if listen_ok(9909):
            out.append({"id": "geph-socks", "label": "迷雾通 Geph5（SOCKS5 9909）", "kind": "local",
                        "proto": "socks5", "host": "127.0.0.1", "port": 9909, "weight": 1.0})
        if listen_ok(8086):
            out.append({"id": "warp", "label": "Cloudflare WARP（warp-plus 8086）", "kind": "local",
                        "proto": "socks5", "host": "127.0.0.1", "port": 8086, "weight": 1.05})
        if listen_ok(2086):
            bn = best_node()
            lab = (f"sing-box 免费节点 {bn['proto']} {bn['server']}:{bn['port']}"
                   if bn else "sing-box 免费节点（HTTP 2086）")
            out.append({"id": "sbox-node", "label": lab, "kind": "local",
                        "proto": "http", "host": "127.0.0.1", "port": 2086, "weight": 1.0})
    pool = []
    try:
        pool = json.load(open(os.path.join(HERE, "pool.json"), encoding="utf-8")).get("kept", [])
    except Exception:
        pass
    for p in pool[:30]:
        out.append({"id": f"pub-{p['proto']}-{p['host']}-{p['port']}",
                    "label": f"{p['host']}:{p['port']}（{p['proto']} 公开代理）", "kind": "remote",
                    "proto": p["proto"], "host": p["host"], "port": p["port"],
                    "user": p.get("user", ""), "pass": p.get("pass", ""),
                    "prev_kbps": p.get("speed_kbps"), "prev_ms": p.get("best_ms"), "weight": 1.0})
    return out


def make_record(m):
    return {"id": m["id"], "label": m["label"], "kind": m["kind"],
            "proto": m["proto"], "host": m["host"], "port": m["port"],
            "user": m.get("user", ""), "pass": m.get("pass", ""), "weight": m.get("weight", 1.0)}


# ---------------------------------------------------------------- run trials
def trial(records, timeout=8.0, conc=8):
    import bench
    done = [0]

    async def main():
        sem = asyncio.Semaphore(conc)

        async def one(rec):
            async with sem:
                r = await bench.probe_one(make_record(rec), timeout=timeout, speed=True)
                r["id"] = rec["id"]
                r["label"] = rec["label"]
                r["kind"] = rec["kind"]
                r["weight"] = rec.get("weight", 1.0)
                done[0] += 1
                verdict = ("OK %8.0f kB/s" % (r.get("speed_kbps") or 0)) if r.get("ok") \
                    else "FAIL " + (r.get("err") or "")[:30]
                print(f"  [{done[0]}/{len(records)}] {rec['label'][:46]:46s} {verdict}", flush=True)
                return r

        return await asyncio.gather(*(one(r) for r in records))

    t0 = time.time()
    res = asyncio.run(main())
    for r in res:
        r["speed_kbps"] = r.get("speed_kbps") or 0
        r["ok_both"] = bool(r.get("ok") and r.get("speed_ok", True))
        r["score"] = round((r["speed_kbps"] * r.get("weight", 1.0)
                            - max(0, r.get("ttfb_ms", 3000) - 300) / 300), 1)
    return res, time.time() - t0


def log_trial(kind, rows, secs):
    hist = []
    if os.path.isfile(TRIALS):
        try:
            hist = json.load(open(TRIALS, encoding="utf-8"))
        except Exception:
            hist = []
    hist.append({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": kind,
                 "secs": round(secs, 1), "rows": rows})
    hist = hist[-40:]
    with io.open(TRIALS, "w", encoding="utf-8", newline="\n") as f:
        json.dump(hist, f, indent=1, ensure_ascii=False)


def prune(rows):
    """Delete dead entries (they are of no further use) and shrink the public pool
    to what still passes.  Returns a failure-class summary for the report."""
    dead_path = os.path.join(HERE, "dead.jsonl")
    dead_summary = {}
    if os.path.isfile(dead_path):
        cnt = {}
        for line in open(dead_path, encoding="utf-8"):
            try:
                r = json.loads(line)
            except Exception:
                continue
            e = (r.get("err") or "?").split(":")[0]
            cnt[e] = cnt.get(e, 0) + 1
        dead_summary = dict(sorted(cnt.items(), key=lambda kv: -kv[1])[:12])
        os.remove(dead_path)
    pool_path = os.path.join(HERE, "pool.json")
    if not os.path.isfile(pool_path):
        return dead_summary
    try:
        d = json.load(open(pool_path, encoding="utf-8"))
    except Exception:
        return dead_summary
    tested = {r["id"]: r["ok_both"] for r in rows if r["kind"] == "remote"}
    old = d.get("kept", [])
    new = []
    for p in old:
        pid = f"pub-{p['proto']}-{p['host']}-{p['port']}"
        if pid in tested and not tested[pid]:
            continue          # 这轮实测不可用 -> 删除
        new.append(p)
    d["kept"] = new
    d["pruned_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    d["dead_summary"] = dead_summary
    with io.open(pool_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(d, f, indent=1, ensure_ascii=False)
    return dead_summary


def select(extra=(), force_local=False):
    cands = candidates()
    cands += [make_record(x) for x in extra]
    if not cands:
        return None, []
    rows, secs = trial(cands)
    usable = [r for r in rows if r["ok_both"]]
    if force_local:
        loc = [r for r in usable if r["kind"] == "local"]
        usable = loc or usable
    usable.sort(key=lambda r: (-r["score"], r.get("ttfb_ms", 9e9)))
    log_trial("select", rows, secs)

    # 公开代理单次测量噪声很大：前 5 名在低并发下再测一轮，用两轮均值定胜负。
    top_ids = {r["id"] for r in usable[:5]}
    if len(top_ids) > 1:
        again, secs2 = trial([make_record(r) for r in rows if r["id"] in top_ids],
                             timeout=6.0, conc=2)
        by = {r["id"]: r for r in again}
        for r in rows:
            a = by.get(r["id"])
            if not a:
                continue
            r["speed_kbps"] = round(((r.get("speed_kbps") or 0) + (a.get("speed_kbps") or 0)) / 2, 1)
            if a.get("ok"):
                r["ttfb_ms"] = a.get("ttfb_ms")
            r["runs"] = 2
            r["ok_both"] = bool(r.get("ok_both") and a.get("ok_both"))
            r["score"] = round(r["speed_kbps"] * r.get("weight", 1.0)
                               - max(0, r.get("ttfb_ms", 3000) - 300) / 300, 1)
        log_trial("refine", again, secs2)

    usable = [r for r in rows if r["ok_both"]]
    if force_local:
        loc = [r for r in usable if r["kind"] == "local"]
        usable = loc or usable
    usable.sort(key=lambda r: (-r["score"], r.get("ttfb_ms", 9e9)))
    best = usable[0] if usable else None
    return best, rows


# ---------------------------------------------------------------- site gate
# 用户的原话："我需要能访问所有这些网站而不是只是打比赛的这个"。
# 速度不是唯一判据：必须真的能把 ChatGPT 这类站点打开。
import re as _re
import subprocess as _sp

GATE = [
    # name, url, budget_s
    ("chatgpt", "https://chatgpt.com/", 25),
    ("chatgpt_api", "https://chatgpt.com/api/auth/session", 18),
    ("claude", "https://claude.ai/", 20),
    ("kaggle", "https://www.kaggle.com/", 20),
    ("google", "https://www.google.com/", 20),
    ("github", "https://github.com/", 20),
    ("huggingface", "https://huggingface.co/", 20),
]
_MK_UNSUPPORTED = _re.compile(r"unsupported_country", _re.I)
_MK_CHALLENGE = _re.compile(r"(Just a moment|请稍候|cf_chl|Attention Required)", _re.I)
_MK_BLOCKED = _re.compile(r"(Error: Forbidden|Access Denied|has been blocked)", _re.I)


def _curl_site(proxy, url, timeout=20):
    args = ["curl", "-sS", "--ssl-no-revoke", "--max-time", str(timeout),
            "--connect-timeout", "10", "-x", "http://" + proxy,
            "-D", "-", "-o", "-", "-w", "\n@@%{http_code} %{size_download} %{time_total}",
            url]
    t0 = time.time()
    try:
        p = _sp.run(args, capture_output=True, timeout=timeout + 6,
                    creationflags=NOWIN)
        out = p.stdout.decode("utf-8", "replace")
        err = p.stderr.decode("utf-8", "replace").strip()
    except _sp.TimeoutExpired:
        return {"code": "000", "size": 0, "secs": round(time.time() - t0, 1),
                "err": "timeout", "markers": [], "location": ""}
    body, _, tail = out.rpartition("@@")
    parts = tail.split()
    code = parts[0] if parts else "000"
    try:
        size = int(float(parts[1]))
    except Exception:
        size = len(body)
    head, _, body2 = body.partition("\r\n\r\n")
    loc = ""
    for line in head.splitlines():
        if line.lower().startswith("location:"):
            loc = line.split(":", 1)[1].strip()
    markers = []
    if _MK_UNSUPPORTED.search(body) or "app-unavailable-in-region" in loc:
        markers.append("unsupported_country")
    if _MK_CHALLENGE.search(body):
        markers.append("challenge")
    if _MK_BLOCKED.search(body):
        markers.append("blocked")
    return {"code": code, "size": size, "secs": round(time.time() - t0, 1),
            "err": err[:80], "markers": markers, "location": loc[:120]}


def gate_one(endpoint):
    """Probe the consumer sites a browser needs through one HTTP proxy endpoint."""
    from concurrent.futures import ThreadPoolExecutor
    rows = {}
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = {n: ex.submit(_curl_site, endpoint, u, t) for n, u, t in GATE}
        for n, _u, _t in GATE:
            try:
                rows[n] = futs[n].result()
            except Exception as e:
                rows[n] = {"code": "000", "size": 0, "secs": 0, "err": repr(e),
                           "markers": []}
    c = rows["chatgpt"]
    general = (c["code"] == "200" and c["size"] > 50000
               and "unsupported_country" not in c["markers"])
    def reachable(n):
        r = rows[n]
        return (r["code"].startswith("2") or r["code"].startswith("3")) \
            and "unsupported_country" not in r["markers"]
    # Kaggle 由 PAC 直连，不参与"快速出口"判定
    fast = (reachable("google") and reachable("github")
            and reachable("huggingface"))
    # 摘要：每个站点一个字符，便于在报告里一眼看
    def mark(n):
        r = rows[n]
        if r["code"] == "200" and "unsupported_country" not in r["markers"]:
            return "ok"
        if "unsupported_country" in r["markers"]:
            return "region"
        if "challenge" in r["markers"]:
            return "cf"
        if r["code"].startswith("3"):
            return "redirect"
        if "blocked" in r["markers"] or r["code"] in ("403", "451"):
            return "blocked"
        return "fail"
    return {"endpoint": endpoint, "general": general, "fast": fast,
            "sites": {n: {"code": rows[n]["code"], "size": rows[n]["size"],
                          "secs": rows[n]["secs"], "verdict": mark(n),
                          "location": rows[n].get("location", ""),
                          "markers": rows[n]["markers"]} for n, _u, _t in GATE}}


# ---------------------------------------------------------------- apply
def apply_proxy(endpoint):
    """Point WinINET at an HTTP proxy endpoint ("host:port")."""
    server = f"http={endpoint};https={endpoint}"
    try:                               # 静态代理优先于 PAC，先摘掉 PAC
        k = winreg.OpenKey(K, IS, 0, winreg.KEY_ALL_ACCESS)
        try:
            winreg.DeleteValue(k, "AutoConfigURL")
        finally:
            k.Close()
    except FileNotFoundError:
        pass
    wset("ProxyServer", server)
    wset("ProxyOverride", "<local>")
    wset("ProxyEnable", 1, winreg.REG_DWORD)
    notify()
    return server


def _split(endpoint):
    host, _, port = endpoint.rpartition(":")
    return host, int(port)


async def _plain_http(endpoint, timeout=8.0):
    host, port = _split(endpoint)
    try:
        async with asyncio.timeout(timeout):
            r, w = await asyncio.open_connection(host, port)
            req = ("GET http://www.gstatic.com/generate_204 HTTP/1.1\r\n"
                   "Host: www.gstatic.com\r\nUser-Agent: Mozilla/5.0\r\n"
                   "Accept: */*\r\nConnection: close\r\n\r\n")
            w.write(req.encode())
            await w.drain()
            line = await r.readuntil(b"\r\n")
            w.close()
            return b" 204" in line
    except Exception:
        return False


def verify_applied(endpoint, timeout=8.0):
    """Prove the applied endpoint really works after the switch (HTTPS + plain HTTP)."""
    import bench
    host, port = _split(endpoint)
    r = asyncio.run(bench.probe_one({"proto": "http", "host": host, "port": port},
                                    timeout=timeout, speed=True))
    return {"ok": bool(r.get("ok") and r.get("speed_ok", True)),
            "ttfb_ms": r.get("ttfb_ms"), "speed_kbps": r.get("speed_kbps"),
            "plain_http": asyncio.run(_plain_http(endpoint)),
            "err": r.get("err", "")}


def disable_proxy():
    wset("ProxyEnable", 0, winreg.REG_DWORD)
    stop_gateway()


# ---------------------------------------------------------------- report
def render_report():
    hist = []
    if os.path.isfile(TRIALS):
        try:
            hist = json.load(open(TRIALS, encoding="utf-8"))
        except Exception:
            hist = []
    act = None
    if os.path.isfile(ACTIVE):
        try:
            act = json.load(open(ACTIVE, encoding="utf-8"))
        except Exception:
            act = None
    last = hist[-1] if hist else {"rows": [], "at": "", "secs": 0}
    rows = (act.get("rows") if act and act.get("rows") else last["rows"])
    rows = sorted(rows, key=lambda r: (-r.get("score", -9e9)))

    def fmt_speed(k):
        return f"{k:,.0f} kB/s · {k*8/1024:.2f} Mbps" if k else "—"

    def fmt_ms(v):
        return f"{v:,.0f} ms" if v else "—"

    tr = ""
    for i, r in enumerate(rows, 1):
        ok = r.get("ok_both")
        cls = "ok" if ok else "bad"
        chosen = act and act.get("chosen", {}).get("id") == r["id"]
        tr += (f"<tr class='{cls}{' chosen' if chosen else ''}'>"
               f"<td>{i}</td><td>{'★ ' if chosen else ''}{r['label']}</td>"
               f"<td>{r['proto']}</td>"
               f"<td>{fmt_ms(r.get('ttfb_ms'))}</td>"
               f"<td>{fmt_speed(r.get('speed_kbps', 0)) if ok else '失败'}</td>"
               f"<td>{'通过' if ok else (r.get('err') or '失败')[:40]}</td></tr>")
    hist_rows = ""
    for h in reversed(hist[-8:]):
        good = sum(1 for r in h["rows"] if r.get("ok_both"))
        hist_rows += (f"<tr><td>{h['at']}</td><td>{len(h['rows'])}</td><td>{good}</td>"
                      f"<td>{h['secs']}s</td></tr>")
    pool_n = 0
    try:
        pool_n = len(json.load(open(os.path.join(HERE, "pool.json"), encoding="utf-8")).get("kept", []))
    except Exception:
        pass
    cur = current_proxy()
    winner = act["chosen"] if act else None
    speed = winner.get("speed_kbps", 0) if winner else 0
    prev = (act or {}).get("baseline") or (act or {}).get("previous") or {}
    prev_txt = (f"系统代理开启 → {prev.get('sys_server')}" if prev.get("sys_enabled")
                else "系统代理关闭，仅迷雾通手动运行")
    geph_row = next((r for r in rows if r.get("id") == "geph-http"), None)
    geph_k = (geph_row or {}).get("speed_kbps") or 0
    geph_txt = (f"迷雾通本轮实测 {fmt_speed(geph_k)}"
                if geph_row and geph_row.get("ok_both") else "迷雾通本轮未通过校验")
    ratio = (speed / geph_k) if (geph_k and speed and winner and winner.get("id") != "geph-http") else 0
    ratio_txt = f"，选用项约为迷雾通的 {ratio:.1f}×" if ratio else ""
    ver = (act or {}).get("verify") or {}
    up_k = ver.get("upload_kbps") or 0
    up_txt = fmt_speed(up_k) if up_k else "未测"
    ver_txt = ("复验通过" if ver.get("ok") else "复验失败") if ver else "未复验"
    ver_note = (f"{act.get('endpoint')} · {fmt_ms(ver.get('ttfb_ms'))} · "
                f"{fmt_speed(ver.get('speed_kbps') or 0)} · 纯HTTP "
                f"{'通过' if ver.get('plain_http') else '受限'}"
                if act and act.get("endpoint") else "—")

    # ---- 分流与站点闸门 ----
    mode = (act or {}).get("mode") or ""
    gen_ep = (act or {}).get("general") or (act or {}).get("endpoint") or "—"
    fast_ep = (act or {}).get("fast") or gen_ep
    gates = (act or {}).get("gates") or []
    GATE_NAMES = ["chatgpt", "chatgpt_api", "claude", "kaggle", "google", "github",
                  "huggingface"]
    gate_tbl = ""
    for g in gates:
        cells = ""
        for n in GATE_NAMES:
            s = (g.get("sites") or {}).get(n) or {}
            v = s.get("verdict", "?")
            cls = {"ok": "g-ok", "cf": "g-cf", "region": "g-cf", "redirect": "g-cf"}.get(v, "g-bad")
            cells += f"<td class='{cls}'>{v}<span class='c'>{s.get('code','')}</span></td>"
        tag = ("通用" if g.get("general") else "") + ("/快速" if g.get("fast") else "")
        gate_tbl += f"<tr><td>{g['endpoint']}</td><td>{tag or '—'}</td>{cells}</tr>"
    if not gate_tbl:
        gate_tbl = "<tr><td colspan='9' class='note'>本次未跑站点闸门</td></tr>"

    bc = {}
    bpath = os.path.join(HERE, "edge_check.json")
    if os.path.isfile(bpath):
        try:
            bc = json.load(open(bpath, encoding="utf-8"))
        except Exception:
            bc = {}
    brows = bc.get("rows") or {}
    b_ok = sum(1 for r in brows.values() if r.get("status") == 200)
    browser_tbl = ""
    LAB = {"cloudflare_trace": "出口探测", "chatgpt": "ChatGPT 主页",
           "chatgpt_login": "OpenAI 登录页", "claude": "Claude", "gemini": "Gemini",
           "google": "Google", "youtube": "YouTube", "github": "GitHub",
           "huggingface": "Hugging Face", "x": "X / Twitter",
           "wikipedia": "Wikipedia", "kaggle": "Kaggle"}
    for k, r in brows.items():
        ok = r.get("status") == 200
        browser_tbl += (f"<tr><td>{LAB.get(k, k)}</td>"
                        f"<td class='{'g-ok' if ok else 'g-bad'}'>{r.get('status') or '—'}</td>"
                        f"<td>{r.get('secs')}s</td>"
                        f"<td>{(r.get('title') or r.get('text') or r.get('err') or '')[:60]}</td></tr>")
    if not browser_tbl:
        browser_tbl = "<tr><td colspan='4' class='note'>未跑真机浏览器实测</td></tr>"
    mode_txt = ("分流 PAC（按站点选出口）" if mode == "pac" else
                "单一代理（所有站点同一个出口）" if mode == "static" else "—")
    cg = None
    for g in gates:
        if g.get("endpoint") == gen_ep:
            cg = (g.get("sites") or {}).get("chatgpt")
    if cg and cg.get("verdict") == "ok":
        cg_txt = "✅ 通过"
        cg_note = f"HTTP {cg.get('code')} · {int(cg.get('size') or 0)//1024} KB · {cg.get('secs')}s"
    elif cg:
        cg_txt = "❌ " + str(cg.get("verdict"))
        cg_note = f"HTTP {cg.get('code')} · {','.join(cg.get('markers') or [])}"
    else:
        cg_txt, cg_note = "未测", "本次未跑闸门"

    html = f"""<!doctype html><meta charset="utf-8">
<title>代理实测与选用报告</title>
<style>
:root{{--bg:#0b0f14;--card:#121924;--line:#1f2b3a;--tx:#e6edf6;--dim:#8aa0b8;--ok:#3ddc97;--bad:#ff6b6b;--acc:#5aa9ff}}
*{{box-sizing:border-box}} body{{margin:0;background:linear-gradient(180deg,#0b0f14,#0d141d 60%);color:var(--tx);
font:14px/1.6 "Segoe UI","Microsoft YaHei",system-ui,sans-serif;padding:28px}}
h1{{font-size:22px;margin:0 0 4px}} h2{{font-size:15px;color:var(--dim);font-weight:600;margin:26px 0 10px;letter-spacing:.03em}}
.wrap{{max-width:1100px;margin:0 auto}}
.hero{{display:grid;grid-template-columns:1.4fr 1fr 1fr 1fr;gap:14px;margin-top:18px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 18px}}
.card .k{{color:var(--dim);font-size:12px;letter-spacing:.06em;text-transform:uppercase}}
.card .v{{font-size:20px;font-weight:650;margin-top:6px}}
.win{{border-color:#2b6a52;box-shadow:0 0 0 1px #234d3d inset}}
.win .v{{color:var(--ok)}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:14px;overflow:hidden}}
th,td{{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);font-size:13px}}
th{{color:var(--dim);font-weight:600;background:#0f1620}}
tr.bad td{{color:#a9606a}} tr.chosen td{{background:#12261f}}
td.g-ok{{color:#3ddc97;font-weight:600}} td.g-bad{{color:#ff6b6b}}
td.g-cf{{color:#e8c268}} td .c{{color:#6f849c;font-size:11px;margin-left:4px}}
.note{{color:var(--dim);font-size:12px;margin-top:10px}}
.badge{{display:inline-block;padding:1px 8px;border-radius:99px;background:#16324a;color:#8fc6ff;font-size:12px;margin-left:6px}}
</style>
<div class="wrap">
<h1>代理实测与选用报告</h1>
<div class="note">生成时间 {act['at'] if act else last['at']} · 测试目标 gstatic/generate_204 + speed.cloudflare.com 1&nbsp;MB ·
一轮 {last['secs']}s · 公开池存活 {pool_n}</div>
<div class="hero">
  <div class="card win"><div class="k">当前模式</div><div class="v">{mode_txt}</div>
    <div class="note">ChatGPT / Claude → {gen_ep}<br>Google / GitHub / HF → {fast_ep}<br>Reddit → 香港线 2086<br>Kaggle → 直连</div></div>
  <div class="card"><div class="k">ChatGPT 闸门</div><div class="v">{cg_txt}</div>
    <div class="note">{cg_note}</div></div>
  <div class="card"><div class="k">最快下载</div><div class="v">{fmt_speed(speed)}</div>
    <div class="note">{fmt_ms(winner.get('ttfb_ms') if winner else None)} 首字节 · 上传 {up_txt}</div></div>
  <div class="card"><div class="k">真机浏览器</div><div class="v">{b_ok}/{len(brows) if brows else 0} 站点 200</div>
    <div class="note">{bc.get('browser','') or '未测'} · {bc.get('at','') or '—'}</div></div>
</div>
<div class="note" style="margin-top:14px">改造前：{prev_txt}。{geph_txt}{ratio_txt}。启用后复验：{ver_txt}（{ver_note}）。</div>
<h2>站点闸门：同一个代理逐站实测</h2>
<table><tr><th>代理出口</th><th>判定</th><th>ChatGPT</th><th>会话API</th><th>Claude</th><th>Kaggle</th><th>Google</th><th>GitHub</th><th>HF</th></tr>{gate_tbl}</table>
<div class="note">要当"通用出口"必须 ChatGPT 返回 200 且页面 &gt;50KB；要当"快速出口"必须 Google/GitHub/HF 全可达（Kaggle 走直连，不参与判定）。
region = 地区被封，cf = Cloudflare 人机挑战（浏览器通常能过），blocked = 源站拒绝该出口 IP。</div>
<h2>真机浏览器实测（Edge 走系统代理/PAC，非 curl）</h2>
<table><tr><th>站点</th><th>状态</th><th>耗时</th><th>页面标题</th></tr>{browser_tbl}</table>
<h2>本轮尝试的全部候选</h2>
<table><tr><th>#</th><th>候选</th><th>协议</th><th>延迟</th><th>下载</th><th>结果</th></tr>{tr}</table>
<h2>历史试验</h2>
<table><tr><th>时间(UTC)</th><th>候选数</th><th>可用</th><th>耗时</th></tr>{hist_rows}</table>
<div class="note">判据：同一轮里必须通过 204 检查且 1&nbsp;MB 下载成功；按 速度×本地加成 − 延迟惩罚 排序，取第一。
公开池来自 GitHub 公开列表（TheSpeedX / monosans / vakhov / proxifly / jetkai 等），每轮重测，失效即淘汰。</div>
</div>"""
    with io.open(REPORT, "w", encoding="utf-8", newline="\n") as f:
        f.write(html)
    return REPORT


# ---------------------------------------------------------------- commands
def cmd_status():
    cur = current_proxy()
    if cur.get("pac"):
        print("系统代理: PAC 自动分流（已生效，ProxyEnable=0 是正常的）")
    else:
        print("系统代理:", "开启" if cur["enabled"] else "关闭")
    print("  ProxyServer:", cur["server"] or "(空)")
    print("  PAC:", cur["pac"] or "(空)")
    for p, name in ((9910, "Geph HTTP"), (9909, "Geph SOCKS5"), (8086, "warp-plus"),
                    (2080, "sing-box"), (9090, "sing-box API"),
                    (2101, "固定 general"), (2103, "固定 fast"), (2090, "CLI mixed"),
                    (2086, "香港线 reddit")):
        print(f"  127.0.0.1:{p:<5d} {name:14s}", "LISTEN" if listen_ok(p) else "-")
    if os.path.isfile(PINNED):
        try:
            pn = json.load(open(PINNED, encoding="utf-8"))
            print("分流:", f"general={pn.get('general')} fast={pn.get('fast')} "
                          f"cli={pn.get('cli')} hk=127.0.0.1:2086  kaggle=直连")
        except Exception:
            pass
    if os.path.isfile(ACTIVE):
        a = json.load(open(ACTIVE, encoding="utf-8"))
        print("上次选定:", a["chosen"]["label"], "|", a.get("at"))
    return 0


def ensure_node():
    """Bring up the best previously-measured subscription node (HTTP inbound 2086)."""
    if listen_ok(2086):
        return True
    bn = best_node()
    if not bn:
        return False
    print(f"starting sing-box node {bn['proto']} {bn['server']}:{bn['port']}", flush=True)
    return start_singbox_node(bn["uri"])


def cmd_select(force_local=False):
    if not listen_ok(9910):
        print("bootstrap Geph not running, starting ...")
        start_geph()
    if not listen_ok(2086) and best_node():
        print("  node:", "up" if ensure_node() else "failed")
    best, rows = select(force_local=force_local)
    if not best:
        print("NO usable proxy found")
        return 1
    dead = prune(rows)
    with io.open(ACTIVE, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "chosen": best, "rows": rows, "dead_summary": dead},
                  f, indent=1, ensure_ascii=False)
    print(f"WINNER {best['label']}  ttfb={best.get('ttfb_ms')}ms  "
          f"speed={best.get('speed_kbps')}kB/s score={best['score']}")
    for r in sorted(rows, key=lambda r: -r["score"])[:8]:
        print(f"  {r['score']:>9.1f}  {r['label'][:44]:44s} "
              f"{r.get('ttfb_ms', 0):>6.0f}ms {r.get('speed_kbps', 0):>9.1f}kB/s "
              f"{'OK' if r['ok_both'] else 'FAIL ' + (r.get('err') or '')[:30]}")
    return 0


def cmd_enable(show=False, force_local=False, reuse=False):
    import pacroute
    if not listen_ok(9910):
        start_geph()
    if not listen_ok(2086) and best_node():
        ensure_node()
    prev = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sys_enabled": bool(current_proxy()["enabled"]),
            "sys_server": current_proxy()["server"],
            "geph_running": listen_ok(9910)}
    base = prev
    if os.path.isfile(ACTIVE):              # 保留第一次观察到的原始状态
        try:
            old = json.load(open(ACTIVE, encoding="utf-8"))
            base = old.get("baseline") or prev
        except Exception:
            pass
    if reuse and os.path.isfile(ACTIVE):
        a = json.load(open(ACTIVE, encoding="utf-8"))
        best, rows = a["chosen"], a["rows"]
        print(f"reusing last winner: {best['label']}")
    else:
        best, rows = select(force_local=force_local)
    if not best:
        print("no usable proxy; leaving system proxy unchanged")
        return 1
    dead = prune(rows)
    endpoint = local_endpoint(best)
    if endpoint is None:
        print("could not expose the winner; falling back to Geph HTTP")
        endpoint = "127.0.0.1:9910" if listen_ok(9910) else None
        if endpoint is None:
            print("no endpoint available; system proxy unchanged")
            return 1

    # ---- 站点闸门：速度最快的代理未必能打开 ChatGPT，必须实测 ----
    # 深测选出的固定出口优先（bestroute.py 装好的那一对）
    gate_eps = pinned_eps()
    for ep in [endpoint, "127.0.0.1:9910", "127.0.0.1:2086"]:
        if ep not in gate_eps and listen_ok(int(ep.rsplit(":", 1)[1])):
            gate_eps.append(ep)
    gates = []
    for ep in gate_eps:
        print(f"  站点闸门 {ep} ...", flush=True)
        g = gate_one(ep)
        gates.append(g)
        print("    " + "  ".join(f"{k}:{v['verdict']}" for k, v in g["sites"].items()),
              flush=True)

    pp = pinned_pair()

    def pick(want, prefer=None):
        """Prefer the deep-tested pinned endpoint for this role, then any local
        one (stays up), then the speed-winner order."""
        ok = [g for g in gates if g[want]]
        if not ok:
            return None
        if prefer:
            for g in ok:
                if g["endpoint"] == prefer:
                    return g
        local = [g for g in ok if g["endpoint"].startswith("127.0.0.1")]
        return (local or ok)[0]

    g_general = pick("general", pp.get("general"))
    g_fast = pick("fast", pp.get("fast"))
    general_ep = g_general["endpoint"] if g_general else endpoint
    fast_ep = g_fast["endpoint"] if g_fast else general_ep

    if general_ep == fast_ep:
        server = apply_proxy(general_ep)
        try:
            pacroute.clear_pac()
        except Exception:
            pass
        mode = "static"
        pac_info = {"url": "", "general": general_ep, "fast": fast_ep}
        ver = verify_applied(general_ep)
    else:
        pac_info = pacroute.apply_pac(general_ep, fast_ep)
        if not pac_info.get("ok"):
            print("PAC 起不来，退回单代理:", pac_info.get("err"))
            server = apply_proxy(general_ep)
            mode = "static"
            general_ep = fast_ep = general_ep
            ver = verify_applied(general_ep)
        else:
            server = "PAC " + pac_info["url"]
            mode = "pac"
            vg = verify_applied(general_ep)
            vf = verify_applied(fast_ep) if fast_ep != general_ep else vg
            ver = {"ok": bool(vg["ok"] and vf["ok"]), "ttfb_ms": vg.get("ttfb_ms"),
                   "speed_kbps": vg.get("speed_kbps"),
                   "plain_http": vg.get("plain_http"), "err": vg.get("err", ""),
                   "fast": {"endpoint": fast_ep, "ttfb_ms": vf.get("ttfb_ms"),
                            "speed_kbps": vf.get("speed_kbps"), "ok": vf.get("ok")}}

    with io.open(ACTIVE, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "chosen": best, "rows": rows, "applied": server, "dead_summary": dead,
                   "previous": prev, "baseline": base, "endpoint": general_ep,
                   "verify": ver, "mode": mode, "pac": pac_info,
                   "general": general_ep, "fast": fast_ep,
                   "gates": gates},
                  f, indent=1, ensure_ascii=False)
    p = render_report()
    print(f"[OK] 已启用（{mode}）")
    print(f"     ChatGPT/Claude 出口  {general_ep}   "
          f"{'✅ 闸门通过' if g_general else '❌ 闸门未过（全部代理都打不开）'}")
    print(f"     Google/GitHub/HF 出口 {fast_ep}   "
          f"{'✅ 闸门通过' if g_fast else '❌ 闸门未过'}")
    print(f"     Kaggle 走直连（Kaggle 的 WAF 拒绝这些代理出口）")
    print(f"     启用后复验 {'通过' if ver['ok'] else '失败 ' + str(ver.get('err'))[:40]}"
          f" | {ver.get('ttfb_ms')} ms | {ver.get('speed_kbps')} kB/s")
    if mode == "pac":
        print(f"     WinINET AutoConfigURL = {pac_info['url']}  (ProxyEnable=0)")
    else:
        print(f"     WinINET ProxyServer = {server}")
    print(f"     报告: {p}")
    if show:
        os.startfile(p)
    return 0


def cmd_disable():
    disable_proxy()
    try:
        import pacroute
        pacroute.clear_pac()
    except Exception:
        pass
    # 固定出口进程故意不杀：它只监听 127.0.0.1，撤掉 PAC 就等于全直连；
    # 留着下一次「启动代理」能秒开、且仍然用深测选出来的那批节点。
    print("[OK] 系统代理已关闭（PAC 已撤，恢复直连；后台固定出口仍在待命）")
    return 0


def cmd_verify(show=False):
    """Real-browser proof that every site the user needs actually opens."""
    import subprocess
    r = subprocess.run([sys.executable, os.path.join(HERE, "edge_check.py"), "--show"],
                       cwd=HERE)
    p = render_report()
    print("[OK] 浏览器实测完成 ->", p)
    if show:
        os.startfile(p)
    return r.returncode


def cmd_report(show=False):
    p = render_report()
    print(p)
    if show:
        os.startfile(p)
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("status"); s.set_defaults(fn=lambda a: cmd_status())
    s = sub.add_parser("select"); s.add_argument("--force-local", action="store_true")
    s.set_defaults(fn=lambda a: cmd_select(a.force_local))
    s = sub.add_parser("enable"); s.add_argument("--show", action="store_true")
    s.add_argument("--force-local", action="store_true")
    s.add_argument("--reuse", action="store_true", help="重新应用上次的胜者，不重测")
    s.set_defaults(fn=lambda a: cmd_enable(a.show, a.force_local, a.reuse))
    s = sub.add_parser("disable"); s.set_defaults(fn=lambda a: cmd_disable())
    s = sub.add_parser("report"); s.add_argument("--show", action="store_true")
    s.set_defaults(fn=lambda a: cmd_report(a.show))
    s = sub.add_parser("verify", help="真机 Edge 逐站验证并刷新报告")
    s.add_argument("--show", action="store_true")
    s.set_defaults(fn=lambda a: cmd_verify(a.show))
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
