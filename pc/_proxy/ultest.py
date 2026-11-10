"""Re-measure upload end-to-end (the deep test's upload number was a localhost
socket-buffer artifact): spin one sing-box per candidate on 2199 and time a real
1 MB POST + a 4 MB GET through it.

  python ultest.py            # top 12 by deep download
  python ultest.py --top 16
"""
import argparse
import json
import os
import socket
import subprocess
import time

import nodes as N
import proxyctl as P

HERE = os.path.dirname(os.path.abspath(__file__))
DEEP = os.path.join(HERE, "node_deep.json")
OUT = os.path.join(HERE, "node_ul.json")
PORT = 2199
BIN = P.SING_EXE
UP = os.path.join(HERE, "_up1.bin")
CFG = os.path.join(HERE, "_ultest_cfg.json")


def log(*a):
    print(*a, flush=True)


def lok(port, t=0.3):
    s = socket.socket()
    s.settimeout(t)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def ensure_payload():
    if os.path.exists(UP) and os.path.getsize(UP) >= 1000000:
        return
    with open(UP, "wb") as f:
        f.write(os.urandom(1000000))


def one(rec, timeout=45):
    ob, meta = N.parse_uri(rec["uri"])
    if not ob:
        return {"err": "parse"}
    ob["tag"] = "x"
    cfg = {"log": {"level": "error"},
           "inbounds": [{"type": "http", "tag": "in", "listen": "127.0.0.1",
                         "listen_port": PORT}],
           "outbounds": [ob, {"type": "direct", "tag": "direct"}]}
    with open(CFG, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f)
    chk = subprocess.run([BIN, "check", "-c", CFG], capture_output=True, text=True,
                         creationflags=0x08000000)
    if chk.returncode != 0:
        return {"err": "check:" + ((chk.stderr or chk.stdout or "").strip()[-80:])}
    p = subprocess.Popen([BIN, "run", "-c", CFG], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, creationflags=0x08000000)
    try:
        for _ in range(40):
            if lok(PORT):
                break
            if p.poll() is not None:
                return {"err": "exited"}
            time.sleep(0.2)
        else:
            return {"err": "no-listen"}
        up = subprocess.run(
            ["curl", "-s", "-o", "NUL", "-x", f"http://127.0.0.1:{PORT}",
             "--ssl-no-revoke", "-m", str(timeout),
             "-w", "%{http_code} %{time_total} %{speed_upload}",
             "-X", "POST", "--data-binary", "@" + UP,
             "https://speed.cloudflare.com/__up"],
            capture_output=True, text=True, timeout=timeout + 15,
            creationflags=0x08000000)
        parts = (up.stdout or "").split()
        up_code = parts[0] if parts else "?"
        up_s = float(parts[1]) if len(parts) > 1 else 0.0
        up_kbps = round(1000000 / 1024 / up_s, 1) if up_s > 0 else 0.0
        dl = subprocess.run(
            ["curl", "-s", "-o", "NUL", "-x", f"http://127.0.0.1:{PORT}",
             "--ssl-no-revoke", "-m", str(timeout),
             "-w", "%{http_code} %{speed_download} %{time_starttransfer}",
             "https://speed.cloudflare.com/__down?bytes=4000000"],
            capture_output=True, text=True, timeout=timeout + 15,
            creationflags=0x08000000)
        dp = (dl.stdout or "").split()
        return {"up_code": up_code, "up_s": round(up_s, 2), "up_kbps": up_kbps,
                "dl_code": dp[0] if dp else "?",
                "dl_kbps": round(float(dp[1]) / 1024, 1) if len(dp) > 1 else 0.0,
                "ttfb_ms": round(float(dp[2]) * 1000) if len(dp) > 2 else None}
    finally:
        p.terminate()
        try:
            p.wait(timeout=6)
        except Exception:
            subprocess.run(["taskkill", "/PID", str(p.pid), "/F"],
                           capture_output=True, creationflags=0x08000000)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=12)
    ap.add_argument("--min-dl", type=float, default=600)
    args = ap.parse_args()
    ensure_payload()
    rows = json.load(open(DEEP, encoding="utf-8"))["rows"]
    cand = [r for r in rows if r.get("chatgpt_ok") and (r.get("dl_kbps") or 0) >= args.min_dl]
    cand.sort(key=lambda r: -(r.get("dl_kbps") or 0))
    log(f"candidates {len(cand)}; testing {min(args.top, len(cand))}")
    out = []
    for i, r in enumerate(cand[:args.top]):
        m = one(r)
        rec = dict(r, **m)
        rec["real_score"] = round((m.get("dl_kbps") or 0) + 1.5 * (m.get("up_kbps") or 0), 1)
        out.append(rec)
        log(f"  {i+1:2d} {r.get('loc','??'):2s} {r['server']}:{r['port']:<6} "
            f"up={m.get('up_kbps')}kB/s (code {m.get('up_code')}, {m.get('up_s')}s) "
            f"dl={m.get('dl_kbps')}kB/s ttfb={m.get('ttfb_ms')}ms {m.get('err','')}")
    out.sort(key=lambda r: -r["real_score"])
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "rows": out}, f, indent=1, ensure_ascii=False)
    log("\n== ranked by real dl + 1.5*up ==")
    for r in out[:8]:
        log(f"  {r.get('loc','??'):2s} {r['proto']:5s} {r['server']}:{r['port']:<6} "
            f"dl={r.get('dl_kbps')} up={r.get('up_kbps')} score={r['real_score']}")
    log("saved " + OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
