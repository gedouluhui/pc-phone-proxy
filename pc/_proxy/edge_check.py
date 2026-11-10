# -*- coding: utf-8 -*-
"""End-to-end check in a real browser (Edge + CDP, headless, own profile).

Proves what the user will actually see: which sites load, which route they take,
and what the exit looks like -- through the *system* proxy/PAC settings, not a
curl override.

Usage:  python edge_check.py [--show] [--keep]
"""
import io
import json
import os
import subprocess
import sys
import time
import urllib.request

import websocket  # websocket-client

HERE = os.path.dirname(os.path.abspath(__file__))
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
PROFILE = os.path.join(HERE, "edge_profile")
PORT = 9333
OUT = os.path.join(HERE, "edge_check.json")

URLS = [
    ("cloudflare_trace", "https://www.cloudflare.com/cdn-cgi/trace", 20),
    ("chatgpt", "https://chatgpt.com/", 30),
    ("chatgpt_login", "https://auth.openai.com/log-in", 30),
    ("claude", "https://claude.ai/", 30),
    ("gemini", "https://gemini.google.com/", 30),
    ("google", "https://www.google.com/", 25),
    ("youtube", "https://www.youtube.com/", 30),
    ("github", "https://github.com/", 25),
    ("huggingface", "https://huggingface.co/", 25),
    ("x", "https://x.com/", 30),
    ("wikipedia", "https://en.wikipedia.org/wiki/Main_Page", 25),
    ("kaggle", "https://www.kaggle.com/", 25),
]

JS_PROBE = r"""
(function(){
  var t = (document.title||'').slice(0,120);
  var b = document.body ? (document.body.innerText||'').slice(0,300) : '';
  return JSON.stringify({title:t, url:location.href, text:b});
})()
"""


class CDP:
    def __init__(self, ws_url):
        self.ws = websocket.create_connection(ws_url, timeout=40,
                                              suppress_origin=True)
        self.n = 0
        self.queue = []

    def send(self, method, params=None, session=None, timeout=45):
        self.n += 1
        mid = self.n
        msg = {"id": mid, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        self.ws.send(json.dumps(msg))
        end = time.time() + timeout
        while time.time() < end:
            self.ws.settimeout(max(0.2, end - time.time()))
            try:
                raw = self.ws.recv()
            except Exception:
                break
            try:
                obj = json.loads(raw)
            except Exception:
                continue
            if obj.get("id") == mid:
                return obj
            if "method" in obj:            # keep, don't eat CDP events
                self.queue.append(obj)
        return {"error": {"message": "timeout " + method}}

    def pump(self, seconds):
        """Receive events for a while, keeping them in the queue."""
        end = time.time() + seconds
        while time.time() < end:
            self.ws.settimeout(max(0.1, end - time.time()))
            try:
                obj = json.loads(self.ws.recv())
            except Exception:
                break
            if "method" in obj:
                self.queue.append(obj)


def http_json(path, method="GET"):
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (PORT, path),
                                 method=method)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def launch(headless=True):
    if not os.path.isfile(EDGE):
        raise SystemExit("Edge not found: " + EDGE)
    args = [EDGE,
            "--remote-debugging-port=%d" % PORT,
            "--remote-allow-origins=*",
            "--user-data-dir=%s" % PROFILE,
            "--no-first-run", "--no-default-browser-check",
            "--disable-sync", "--no-service-autorun",
            "--window-position=-2400,-2400", "--window-size=1280,900"]
    if headless:
        args.append("--headless=new")
    p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            v = http_json("/json/version")
            return p, v
        except Exception:
            if p.poll() is not None:
                raise SystemExit("Edge exited early rc=%s" % p.returncode)
            time.sleep(0.2)
    raise SystemExit("CDP did not come up")


def probe(cdp, url, budget):
    tgt = cdp.send("Target.createTarget", {"url": "about:blank"})
    sid = tgt["result"]["targetId"]
    att = cdp.send("Target.attachToTarget", {"targetId": sid, "flatten": True})
    sess = att["result"]["sessionId"]
    cdp.send("Network.enable", {}, session=sess)
    cdp.send("Page.enable", {}, session=sess)
    t0 = time.time()
    cdp.send("Page.navigate", {"url": url}, session=sess, timeout=budget)
    status, mime, ip, err, main_url = None, None, None, "", ""
    deadline = t0 + budget
    last_title, stable, info = "", 0, {}
    while time.time() < deadline:
        cdp.pump(0.8)
        while cdp.queue:
            ev = cdp.queue.pop(0)
            if ev.get("sessionId") != sess:
                continue
            m = ev.get("method")
            if m == "Network.responseReceived":
                p = ev["params"]
                r = p["response"]
                if p.get("type") == "Document":
                    status, mime = r.get("status"), r.get("mimeType")
                    ip = r.get("remoteIPAddress") or ip
                    main_url = r.get("url", "")
            elif m == "Network.loadingFailed":
                if ev["params"].get("type") == "Document":
                    err = ev["params"].get("errorText", "")
        res = cdp.send("Runtime.evaluate", {"expression": JS_PROBE,
                                            "returnByValue": True,
                                            "awaitPromise": False}, session=sess)
        try:
            info = json.loads(res["result"]["result"]["value"])
        except Exception:
            info = {}
        title = info.get("title", "") or ""
        if title and title == last_title:
            stable += 1
        else:
            stable = 0
        last_title = title
        challenge = any(k in title for k in ("请稍候", "Just a moment", "Attention Required"))
        if title and stable >= 2 and not challenge:
            break
        if title and challenge and time.time() - t0 > budget * 0.7:
            break
    cdp.send("Target.closeTarget", {"targetId": sid})
    return {"url": url, "final_url": info.get("url", ""), "secs": round(time.time() - t0, 2),
            "status": status, "mime": mime, "remote_ip": ip,
            "main_url": main_url, "err": err, "title": info.get("title", ""),
            "text": " ".join((info.get("text") or "").split())[:220]}


def main(argv):
    headless = "--show" not in argv
    proc, ver = launch(headless=headless)
    print("Edge", ver.get("Browser"), "headless" if headless else "visible", flush=True)
    cdp = CDP(ver["webSocketDebuggerUrl"])
    # the PAC endpoint itself must be reachable
    try:
        pac = urllib.request.urlopen("http://127.0.0.1:8891/proxy.pac", timeout=5).read(400)
        print("PAC served:", pac.decode("utf-8", "replace").splitlines()[0], flush=True)
    except Exception as e:
        print("PAC NOT served:", e, flush=True)
    rows = {}
    for name, url, budget in URLS:
        r = probe(cdp, url, budget)
        rows[name] = r
        print("%-16s status=%-4s %6ss ip=%-16s %s" %
              (name, r["status"], r["secs"], (r["remote_ip"] or "-")[:16],
               (r["title"] or r["err"] or r["text"][:60])[:70]), flush=True)
    io.open(OUT, "w", encoding="utf-8").write(
        json.dumps({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "browser": ver.get("Browser"), "headless": headless,
                    "rows": rows}, ensure_ascii=False, indent=1))
    print("saved", OUT)
    try:
        cdp.ws.close()
    except Exception:
        pass
    if "--keep" not in argv:
        proc.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
