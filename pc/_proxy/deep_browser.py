# -*- coding: utf-8 -*-
"""Real-browser deep check: does ChatGPT actually work end to end (assets, JS,
login form), and do platform/api endpoints answer in a browser context?

  python deep_browser.py            # headless
  python deep_browser.py --show
"""
import json
import time

import edge_check as E

JS = r"""
(function(){
  var t=(document.title||'').slice(0,120);
  var b=document.body?(document.body.innerText||'').slice(0,600):'';
  var imgs=document.images.length;
  var bad=[].slice.call(document.images).filter(function(i){return i.complete&&i.naturalWidth===0}).length;
  var sel='input[type=email],input[name=email],input[name=username],input[type=password]';
  return JSON.stringify({title:t,url:location.href,text:b,imgs:imgs,bad:bad,
    has_input: !!document.querySelector(sel),
    buttons: [].slice.call(document.querySelectorAll('button,a')).map(function(e){
      return (e.innerText||'').trim().slice(0,24)}).filter(Boolean).slice(0,25)});
})()
"""


def nav(cdp, url, sess, budget=40, settle=1.0):
    cdp.send("Network.enable", {}, session=sess)
    cdp.send("Page.enable", {}, session=sess)
    t0 = time.time()
    cdp.send("Page.navigate", {"url": url}, session=sess, timeout=budget)
    status = None
    fails, ok_bytes, docs = [], 0, ""
    reqs = {}
    while time.time() - t0 < budget:
        cdp.pump(1.0)
        while cdp.queue:
            ev = cdp.queue.pop(0)
            if ev.get("sessionId") != sess:
                continue
            m = ev.get("method")
            p = ev.get("params") or {}
            if m == "Network.responseReceived":
                r = p.get("response") or {}
                if p.get("type") == "Document":
                    status = r.get("status")
                    docs = r.get("url", "")
                reqs[p.get("requestId")] = r.get("url", "")
            elif m == "Network.loadingFinished":
                ok_bytes += p.get("encodedDataLength") or 0
            elif m == "Network.loadingFailed":
                u = reqs.get(p.get("requestId"), "?")
                fails.append((p.get("errorText", ""), u[:90]))
        res = cdp.send("Runtime.evaluate", {"expression": JS, "returnByValue": True},
                       session=sess)
        try:
            info = json.loads(res["result"]["result"]["value"])
        except Exception:
            info = {}
        txt = ((info.get("text") or "") + (info.get("title") or ""))
        if time.time() - t0 > 12 and (info.get("has_input") or "登录" in txt or
                                      "Log in" in txt or "Sign up" in txt):
            break
    time.sleep(settle)
    return {"status": status, "docs": docs, "secs": round(time.time() - t0, 1),
            "bytes_kb": round(ok_bytes / 1024), "fails": fails[:12],
            "fail_n": len(fails), "info": info}


def click_login(cdp, sess):
    js = r"""
    (function(){
      var els=[].slice.call(document.querySelectorAll('button,a'));
      for (var i=0;i<els.length;i++){
        var t=(els[i].innerText||'').trim().toLowerCase();
        if (t==='log in'||t==='login'||t==='登录'||t==='登入'||t==='sign up'){
          els[i].click(); return t;
        }
      }
      return '';
    })()
    """
    r = cdp.send("Runtime.evaluate", {"expression": js, "returnByValue": True}, session=sess)
    return (r.get("result", {}).get("result", {}) or {}).get("value", "")


def main(argv):
    import sys
    headless = "--show" not in argv
    proc, ver = E.launch(headless=headless)
    print("Edge", ver.get("Browser"), "headless" if headless else "visible", flush=True)
    cdp = E.CDP(ver["webSocketDebuggerUrl"])

    def newtab():
        t = cdp.send("Target.createTarget", {"url": "about:blank"})
        tid = t["result"]["targetId"]
        a = cdp.send("Target.attachToTarget", {"targetId": tid, "flatten": True})
        return a["result"]["sessionId"]

    try:
        s = newtab()
        r = nav(cdp, "https://chatgpt.com/", s, 45)
        print(f"chatgpt      status={r['status']} {r['secs']}s {r['bytes_kb']}KB "
              f"imgs={r['info'].get('imgs')} broken={r['info'].get('bad')} "
              f"fail={r['fail_n']} input={r['info'].get('has_input')}", flush=True)
        print("  title:", r["info"].get("title"), flush=True)
        print("  text :", " ".join((r["info"].get("text") or "").split())[:160], flush=True)
        for e, u in r["fails"][:6]:
            print("  fail:", e, u, flush=True)
        if not r["info"].get("has_input"):
            t = click_login(cdp, s)
            print("  clicked:", t or "(no login button found)", flush=True)
            if t:
                r2 = nav(cdp, "https://chatgpt.com/", s, 30, settle=0.5)
                time.sleep(6)
                res = cdp.send("Runtime.evaluate", {"expression": JS, "returnByValue": True},
                               session=s)
                try:
                    i2 = json.loads(res["result"]["result"]["value"])
                except Exception:
                    i2 = {}
                print("  after-login url:", i2.get("url"), flush=True)
                print("  after-login title:", i2.get("title"), flush=True)
                print("  after-login input:", i2.get("has_input"),
                      "text:", " ".join((i2.get("text") or "").split())[:140], flush=True)
        shot = cdp.send("Page.captureScreenshot", {"format": "png"}, session=s)
        d = (shot.get("result") or {}).get("data")
        if d:
            import base64
            open("chatgpt_shot.png", "wb").write(base64.b64decode(d))
            print("  shot -> chatgpt_shot.png", flush=True)

        for name, url in (("platform", "https://platform.openai.com/"),
                          ("api_models", "https://api.openai.com/v1/models"),
                          ("sora", "https://sora.chatgpt.com/")):
            s2 = newtab()
            r = nav(cdp, url, s2, 30)
            print(f"{name:10s}   status={r['status']} {r['secs']}s {r['bytes_kb']}KB "
                  f"title={r['info'].get('title')!r}", flush=True)
            print("  text:", " ".join((r["info"].get("text") or "").split())[:140], flush=True)
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv))
