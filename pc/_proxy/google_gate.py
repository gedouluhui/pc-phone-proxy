# -*- coding: utf-8 -*-
"""Google 地区闸门：判断每个出口在 Google 眼里是不是「支持地区」。

为什么需要它（2026-11-23 17:18 实测）：Gemini 显示「目前不支持你所在的地区」，而
`gemini.google.com/robots.txt` 探针照样 200、cloudflare trace 说出口在 US。Google 用的是
自己的 IP 地理库（参考了真实用户位置）——公开源里大量节点主要被伊朗用户在用，Google
直接把这些出口判成 IR：同一时刻 support.google.com 跳到 `hl=zh-Hans-IR`，NotebookLM
跳到 `notebook.google/?location=unsupported`。所以只能问 Google 本人：

  * https://notebooklm.google.com/           最终 URL 含 `unsupported`            -> bad
  * https://aistudio.google.com/app/prompts/new_chat  最终 URL 含 `available-regions`/`unsupported` -> bad

两项都能访问且都没被拒 -> ok；访问不了 -> err（节点本身不通，交给其它探针）。

每个节点单独起一个只有该出站的 sing-box（mixed 入站，随机端口），urllib 经它访问。
sing-box.exe 在 TUN 规则里直连，所以测到的就是该节点自己的出口。

结果写 google_gate.json：{"server:port": {"verdict": ok|bad|err, "at": epoch}}，
tun_mode.build_config 用它筛 grp-google 成员。

CLI：python google_gate.py --tun    测 singbox_tun.json 里全部 g* 出口
"""
import io
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "bin", "sing-box.exe")
STORE = os.path.join(HERE, "google_gate.json")
TUN_CFG = os.path.join(HERE, "singbox_tun.json")
FRESH = 6 * 3600          # 结论 6 小时内有效（Google 的地理库变化慢，但节点会换 IP）
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0 Safari/537.36")
PROBES = (
    ("https://notebooklm.google.com/", ("unsupported",)),
    ("https://aistudio.google.com/app/prompts/new_chat", ("available-regions", "unsupported")),
)


def node_key(ob):
    return "%s:%s" % (str((ob or {}).get("server") or "").lower(), (ob or {}).get("server_port"))


def classify(results):
    """results: [(final_url or None, bad_markers_hit: bool), ...] -> ok / bad / err（纯函数）。"""
    if any(hit for _, hit in results):
        return "bad"
    if results and all(u for u, _ in results):
        return "ok"
    return "err"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_port(port, proc, secs=8.0):
    t0 = time.time()
    while time.time() - t0 < secs:
        if proc.poll() is not None:
            return False
        s = socket.socket()
        s.settimeout(0.3)
        try:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        finally:
            s.close()
        time.sleep(0.2)
    return False


def _fetch_final(url, port, timeout):
    op = urllib.request.build_opener(urllib.request.ProxyHandler(
        {"http": "http://127.0.0.1:%d" % port, "https": "http://127.0.0.1:%d" % port}))
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept-Language": "en-US,en;q=0.9"})
    try:
        with op.open(req, timeout=timeout) as r:
            r.read(2048)
            return r.geturl()
    except urllib.error.HTTPError as e:
        # 4xx/5xx 也说明链路是通的；最终 URL 照样能看出是不是被跳到「不支持」页
        return e.geturl() or url
    except Exception:
        return None


def check_outbound(ob, timeout=12.0):
    """单个出站 -> ok / bad / err。不抛异常。"""
    if not os.path.isfile(BIN):
        return "err"
    ob = dict(ob)
    ob["tag"] = "node"
    port = _free_port()
    path = os.path.join(HERE, "logs", "gate_%d.json" % port)
    cfg = {"log": {"level": "error"},
           "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": port}],
           "outbounds": [ob, {"type": "direct", "tag": "direct"}],
           "route": {"final": "node"}}
    proc = None
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with io.open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        proc = subprocess.Popen([BIN, "run", "-c", path], cwd=HERE, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                                creationflags=0x08000000)
        if not _wait_port(port, proc):
            return "err"
        results = []
        for url, marks in PROBES:
            final = _fetch_final(url, port, timeout)
            hit = bool(final) and any(m in final.lower() for m in marks)
            results.append((final, hit))
            if hit:
                break
        return classify(results)
    except Exception:
        return "err"
    finally:
        if proc is not None:
            try:
                proc.kill()
                proc.wait(3)
            except Exception:
                pass
        try:
            os.remove(path)
        except OSError:
            pass


def load(now=None):
    """{key: verdict}，只返回 FRESH 内的结论。"""
    now = now or time.time()
    try:
        with io.open(STORE, encoding="utf-8") as f:
            raw = json.load(f) or {}
    except Exception:
        return {}
    return {k: v.get("verdict") for k, v in raw.items()
            if isinstance(v, dict) and now - float(v.get("at") or 0) <= FRESH}


def save(verdicts, now=None):
    now = now or time.time()
    try:
        with io.open(STORE, encoding="utf-8") as f:
            raw = json.load(f) or {}
    except Exception:
        raw = {}
    for k, v in verdicts.items():
        if v in ("ok", "bad"):           # err 不覆盖已有结论：节点一时不通不代表地区变了
            raw[k] = {"verdict": v, "at": now}
    # 只留最近 3 天，避免无限增长
    raw = {k: v for k, v in raw.items() if now - float(v.get("at") or 0) <= 3 * 86400}
    tmp = STORE + ".tmp"
    with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(raw, f, ensure_ascii=False, indent=1)
    os.replace(tmp, STORE)


def check_many(outbounds, conc=4, log=print):
    """[(tag, ob)] -> {key: verdict}；结果同时写入 STORE。"""
    items = [(t, o) for t, o in outbounds if o.get("server")]
    if not items:
        return {}
    with ThreadPoolExecutor(max_workers=max(1, min(conc, len(items)))) as ex:
        res = list(ex.map(lambda it: (it[0], node_key(it[1]), check_outbound(it[1])), items))
    out = {k: v for _, k, v in res}
    save(out)
    if log:
        log("Google 地区闸门：" + ", ".join("%s=%s" % (t, v) for t, _, v in res))
    return out


def tun_outbounds(path=TUN_CFG):
    try:
        with io.open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return []
    return [(o.get("tag"), o) for o in cfg.get("outbounds") or []
            if (o.get("tag") or "").startswith("g") and o.get("server")]


def pinned_outbounds(path=os.path.join(HERE, "singbox_pinned.json")):
    return tun_outbounds(path)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    src = pinned_outbounds() if "--pinned" in sys.argv else tun_outbounds()
    print(json.dumps(check_many(src), ensure_ascii=False, indent=1))
