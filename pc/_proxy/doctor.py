# -*- coding: utf-8 -*-
"""一键体检：把「网络到底哪一段坏了」用一张表说清楚。

为什么要这个脚本：代理栈有 5 个可动部件（pinned 出口组、单节点出口、PAC 渲染、
PAC 服务、注册表/环境变量），用户看到的永远只有一句「网页打不开」。修一次要
从头 tail 五个日志；这个脚本把「端口 -> PAC 内容 -> 逐站实测 -> 出口身份」
按依赖顺序跑一遍，第一个 FAIL 就是根因所在层，后面的失败都是它的后果。

用法：
    python doctor.py            # 人读表格
    python doctor.py --json     # 机器读（写 logs/doctor.json 并打印 JSON）

退出码：0 全绿 / 1 有 WARN / 2 有 FAIL。可直接给 bat 或看门狗调用。
"""
import argparse
import io
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import pacroute            # noqa: E402
import sysstate            # noqa: E402

GEN, FAST, CLI, STEAM, HK = 2101, 2103, 2090, 2096, 2086
OUT = os.path.join(HERE, "logs", "doctor.json")
STATUS = os.path.join(HERE, "watchdog_status.json")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
HDRS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "sec-ch-ua": '"Chromium";v="131", "Not_A Brand";v="24"',
    "sec-ch-ua-platform": '"Windows"',
    "Upgrade-Insecure-Requests": "1",
}
# Cloudflare 拦截页的指纹：200 + 大页面也可能是它，不能只看状态码
CHALLENGE = (b"challenge-platform", b"Just a moment", b"cf-chl-",
             b"unsupported_country", b"Attention Required")


def _open(url, port=None, timeout=15):
    handler = (urllib.request.ProxyHandler({"http": "http://127.0.0.1:%d" % port,
                                            "https": "http://127.0.0.1:%d" % port})
               if port else urllib.request.ProxyHandler({}))
    op = urllib.request.build_opener(handler)
    req = urllib.request.Request(url, headers=HDRS)
    return op.open(req, timeout=timeout)


def probe(url, port=None, timeout=15, need=12000):
    """返回 dict(code, size, ms, challenge, final, err)。异常也返回 dict。"""
    t0 = time.time()
    try:
        with _open(url, port, timeout) as r:
            body = r.read(need)
            return {"code": r.status, "size": len(body), "ms": round(time.time() - t0, 2),
                    "challenge": any(m in body for m in CHALLENGE),
                    "final": r.geturl(), "err": ""}
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(need)
        except Exception:
            pass
        return {"code": e.code, "size": len(body), "ms": round(time.time() - t0, 2),
                "challenge": any(m in body for m in CHALLENGE),
                "final": url, "err": "HTTP %s" % e.code}
    except Exception as e:
        return {"code": 0, "size": 0, "ms": round(time.time() - t0, 2),
                "challenge": False, "final": url, "err": type(e).__name__ + ": " + str(e)[:90]}


def port_open(port):
    s = socket.socket()
    s.settimeout(0.4)
    try:
        return s.connect_ex(("127.0.0.1", int(port))) == 0
    finally:
        s.close()


def check_ports():
    want = [("general", GEN), ("fast", FAST), ("cli", CLI), ("steam", STEAM)]
    rows = [(n, p, port_open(p)) for n, p in want]
    dead = [n for n, p, ok in rows if not ok]
    detail = " ".join("%s:%d%s" % (n, p, "" if ok else "(down)") for n, p, ok in rows)
    if "general" in dead or "fast" in dead or "cli" in dead:
        return "FAIL", detail + "  <- 核心出口缺失，浏览器必然断", rows
    if "steam" in dead:
        return "WARN", detail + "  <- Steam/壁纸引擎走兜底", rows
    return "OK", detail, rows


def check_pac():
    if not pacroute.server_alive():
        return "FAIL", "PAC 服务 :%d 没在监听 -> 系统拿不到 PAC" % pacroute.PORT
    served = pacroute._served_bytes()
    text = served.decode("utf-8", "replace") if served else ""
    eps = pacroute.pac_endpoints(text)
    if not eps:
        return "FAIL", "PAC 服务返回的内容里找不到 GENERAL 规则"
    dead = [p for p in eps if not port_open(int(p))]
    head = text.split("\n")[0][:60]
    if dead:
        # 这就是 2026-11-18 那个故障：GENERAL fail-closed 指向死端口，Claude 硬断
        return "FAIL", "GENERAL -> %s，其中 %s 没在监听（%s）" % (
            "/".join(eps), ",".join(dead), head)
    url = pacroute._wget("AutoConfigURL")
    if url != sysstate.pac_url():
        return "FAIL", "注册表 AutoConfigURL=%r，应为 %r" % (url, sysstate.pac_url())
    return "OK", "GENERAL -> %s，URL 正确" % "/".join(eps)


def check_env():
    try:
        ok = sysstate.env_ok(CLI)
    except Exception as e:
        return "WARN", "环境变量检查异常: %r" % (e,)
    return ("OK", "HTTP(S)_PROXY -> 127.0.0.1:%d" % CLI) if ok else \
           ("WARN", "HTTP(S)_PROXY 缺失或漂移（命令行工具会走直连）")


SITES = [
    # name, url, port, 期望
    ("ChatGPT", "https://chatgpt.com/", GEN, "ok"),
    ("OpenAI API", "https://platform.openai.com/", GEN, "soft"),
    ("Claude", "https://claude.ai/", GEN, "soft"),
    ("Gemini", "https://gemini.google.com/", FAST, "ok"),
    ("AI Studio", "https://aistudio.google.com/", FAST, "ok"),
    ("GitHub", "https://github.com/", FAST, "ok"),
    ("HuggingFace", "https://huggingface.co/", FAST, "ok"),
]


def check_sites():
    rows = []
    worst = "OK"
    for name, url, port, need in SITES:
        r = probe(url, port)
        good = (r["code"] in (200, 204, 301, 302, 304)) and not r["challenge"]
        if not good and need == "soft" and r["code"] in (401, 403):
            # 平台页对未登录/爬虫返 401/403 不算链路故障，但也不算绿
            state = "WARN"
        elif good:
            state = "OK"
        else:
            state = "FAIL"
        if state == "FAIL" or (state == "WARN" and worst == "OK"):
            worst = state if state == "FAIL" else "WARN"
        note = "%s %dB %.2fs" % (r["code"], r["size"], r["ms"])
        if r["challenge"]:
            note += " (Cloudflare 挑战页)"
        if r["err"] and r["code"] == 0:
            note = r["err"]
        rows.append({"name": name, "port": port, "state": state, "note": note})
    ok = sum(1 for r in rows if r["state"] == "OK")
    return worst, "%d/%d 站点直通" % (ok, len(rows)), rows


def check_exit_identity():
    """出口 IP 与直连 IP 对比。

    2026-11-18 踩过：PC 走手机热点，手机自己在跑 VPN，所以「直连」也是新加坡
    出口 —— 拿直连当基线会把「代理没生效」误判成「代理正常」。
    """
    def ip(port):
        # 必须走 HTTPS：bestroute 的 route 规则把 80 端口强制 direct，
        # 用 http://ip-api.com 查出来的永远是本地出口（会误判成「没走代理」）。
        try:
            with _open("https://ipinfo.io/json", port, 10) as r:
                j = json.loads(r.read(4000).decode("utf-8", "replace"))
            return "%s %s" % (j.get("ip"), j.get("country")) if j.get("ip") else "?"
        except Exception:
            return "?"
    via, direct = ip(GEN), ip(None)
    if via == "?":
        return "FAIL", "经 2101 拿不到出口 IP（出口组上游死了）"
    if direct == "?":
        return "WARN", "代理出口 %s；直连探测失败（不影响使用）" % via
    if via.split()[0] == direct.split()[0]:
        return "WARN", "代理出口 %s == 直连 %s <- 请求可能没真的走代理" % (via, direct)
    return "OK", "代理出口 %s，直连 %s" % (via, direct)


def check_watchdog():
    try:
        with io.open(STATUS, encoding="utf-8") as f:
            st = json.load(f)
    except Exception:
        return "WARN", "读不到 watchdog_status.json（看门狗没跑过？）"
    try:
        pid = int(io.open(os.path.join(HERE, "watchdog.pid")).read().strip())
        import proxyctl as P
        # PID 会被复用：必须确认这个 pid 现在真的是 python，否则「存活」是假象
        live = P.pid_image(pid).lower().startswith("python")
    except Exception:
        pid, live = 0, False
    age = ""
    try:
        t = time.mktime(time.strptime(st["at"], "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
        age = "%.0f 分钟前更新" % ((time.time() - t) / 60.0)
    except Exception:
        pass
    detail = "pid=%s %s rebuilds=%s err=%s" % (
        pid, "存活" if live else "未运行", st.get("rebuilds"), st.get("last_error") or "-")
    if not live:
        return "FAIL", detail + "（退出组坏了不会自愈）"
    return "OK", detail + (" " + age if age else "")


CHECKS = [
    ("出口端口", check_ports),
    ("PAC 内容", check_pac),
    ("系统代理", check_env),
    ("逐站实测", check_sites),
    ("出口身份", check_exit_identity),
    ("看门狗", check_watchdog),
]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    a = ap.parse_args(argv)
    results = []
    for name, fn in CHECKS:
        try:
            state, detail, *extra = fn()
        except Exception as e:
            state, detail, extra = "FAIL", "检查自身异常: %r" % (e,), []
        results.append({"check": name, "state": state, "detail": detail, "rows": extra[0] if extra else None})

    worst = "OK"
    for r in results:
        if r["state"] == "FAIL":
            worst = "FAIL"
        elif r["state"] == "WARN" and worst == "OK":
            worst = "WARN"

    if a.json:
        data = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "verdict": worst, "checks": results}
        print(json.dumps(data, ensure_ascii=False, indent=1))
    else:
        icon = {"OK": "[OK]  ", "WARN": "[WARN]", "FAIL": "[FAIL]"}
        print("=" * 72)
        print(" 代理体检  %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
        print("=" * 72)
        for r in results:
            print("%s %-8s %s" % (icon[r["state"]], r["check"], r["detail"]))
            for row in (r["rows"] or []):
                if isinstance(row, dict):
                    print("         %s %-12s %s" % (icon[row["state"]], row["name"], row["note"]))
        print("-" * 72)
        if worst == "OK":
            print("结论：全链路正常。浏览器打不开就先清浏览器缓存/换无痕窗口。")
        elif worst == "WARN":
            print("结论：能用，但有降级项（见上面 WARN）。不影响浏览器主流程。")
        else:
            print("结论：按行序从上往下，第一个 FAIL 就是根因；下面的是它的后果。")
            print("      修法：python autoroute.py --apply 重建 PAC；")
            print("            出口缺失则重跑 启动代理.bat 让看门狗重建出口组。")
        print("-" * 72)

    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with io.open(OUT, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "verdict": worst,
                       "checks": results}, f, ensure_ascii=False, indent=1)
    except OSError:
        pass
    return 2 if worst == "FAIL" else (1 if worst == "WARN" else 0)


if __name__ == "__main__":
    sys.exit(main())
