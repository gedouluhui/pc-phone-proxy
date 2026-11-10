"""Harvest proxy candidates from GitHub-hosted public lists.

Reads sources.json (built in), downloads each list through the bootstrap proxy
(the only working channel on this machine), and normalises everything into
candidates.jsonl keyed by (proto, host, port).

Nothing here is trusted: every entry must survive bench.py before it is kept.
"""
import base64
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw")
# Empty = direct.  Set BOOT_PROXY=http://127.0.0.1:PORT when GitHub raw needs
# an existing proxy to reach.
BOOTSTRAP = os.environ.get("BOOT_PROXY", "").strip()

# (slug, proto_hint, url)
SOURCES = [
    # ---- HTTP proxy lists (GitHub, actively maintained) ----
    ("speedx_http", "http", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"),
    ("speedx_socks4", "socks4", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt"),
    ("speedx_socks5", "socks5", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"),
    ("monosans_http", "http", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"),
    ("monosans_socks4", "socks4", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt"),
    ("monosans_socks5", "socks5", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"),
    ("vakhov_http", "http", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt"),
    ("vakhov_socks4", "socks4", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks4.txt"),
    ("vakhov_socks5", "socks5", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt"),
    ("clarketm_http", "http", "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt"),
    ("shiftytr_http", "http", "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt"),
    ("mmpx12_http", "http", "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt"),
    ("proxifly_http", "http", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt"),
    ("proxifly_socks4", "socks4", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt"),
    ("proxifly_socks5", "socks5", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt"),
    ("zloi_http", "http", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt"),
    ("zloi_socks5", "socks5", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt"),
    ("jetkai_http", "http", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt"),
    ("jetkai_socks5", "socks5", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt"),
    ("roosterkid_https", "http", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt"),
    ("roosterkid_socks5", "socks5", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt"),
    ("hookzof_socks5", "socks5", "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt"),
    ("sunny9577_mixed", "http", "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt"),
    # ---- More plain lists (2026-11-09 audit) ----
    ("openproxylist_http", "http", "https://openproxylist.xyz/http.txt"),
    ("proxyspace_http", "http", "https://proxyspace.pro/http.txt"),
    ("proxyspace_https", "http", "https://proxyspace.pro/https.txt"),
    ("proxyspace_socks5", "socks5", "https://proxyspace.pro/socks5.txt"),
    ("proxyscrape_http", "http", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all"),
    ("monosans_all", "http", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt"),
    ("zloi_https", "http", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/https.txt"),
    ("themiralay_all", "http", "https://raw.githubusercontent.com/themiralay/Proxy-List-World/master/data.txt"),
    # ---- Proxy subscription links (need a client; parsed only if reachable) ----
    ("sub_barry", "sub", "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt"),
    ("sub_mahdibland", "sub", "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"),
    ("sub_eternity", "sub", "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt"),
    ("sub_freefq", "sub", "https://raw.githubusercontent.com/freefq/free/master/v2"),
    ("sub_aliilapro", "sub", "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt"),
    ("sub_aliilapro2", "sub", "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt"),
    ("sub_pawdroid", "sub", "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"),
    ("sub_ermaozi", "sub", "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt"),
    ("sub_ripao", "sub", "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub"),
    ("sub_tssf", "sub", "https://raw.githubusercontent.com/ts-sf/fly/main/v2"),
    ("sub_matin", "sub", "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt"),
    ("sub_mheidari", "sub", "https://raw.githubusercontent.com/mheidari98/.proxy/main/all"),
    # ---- 2026-11-10 expansion: protocol-split aggregators + more lists ----
    ("mhd_vmess", "sub", "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vmess.txt"),
    ("mhd_ss", "sub", "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/ss.txt"),
    ("mhd_trojan", "sub", "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/trojan.txt"),
    ("barry_vless", "sub", "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt"),
    ("barry_vmess", "sub", "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt"),
    ("barry_ss", "sub", "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/ss.txt"),
    ("barry_trojan", "sub", "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt"),
    ("kwinshadow_mix", "sub", "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/mix.txt"),
    ("kwinshadow_vless", "sub", "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/vless.txt"),
    ("kwinshadow_vmess", "sub", "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/vmess.txt"),
    ("kwinshadow_ss", "sub", "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/ss.txt"),
    ("kwinshadow_trojan", "sub", "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/trojan.txt"),
    ("surfboard_mixed", "sub", "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed"),
    ("surfboard_vless", "sub", "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vless"),
    ("wuqb_mix_uri", "sub", "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri"),
    ("wuqb_mix", "sub", "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix"),
    ("free18_v", "sub", "https://raw.githubusercontent.com/free18/v2ray/main/v.txt"),
    ("roosterkid_v2ray", "sub", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt"),
    ("peasoft_all", "sub", "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt"),
    ("lalatina_all", "sub", "https://raw.githubusercontent.com/LalatinaHub/Mineral/master/result/nodes"),
    # ---- 2026-11-10 expansion: extra plain proxy lists ----
    ("vakhov_https", "http", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/https.txt"),
    ("shifty_socks4", "socks4", "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt"),
    ("shifty_socks5", "socks5", "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt"),
    ("proxifly_all", "http", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt"),
    ("roosterkid_socks4", "socks4", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt"),
    ("jetkai_https", "http", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt"),
    ("mmpx12_socks5", "socks5", "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt"),
    ("openproxy_socks5", "socks5", "https://openproxylist.xyz/socks5.txt"),
    ("proxyscrape_socks5", "socks5", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all"),
]

HOSTPORT = re.compile(r"^(?:(\w+)://)?(?:([^:@/\s]+):([^@/\s]+)@)?\[?([0-9a-fA-F:.]+?)\]?:(\d{1,5})$")


def fetch(slug: str, url: str, timeout: int = 30):
    t0 = time.time()
    try:
        proxies = {"http": BOOTSTRAP, "https": BOOTSTRAP} if BOOTSTRAP else None
        r = requests.get(url, proxies=proxies,
                         timeout=timeout, headers={"User-Agent": "curl/8.5.0"})
        dt = time.time() - t0
        body = r.content
        ok = r.status_code == 200 and len(body) > 0
        return {"slug": slug, "url": url, "status": r.status_code, "bytes": len(body),
                "secs": round(dt, 2), "ok": ok, "body": body}
    except Exception as e:
        return {"slug": slug, "url": url, "status": 0, "bytes": 0,
                "secs": round(time.time() - t0, 2), "ok": False, "err": str(e)[:160], "body": b""}


def maybe_b64(text: str):
    """Many `sub` sources ship one base64 blob instead of plain URIs."""
    if "://" in text:
        return text
    s = re.sub(r"\s+", "", text)
    if len(s) < 40:
        return text
    s2 = s.replace("-", "+").replace("_", "/")
    s2 += "=" * (-len(s2) % 4)
    try:
        dec = base64.b64decode(s2).decode("utf-8", "replace")
    except Exception:
        return text
    return dec if "://" in dec else text


def parse_line(line: str, proto: str):
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    if proto == "sub":
        if "://" in s:
            return {"kind": "node", "uri": s}
        return None
    m = HOSTPORT.match(s)
    if not m:
        # bare host:port already handled; try host port with space
        return None
    scheme, user, pwd, host, port = m.group(1), m.group(2), m.group(3), m.group(4), int(m.group(5))
    if not (0 < port < 65536):
        return None
    p = (scheme or proto).lower()
    if p in ("http", "https"):
        p = "http"
    if p not in ("http", "socks4", "socks5"):
        return None
    return {"kind": "proxy", "proto": p, "host": host, "port": port,
            "user": user or "", "pass": pwd or ""}


def main():
    os.makedirs(RAW, exist_ok=True)
    t0 = time.time()
    fresh = "--fresh" in sys.argv
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda s: fetch(s[0], s[2]), SOURCES))
    # Retry every failed source once with a longer budget (big subscription
    # blobs often miss the first 30 s window through the bootstrap proxy).
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(
            lambda r: r if r["body"] else fetch(r["slug"], r["url"], 60), results))

    src_rows = []
    seen = {}
    # Cumulative pool: keep entries harvested by earlier runs that the current
    # sources no longer serve.  Dead ones get filtered by the TCP prefilter, and
    # this way a temporarily failing source cannot silently shrink the pool.
    old_path = os.path.join(HERE, "candidates.jsonl")
    if not fresh and os.path.isfile(old_path):
        try:
            with io.open(old_path, encoding="utf-8") as f:
                for line in f:
                    try:
                        x = json.loads(line)
                    except Exception:
                        continue
                    if x.get("kind") == "node":
                        key = ("node", x.get("uri", "")[:400])
                    elif x.get("kind") == "proxy":
                        key = (x.get("proto"), x.get("host"), x.get("port"),
                               x.get("user", ""))
                    else:
                        continue
                    seen.setdefault(key, x)
            print(f"  carried over {len(seen)} candidates from previous harvest")
        except Exception as e:
            print(f"  [warn] could not read old candidates: {e!r}")
    for r in results:
        src_rows.append({k: r[k] for k in ("slug", "url", "status", "bytes", "secs", "ok") if k in r})
        if not r["ok"]:
            print(f"  FAIL {r['slug']:18s} {r.get('err', r['status'])}")
            continue
        proto = next(p for s, p, u in SOURCES if s == r["slug"])
        text = r["body"].decode("utf-8", "replace")
        if proto == "sub":
            text = maybe_b64(text)
        with io.open(os.path.join(RAW, r["slug"] + ".txt"), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        n_new = 0
        for line in text.splitlines():
            item = parse_line(line, proto)
            if not item:
                continue
            if item["kind"] == "node":
                key = ("node", item["uri"][:400])
            else:
                key = (item["proto"], item["host"], item["port"], item["user"])
            if key in seen:
                continue
            seen[key] = dict(item, source=r["slug"])
            n_new += 1
        print(f"  OK   {r['slug']:18s} {r['bytes']:>8d}B {r['secs']:>5.1f}s  +{n_new}")

    items = list(seen.values())
    proxies = [x for x in items if x["kind"] == "proxy"]
    nodes = [x for x in items if x["kind"] == "node"]
    with io.open(os.path.join(HERE, "candidates.jsonl"), "w", encoding="utf-8", newline="\n") as f:
        for x in items:
            f.write(json.dumps(x, ensure_ascii=False) + "\n")
    with io.open(os.path.join(HERE, "sources.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(src_rows, f, indent=1)
    from collections import Counter
    print(f"\nunique candidates: {len(items)}  proxies={len(proxies)} {dict(Counter(p['proto'] for p in proxies))} nodes={len(nodes)}")
    print(f"elapsed {time.time()-t0:.1f}s -> candidates.jsonl")
    return 0


if __name__ == "__main__":
    sys.exit(main())
