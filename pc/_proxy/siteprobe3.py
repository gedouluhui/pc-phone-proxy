# -*- coding: utf-8 -*-
"""Probe a broad site list through each configured exit and report which exit
answers 200/30x for each site. Read-only; no settings are changed.

  python siteprobe3.py            # writes site_matrix.json
"""
import json
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "site_matrix.json")

EXITS = [("fast", "127.0.0.1:2103"), ("general", "127.0.0.1:2101"),
         ("hk", "127.0.0.1:2086"), ("geph", "127.0.0.1:9910")]

SITES = [
    ("google", "https://www.google.com/"), ("youtube", "https://www.youtube.com/"),
    ("x", "https://x.com/"), ("instagram", "https://www.instagram.com/"),
    ("facebook", "https://www.facebook.com/"), ("tiktok", "https://www.tiktok.com/"),
    ("reddit", "https://www.reddit.com/"), ("pinterest", "https://www.pinterest.com/"),
    ("linkedin", "https://www.linkedin.com/"), ("quora", "https://www.quora.com/"),
    ("medium", "https://medium.com/"), ("substack", "https://substack.com/"),
    ("nytimes", "https://www.nytimes.com/"), ("bbc", "https://www.bbc.com/"),
    ("bloomberg", "https://www.bloomberg.com/"), ("reuters", "https://www.reuters.com/"),
    ("amazon", "https://www.amazon.com/"), ("ebay", "https://www.ebay.com/"),
    ("paypal", "https://www.paypal.com/"), ("spotify", "https://open.spotify.com/"),
    ("twitch", "https://www.twitch.tv/"), ("netflix", "https://www.netflix.com/"),
    ("steam", "https://store.steampowered.com/"), ("discord", "https://discord.com/"),
    ("telegram", "https://web.telegram.org/"), ("whatsapp", "https://web.whatsapp.com/"),
    ("github", "https://github.com/"), ("gitlab", "https://gitlab.com/"),
    ("bitbucket", "https://bitbucket.org/"), ("stackoverflow", "https://stackoverflow.com/"),
    ("arxiv", "https://arxiv.org/"), ("semanticscholar", "https://www.semanticscholar.org/"),
    ("openreview", "https://openreview.net/"), ("huggingface", "https://huggingface.co/"),
    ("civitai", "https://civitai.com/"), ("replicate", "https://replicate.com/"),
    ("openrouter", "https://openrouter.ai/"), ("groq", "https://groq.com/"),
    ("mistral", "https://mistral.ai/"), ("together", "https://api.together.xyz/"),
    ("colab", "https://colab.research.google.com/"), ("drive", "https://drive.google.com/"),
    ("gmail", "https://mail.google.com/"), ("gemini", "https://gemini.google.com/"),
    ("chatgpt", "https://chatgpt.com/"), ("claude", "https://claude.ai/"),
    ("kaggle", "https://www.kaggle.com/"), ("docker", "https://hub.docker.com/"),
    ("pypi", "https://pypi.org/"), ("npm", "https://www.npmjs.com/"),
    ("wikipedia", "https://en.wikipedia.org/wiki/Main_Page"),
    ("coursera", "https://www.coursera.org/"), ("udemy", "https://www.udemy.com/"),
    ("pixiv", "https://www.pixiv.net/"), ("slack", "https://slack.com/"),
]


def probe(proxy, url, timeout=18):
    p = subprocess.run(["curl", "-s", "-o", "NUL", "-x", "http://" + proxy,
                        "--ssl-no-revoke", "-m", str(timeout),
                        "-w", "%{http_code} %{time_starttransfer} %{size_download}",
                        url], capture_output=True, text=True,
                       creationflags=0x08000000)
    parts = (p.stdout or "").split()
    code = parts[0] if parts else "000"
    ttfb = float(parts[1]) if len(parts) > 1 else 0.0
    size = int(float(parts[2])) if len(parts) > 2 else 0
    return {"code": code, "ttfb": round(ttfb, 2), "kb": round(size / 1024)}


def job(item):
    name, url = item
    row = {"name": name, "url": url, "exits": {}}
    for ename, ep in EXITS:
        try:
            row["exits"][ename] = probe(ep, url)
        except Exception as e:
            row["exits"][ename] = {"code": "err", "ttfb": 0, "kb": 0, "e": str(e)[:40]}
    return row


def good(r):
    c = str(r.get("code"))
    return c.startswith("2") or c in ("301", "302", "303", "307", "308")


def main():
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=8) as ex:
        rows = list(ex.map(job, SITES))
    print(f"probed {len(rows)} sites x {len(EXITS)} exits in {time.time()-t0:.0f}s\n")
    hdr = "%-14s" % "site" + "".join("%-16s" % e for e, _ in EXITS)
    print(hdr)
    only = {}
    for r in rows:
        cells = ""
        for e, _ in EXITS:
            x = r["exits"][e]
            mark = "OK " if good(x) else "BAD"
            cells += "%-16s" % f"{x['code']} {mark}{x['ttfb']}s"
        print("%-14s" % r["name"] + cells)
        fails = [e for e, _ in EXITS if not good(r["exits"][e])]
        works = [e for e, _ in EXITS if good(r["exits"][e])]
        if fails and works:
            only[r["name"]] = {"works": works, "fails": fails}
    print("\n== sites that fail on some exit but work on another ==")
    for k, v in only.items():
        print(f"  {k:14s} works={','.join(v['works']):26s} fails={','.join(v['fails'])}")
    json.dump({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "exits": EXITS, "rows": rows}, open(OUT, "w", encoding="utf-8"),
              indent=1, ensure_ascii=False)
    print("\nsaved " + OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
