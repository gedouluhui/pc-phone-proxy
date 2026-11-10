# -*- coding: utf-8 -*-
"""Probe general consumer sites through each candidate proxy.

For every proxy we hit:
  1) cloudflare trace (exit ip / country)
  2) chatgpt.com + its auth/session endpoint (region + bot gate)
  3) a list of other sites the user needs

Output: site_probe.json + a compact table on stdout.
"""
import io, json, os, re, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
CURL = "curl"

PROXIES = [
    ("applied_4.144.146.21", "http://4.144.146.21:80"),
    ("geph_http_9910", "http://127.0.0.1:9910"),
    ("geph_socks_9909", "socks5h://127.0.0.1:9909"),
    ("sbox_2086", "http://127.0.0.1:2086"),
    ("pub_socks5_183.80.59.62", "socks5h://183.80.59.62:1083"),
    ("pub_http_204.199.106.226", "http://204.199.106.226:999"),
]

SITES = [
    ("cloudflare_trace", "https://www.cloudflare.com/cdn-cgi/trace"),
    ("chatgpt", "https://chatgpt.com/"),
    ("chatgpt_session", "https://chatgpt.com/api/auth/session"),
    ("openai_auth", "https://auth.openai.com/"),
    ("openai_api", "https://api.openai.com/v1/models"),
    ("sora", "https://sora.chatgpt.com/"),
    ("claude", "https://claude.ai/"),
    ("gemini", "https://gemini.google.com/"),
    ("google", "https://www.google.com/"),
    ("youtube", "https://www.youtube.com/"),
    ("github", "https://github.com/"),
    ("huggingface", "https://huggingface.co/"),
    ("x", "https://x.com/"),
    ("reddit", "https://www.reddit.com/"),
    ("wikipedia", "https://en.wikipedia.org/wiki/Main_Page"),
    ("kaggle", "https://www.kaggle.com/"),
    ("ipinfo", "https://ipinfo.io/json"),
]

MARKERS = [
    ("unsupported_country", re.compile(r"unsupported_country", re.I)),
    ("cf_challenge", re.compile(r"(Just a moment|cf-challenge|cf_chl_opt|Attention Required)", re.I)),
    ("access_denied", re.compile(r"Access Denied|You don't have permission", re.I)),
    ("rate_limited", re.compile(r"rate limit|too many requests", re.I)),
]


def curl(proxy, url, timeout=20):
    args = [CURL, "-sS", "--max-time", str(timeout), "--connect-timeout", "10",
            "-x", proxy, "-o", "-", "-w", "\n==META==%{http_code} %{time_total} %{size_download} %{remote_ip}\n", url]
    t0 = time.time()
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout + 8,
                           creationflags=0x08000000)
        out = p.stdout
        err = p.stderr.decode("utf-8", "replace").strip()
    except subprocess.TimeoutExpired:
        return {"ok": False, "err": "timeout", "secs": round(time.time() - t0, 2)}
    text = out.decode("utf-8", "replace")
    body, _, meta = text.rpartition("==META==")
    code = size = remote = ""
    if meta:
        parts = meta.strip().split()
        code = parts[0] if parts else ""
        remote = parts[-1] if len(parts) >= 4 else ""
        try:
            size = int(float(parts[2]))
        except Exception:
            size = len(body)
    markers = [n for n, rx in MARKERS if rx.search(body[:20000])]
    exit_info = {}
    if "cdn-cgi/trace" in url and body:
        for line in body.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                if k in ("ip", "loc", "colo", "tls", "http"):
                    exit_info[k] = v
    return {"ok": bool(code) and code != "000", "code": code, "remote": remote,
            "size": size, "secs": round(time.time() - t0, 2),
            "head": body[:220].replace("\n", " ").replace("\r", ""),
            "markers": markers, "exit": exit_info, "err": err[:200]}


def main():
    results = {}
    for name, proxy in PROXIES:
        t0 = time.time()
        print(f"\n### {name}  ({proxy})", flush=True)
        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = {s: ex.submit(curl, proxy, u) for s, u in SITES}
            rows = {}
            for s, _u in SITES:
                try:
                    rows[s] = futs[s].result()
                except Exception as e:
                    rows[s] = {"ok": False, "err": repr(e)}
        results[name] = {"proxy": proxy, "secs": round(time.time() - t0, 1), "rows": rows}
        ex_info = rows.get("cloudflare_trace", {}).get("exit") or {}
        print(f"  exit: ip={ex_info.get('ip')} loc={ex_info.get('loc')} colo={ex_info.get('colo')}", flush=True)
        for s, _u in SITES:
            if s == "cloudflare_trace":
                continue
            r = rows[s]
            code = r.get("code", "-")
            mk = ",".join(r.get("markers") or [])
            print(f"  {s:18s} {str(code):4s} {r.get('secs','?'):>6}s {str(r.get('size','?')):>9s}  {mk}  {r.get('err','') or ''}".rstrip(), flush=True)

    out = os.path.join(HERE, "site_probe.json")
    with io.open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=1)
    print("\nJSON ->", out)


if __name__ == "__main__":
    sys.exit(main())
