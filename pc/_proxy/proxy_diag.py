# -*- coding: utf-8 -*-
"""proxy_diag.py — 一键判断某个域名该走直连还是代理，以及实际哪条路通。

用法:
    python proxy_diag.py modelscope.cn google.com alipayobjects.com
    python proxy_diag.py            # 不带参数则跑内置体检清单

判断逻辑与 proxy.pac 保持一致（DOMESTIC / SENSITIVE / DIRECT 名单 + .cn 等后缀）。
输出四列: 直连 / 2103(快速门) / 2101(通用门) / 2090(命令行门)，单位为毫秒，X = 连接失败。
"""
import socket
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

try:
    import pacroute
    DOMESTIC = pacroute.DOMESTIC
    SENSITIVE = pacroute.SENSITIVE
    DIRECT_LIST = pacroute.DIRECT
except Exception:
    DOMESTIC, SENSITIVE, DIRECT_LIST = [], [], []

GATES = [("2103", 2103), ("2101", 2101), ("2090", 2090)]


def match(host, domains):
    host = host.lower()
    for d in domains:
        d = d.lower()
        if host == d or host.endswith("." + d):
            return True
    return False


def pac_verdict(host):
    if match(host, DOMESTIC):
        return "DIRECT(DOMESTIC)"
    if match(host, SENSITIVE):
        return "DIRECT(SENSITIVE)"
    if match(host, DIRECT_LIST):
        return "DIRECT(DIRECT)"
    return "PROXY(fast→general)"


def tcp(host, port, timeout=6.0):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def via_proxy(host, port, proxy_port, timeout=6.0):
    """向本地代理发 CONNECT，返回是否收到 200。"""
    try:
        s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
        s.settimeout(timeout)
        req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        s.sendall(req.encode())
        buf = s.recv(64)
        s.close()
        return b" 200" in buf
    except Exception:
        return False


def main():
    targets = sys.argv[1:] or ["modelscope.cn", "www.baidu.com", "github.com",
                               "www.google.com", "alipayobjects.com", "www.12306.cn"]
    print(f"{'domain':28s} {'PAC 判定':24s} {'直连':>6s} {'2103':>6s} {'2101':>6s} {'2090':>6s}")
    print("-" * 88)
    for t in targets:
        host = t.strip().replace("https://", "").replace("http://", "").split("/")[0]
        row = [f"{host:28s}", f"{pac_verdict(host):24s}"]
        row.append(f"{'OK' if tcp(host, 443) else 'X':>6s}")
        for _, p in GATES:
            row.append(f"{'OK' if via_proxy(host, 443, p) else 'X':>6s}")
        print(" ".join(row))
    print()
    print("读法：PAC=DIRECT 但直连 X → 该站被墙或 DNS 污染；PAC=PROXY 但三个门全 X → 节点问题。")
    print("      国内站出现 PAC=PROXY（且直连 OK）→ 把它加进 pacroute.py 的 DOMESTIC，跑 apply_pac 即可。")


if __name__ == "__main__":
    main()
