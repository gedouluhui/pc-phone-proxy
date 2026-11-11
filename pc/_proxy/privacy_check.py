# -*- coding: utf-8 -*-
"""隐私自检（只读，不改任何配置）

检查项：
  1. 三道门是否在听
  2. HTTPS 经代理的出口 IP（应为节点 IP，不是你的真实 IP）
  3. 明文 HTTP(80) 是否被强制直连（不应经过节点）
  4. 敏感域（银行/政务/教育）是否按 PAC 规则直连
  5. 系统根证书里有没有疑似 MITM 的证书（Charles/Fiddler/Burp/自建代理）
  6. IPv6 是否可用（WebRTC 泄露风险提示）

用法：双击或 `python privacy_check.py`
"""
import io
import json
import os
import re
import socket
import subprocess
import sys
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)

HERE = os.path.dirname(os.path.abspath(__file__))
PAC = os.path.join(HERE, "proxy.pac")
GATES = {"general": 2101, "fast": 2103, "cli": 2090}
TIMEOUT = 15


def http_get(url, proxy=None):
    """proxy: 'http://127.0.0.1:2101' 或 None（直连）"""
    try:
        if proxy:
            op = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        else:
            op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with op.open(url, timeout=TIMEOUT) as r:
            return (r.read() or b"").decode("utf-8", "replace").strip()[:120]
    except Exception as e:
        return "ERR:%s" % str(e)[:60]


def port_open(port):
    s = socket.socket()
    s.settimeout(0.6)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def pac_sensitive():
    try:
        text = io.open(PAC, encoding="utf-8").read()
        m = re.search(r"var SENSITIVE = \[(.*?)\];", text, re.S)
        if not m:
            return []
        return [x.strip().strip('"') for x in m.group(1).split(",") if x.strip()]
    except Exception:
        return []


def suspicious_cas():
    ps = (
        "Get-ChildItem Cert:\\LocalMachine\\Root,Cert:\\CurrentUser\\Root -ErrorAction SilentlyContinue | "
        "ForEach-Object { $_.Subject }"
    )
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=60,
                           creationflags=0x08000000)
        subs = [x.strip() for x in (r.stdout or "").splitlines() if x.strip()]
    except Exception:
        return None, []
    bad_keys = ("mitm", "charles", "fiddler", "burp", "proxy", "superfish",
                "anyproxy", "whistle", "clash", "v2ray", "sing-box")
    hits = [s for s in subs if any(k in s.lower() for k in bad_keys)]
    return len(subs), hits


def main():
    print("=" * 64)
    print("代理隐私自检（只读）")
    print("=" * 64)

    ok = True

    # 1. 门
    print("\n[1] 代理门")
    for name, port in GATES.items():
        live = port_open(port)
        ok = ok and live
        print("    %-8s 127.0.0.1:%-5d %s" % (name, port, "OK" if live else "未监听 ✗"))

    # 2. 出口 IP
    print("\n[2] 出口 IP（直连 vs 各门 HTTPS）")
    direct = http_get("http://ipv4.icanhazip.com")
    print("    直连(真实):      %s" % direct)
    node_ips = {}
    for name, port in GATES.items():
        ip = http_get("https://ipv4.icanhazip.com", "http://127.0.0.1:%d" % port)
        node_ips[name] = ip
        flag = ""
        if ip == direct:
            flag = "  ← 泄露告警：HTTPS 未经节点！"
            ok = False
        elif ip.startswith("ERR"):
            flag = "  ← 该门暂时不可用"
        print("    %-8s HTTPS:    %s%s" % (name, ip, flag))

    # 3. 明文 HTTP 是否直连
    print("\n[3] 明文 HTTP(80) 是否绕过节点")
    plain = http_get("http://ipv4.icanhazip.com", "http://127.0.0.1:%d" % GATES["fast"])
    if plain == direct:
        print("    %s  = 真实 IP ⇒ 明文不经过节点 ✓" % plain)
    elif plain in node_ips.values():
        print("    %s  = 节点 IP ⇒ 明文仍走节点 ✗（内容对节点可见）" % plain)
        ok = False
    else:
        print("    %s（无法判定，可能是直连 IP 变化）" % plain)

    # 4. 敏感域
    print("\n[4] 敏感域直连规则")
    sens = pac_sensitive()
    print("    PAC SENSITIVE 条目: %d 条" % len(sens))
    for probe in ("icbc.com.cn", "www.gov.cn", "www.edu.cn"):
        hit = any(probe == d or probe.endswith("." + d) for d in sens)
        print("    %-16s %s" % (probe, "DIRECT ✓" if hit else "未覆盖 ✗"))
        ok = ok and hit

    # 5. 根证书
    print("\n[5] 系统根证书（MITM 检测）")
    total, hits = suspicious_cas()
    if total is None:
        print("    读取失败（可忽略）")
    else:
        print("    根证书总数: %d" % total)
        if hits:
            print("    ⚠ 发现疑似抓包/代理证书，HTTPS 可能被中间人解密：")
            for h in hits[:6]:
                print("      - %s" % h[:100])
            ok = False
        else:
            print("    未发现 Charles/Fiddler/Burp/mitmproxy 类证书 ✓")

    # 6. IPv6 / WebRTC 提示
    print("\n[6] IPv6 / WebRTC")
    v6 = http_get("http://ipv6.icanhazip.com")
    if v6.startswith("ERR"):
        print("    IPv6 不可用 ✓（减少一类泄露面）")
    else:
        print("    IPv6 可用: %s" % v6)
        print("    提示：网站可通过 WebRTC 拿到你的内网/公网地址；在浏览器里关闭 WebRTC 或")
        print("          安装禁用 WebRTC 的扩展可消除该风险（代理层挡不住 WebRTC）。")

    print("\n" + "=" * 64)
    print("结论: %s" % ("通过（未发现明显泄露）" if ok else "存在告警，见上方 ✗ 项"))
    print("注意: 免费节点运营者仍能看到你访问的域名/时间/流量大小，这是代理协议本身的")
    print("      可见性，任何客户端都无法隐藏；敏感账号请勿经免费节点登录。")
    print("=" * 64)


if __name__ == "__main__":
    main()
