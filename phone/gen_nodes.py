# -*- coding: utf-8 -*-
"""Convert a pinned.json member map (share URIs) into the app's node list.

Input: a pinned.json like
    {"members": {"vless://...": "g0", "ss://...": "p3"}}
  1. Generate it with the PC pipeline (bestroute.py --apply writes it), or
  2. Write it yourself: key = share URI, value = short tag.

Usage:
    python gen_nodes.py [pinned.json] [--order g3,g0,...]

Output:
    assets/nodes.json          embedded into the APK by build_apk.py
    pc_test_config.json        socks inbound + first node, for local testing

Credentials are read from files only; the console prints protocol/host/port
so you can eyeball the result without leaking UUIDs or passwords.
"""
import base64
import json
import os
import sys
import urllib.parse

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
argv = [a for a in sys.argv[1:] if not a.startswith("--")]
ORDER_ARG = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--order=")), "")
PINNED = os.path.abspath(argv[0]) if argv else os.environ.get("PINNED_JSON") or os.path.join(HERE, "pinned.json")


def b64decode_pad(s):
    s = s.strip()
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8")
    except Exception:
        return base64.b64decode(s).decode("utf-8")


def vless_outbound(p, q):
    uuid = urllib.parse.unquote(p.username or "")
    net = q.get("type", ["tcp"])[0]
    sec = q.get("security", ["none"])[0]
    user = {"id": uuid, "encryption": q.get("encryption", ["none"])[0]}
    if q.get("flow"):
        user["flow"] = q["flow"][0]
    ob = {
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": p.hostname, "port": p.port, "users": [user]}]},
        "streamSettings": {"network": net, "security": sec},
    }
    ss = ob["streamSettings"]
    if sec == "reality":
        ss["realitySettings"] = {
            "serverName": q.get("sni", [""])[0],
            "fingerprint": q.get("fp", ["chrome"])[0],
            "publicKey": q.get("pbk", [""])[0],
            "shortId": q.get("sid", [""])[0],
            "spiderX": q.get("spx", ["/"])[0],
        }
    elif sec == "tls":
        ss["tlsSettings"] = {
            "serverName": q.get("sni", [""])[0],
            "fingerprint": q.get("fp", ["chrome"])[0],
            "alpn": q.get("alpn", [""])[0].split(",") if q.get("alpn") else [],
        }
    if net == "grpc":
        ss["grpcSettings"] = {
            "serviceName": q.get("serviceName", [""])[0],
            "multiMode": q.get("mode", ["gun"])[0] == "multi",
        }
    elif net == "ws":
        ss["wsSettings"] = {
            "path": q.get("path", ["/"])[0],
            "headers": {"Host": q.get("host", [""])[0]} if q.get("host") else {},
        }
    elif net == "tcp" and q.get("headerType", ["none"])[0] == "http":
        ss["tcpSettings"] = {"header": {"type": "http"}}
    return ob


def ss_outbound(p):
    info = b64decode_pad(urllib.parse.unquote(p.username or ""))
    method, _, pw = info.partition(":")
    if not pw:
        raise ValueError("ss userinfo not method:password")
    return {
        "protocol": "shadowsocks",
        "settings": {"servers": [{
            "address": p.hostname, "port": p.port,
            "method": method, "password": pw}]},
    }


def main():
    with open(PINNED, encoding="utf-8") as f:
        d = json.load(f)
    by_tag = {tag: uri for uri, tag in d["members"].items()}
    order = [t.strip() for t in ORDER_ARG.split(",") if t.strip()] or list(by_tag)
    order = [t for t in order if t in by_tag]
    nodes = []
    for tag in order:
        uri = by_tag[tag]
        p = urllib.parse.urlparse(uri)
        q = urllib.parse.parse_qs(p.query)
        if p.scheme == "vless":
            ob = vless_outbound(p, q)
        elif p.scheme == "ss":
            ob = ss_outbound(p)
        else:
            raise ValueError("unsupported scheme " + p.scheme)
        ob["tag"] = "proxy"
        nodes.append({"tag": tag, "name": tag, "outbound": ob})
        print("OK", tag, ob["protocol"], p.hostname, p.port)
    if not nodes:
        raise SystemExit("no nodes found in " + PINNED)
    os.makedirs(os.path.join(HERE, "assets"), exist_ok=True)
    with open(os.path.join(HERE, "assets", "nodes.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump(nodes, f, ensure_ascii=False, indent=1)
    # PC validation config: socks inbound + best node + proxy-all routing
    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": 18081,
                      "protocol": "socks",
                      "settings": {"udp": True, "auth": "noauth"}}],
        "outbounds": [nodes[0]["outbound"],
                      {"protocol": "freedom", "tag": "direct"}],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
            {"ip": ["geoip:private"], "outboundTag": "direct"},
            {"network": "tcp,udp", "outboundTag": "proxy"}]},
    }
    with open(os.path.join(HERE, "pc_test_config.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=1)
    print("nodes.json + pc_test_config.json written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
