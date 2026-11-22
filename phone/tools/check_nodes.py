# -*- coding: utf-8 -*-
"""用真实的 Xray 内核校验 assets/nodes.json 里每一条出站。

为什么不是"再写一遍规则表"：Xray 的约束（传输组合、REALITY 参数、SS2022 密钥
长度…）由内核代码定义，Java 侧手写规则永远会漏。这个脚本把 nodes.json 里的
每条 outbound 拼成一份最小配置，交给 `xray run -test -c` 判定 —— 判据就是
真正会在手机上跑的那个内核。

用法：
    python tools/check_nodes.py [--bin path/to/xray] [--config assets/nodes.json]

没有 xray 二进制时返回 0（跳过），方便本地无网/无内核时照常打包；
CI 里由 .github/workflows 下载固定版本的 xray 后强制执行。
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def find_xray(explicit):
    for cand in filter(None, [explicit, os.environ.get("XRAY_BIN"),
                              os.path.join(HERE, "xray", "xray.exe"),
                              os.path.join(HERE, "xray", "xray")]):
        if cand and os.path.isfile(cand):
            return cand
    return shutil.which("xray")


def base_config(outbound):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": 10809,
                      "protocol": "socks", "settings": {"udp": True, "auth": "noauth"}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
        "routing": {"domainStrategy": "AsIs",
                    "rules": [{"type": "field", "network": "tcp,udp",
                               "outboundTag": outbound.get("tag", "proxy")}]},
    }


def check_one(xray, node, tmpdir):
    path = os.path.join(tmpdir, "cfg.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(base_config(node), f, ensure_ascii=False)
    r = subprocess.run([xray, "run", "-test", "-c", path],
                       capture_output=True, text=True, errors="replace", timeout=45)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=None)
    ap.add_argument("--config", default=os.path.join(ROOT, "assets", "nodes.json"))
    args = ap.parse_args()

    xray = find_xray(args.bin)
    if not xray:
        print("SKIP: 没找到 xray 二进制（设 XRAY_BIN 或放到 tools/xray/）")
        return 0

    with open(args.config, encoding="utf-8") as f:
        nodes = json.load(f)
    if not nodes:
        print("SKIP: nodes.json 为空（公版）")
        return 0

    bad = []
    with tempfile.TemporaryDirectory() as tmp:
        for node in nodes:
            tag = node.get("tag", "?")
            ob = node.get("outbound")
            if not ob:
                bad.append((tag, "no outbound"))
                continue
            ob = dict(ob)
            ob.setdefault("tag", "proxy")
            code, out = check_one(xray, ob, tmp)
            first = next((l.strip() for l in out.splitlines() if l.strip()), "")
            if code != 0:
                bad.append((tag, first[:160]))
                print("FAIL %-6s %s" % (tag, first[:160]))
            else:
                print("OK   %-6s %s" % (tag, ob.get("protocol")))

    print("\n%d/%d 通过" % (len(nodes) - len(bad), len(nodes)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
