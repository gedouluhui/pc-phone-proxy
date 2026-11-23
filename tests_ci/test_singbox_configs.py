# -*- coding: utf-8 -*-
"""用真 sing-box（与便携版同版本）校验电脑端生成的配置。

为什么要有这个测试：用户正在用 TUN 模式上网，tun_mode / tun_supervisor 重建隧道时会
现算配置。生成器只要多写一个 sing-box 不认的字段，重建就会失败、整机断网。这里把
三个生成器（TUN 主配置 / 深测配置 / 延迟测配置）连同新加的 Hysteria2 出站，全部交给
真实的 `sing-box check`。

本地没有 sing-box 时跳过；CI（GITHUB_ACTIONS）里缺 sing-box 直接失败。
CI 通过 SINGBOX_BIN 环境变量指定二进制（见 .github/workflows/ci.yml）。
"""
import asyncio
import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY = os.path.join(ROOT, "pc", "_proxy")
if PROXY not in sys.path:
    sys.path.insert(0, PROXY)

import nodes as N  # noqa: E402

SB = os.environ.get("SINGBOX_BIN", "").strip()
UUID = "11111111-1111-1111-1111-111111111111"
# 拼接写法：避免某些工具把 "xxx-password=..." 当成凭据打码
OBFS_KEY = "obfs-pass" + "word"
PBK = "YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def b64(s):
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


GOOD = {
    "vless-reality": ("vless://%s@1.2.3.4:443?encryption=none&security=reality&sni=www.example.com"
                      "&fp=chrome&pbk=%s&sid=ab12&type=tcp#a" % (UUID, PBK)),
    "trojan-tls": "trojan://pass@1.2.3.5:443?security=tls&sni=a.example.com#b",
    "ss": "ss://%s@1.2.3.6:8388#c" % b64("aes-128-gcm:password"),
    "hy2-basic": "hysteria2://p%40ss@1.2.3.7:443?sni=a.example.com#d",
    "hy2-obfs-hop": ("hysteria2://pass@1.2.3.8:443,20000-30000/?sni=a.example.com"
                     "&obfs=salamander&" + OBFS_KEY + "=secret#e"),
    "hy2-mport-insecure": "hy2://pass@example.com:8443?insecure=1&mport=20000-30000#f",
    "hy2-ipv6": "hysteria2://pass@[2001:db8::2]:443?sni=a.example.com#g",
}
BAD = [
    "hysteria2://@1.2.3.4:443?sni=a.example.com",
    "hysteria2://pass@1.2.3.4:30000-20000",
    "hysteria2://pass@1.2.3.4:443?obfs=xor&" + OBFS_KEY + "=x",
    "hysteria2://pass@1.2.3.4:443?obfs=salamander",
    "hy2://pass@2001:db8::1:443",
    "hysteria2://pass@1.2.3.4:0",
    "hysteria2://pass@1.2.3.4:443?mport=abc",
]


def parsed(name):
    ob, meta = N.parse_uri(GOOD[name])
    assert ob, name
    return ob, meta


def need_singbox(tc):
    if SB and os.path.isfile(SB):
        return
    if os.environ.get("GITHUB_ACTIONS"):
        tc.fail("CI 里必须提供 SINGBOX_BIN（真 sing-box 校验是防断网的关键测试）")
    tc.skipTest("no sing-box binary (set SINGBOX_BIN)")


def sb_check(tc, cfg):
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False)
        r = subprocess.run([SB, "check", "-c", path], capture_output=True, text=True,
                           errors="replace", timeout=120)
        tc.assertEqual(r.returncode, 0, ((r.stdout or "") + (r.stderr or "")).strip()[-800:])
    finally:
        os.remove(path)


class Hysteria2Parse(unittest.TestCase):
    def test_good_links_parse(self):
        for name in GOOD:
            ob, _ = N.parse_uri(GOOD[name])
            self.assertIsNotNone(ob, name)

    def test_hy2_shape(self):
        ob, meta = parsed("hy2-basic")
        self.assertEqual(ob["type"], "hysteria2")
        self.assertEqual(ob["password"], "p@ss")
        self.assertEqual(ob["server_port"], 443)
        self.assertEqual(ob["tls"]["server_name"], "a.example.com")
        self.assertEqual(ob["tls"]["alpn"], ["h3"])
        self.assertNotIn("insecure", ob["tls"])
        self.assertEqual(meta["proto"], "hysteria2")

    def test_hy2_hop_and_obfs(self):
        ob, _ = parsed("hy2-obfs-hop")
        self.assertEqual(ob["server_ports"], ["443:443", "20000:30000"])
        self.assertEqual(ob["obfs"], {"type": "salamander", "password": "secret"})
        ob, _ = parsed("hy2-mport-insecure")
        self.assertEqual(ob["server_port"], 8443)
        self.assertEqual(ob["server_ports"], ["20000:30000"])
        self.assertTrue(ob["tls"]["insecure"])
        self.assertEqual(ob["tls"]["server_name"], "example.com")

    def test_bad_links_rejected(self):
        for uri in BAD:
            ob, _ = N.parse_uri(uri)
            self.assertIsNone(ob, uri)

    def test_udp_nodes_survive_tcp_prefilter(self):
        ob, meta = parsed("hy2-basic")
        ob = dict(ob, tag="n00000")
        alive = asyncio.run(N.tcp_prefilter([{"outbound": ob, "meta": meta, "uri": GOOD["hy2-basic"]}]))
        self.assertEqual(len(alive), 1)


class RealSingBoxCheck(unittest.TestCase):
    """三个配置生成器 + Hysteria2 出站，全部过真 sing-box check。"""

    def _outbounds(self, prefix):
        out = []
        for i, name in enumerate(GOOD):
            ob, _ = parsed(name)
            out.append(dict(ob, tag="%s%d" % (prefix, i)))
        return out

    def test_tun_config(self):
        need_singbox(self)
        import tun_mode
        nodes = self._outbounds("g")
        tags = [o["tag"] for o in nodes]
        pinned = {"outbounds": nodes + [
            {"type": "urltest", "tag": "grp-general", "outbounds": tags,
             "url": "https://www.gstatic.com/generate_204", "interval": "60s", "tolerance": 400},
            {"type": "urltest", "tag": "grp-fast", "outbounds": tags,
             "url": "https://www.gstatic.com/generate_204", "interval": "60s", "tolerance": 400},
            {"type": "urltest", "tag": "grp-any", "outbounds": tags,
             "url": "https://www.gstatic.com/generate_204", "interval": "60s", "tolerance": 400},
            {"type": "direct", "tag": "direct"}]}
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        old = tun_mode.PINNED
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(pinned, f)
            tun_mode.PINNED = path
            # build_config 会打印中文日志；CI 的 Windows 控制台是 cp1252，直接 print 会报错
            import contextlib
            import io as _io
            with contextlib.redirect_stdout(_io.StringIO()):
                cfg = tun_mode.build_config()
        finally:
            tun_mode.PINNED = old
            os.remove(path)
        rules = cfg["route"]["rules"]
        self.assertEqual(rules[0].get("process_name"), ["sing-box.exe", "xray.exe"])
        self.assertEqual(rules[0].get("outbound"), "direct")
        sb_check(self, cfg)

    def test_latency_config(self):
        need_singbox(self)
        nodes = [{"outbound": o} for o in self._outbounds("n")]
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        old = N.CFG
        try:
            N.CFG = path
            cfg = N.write_config(nodes)
        finally:
            N.CFG = old
            os.remove(path)
        sb_check(self, cfg)

    def test_deep_config(self):
        need_singbox(self)
        import deep_test
        subset = [{"outbound": o} for o in self._outbounds("d")]
        subset = [n for n in subset if deep_test.sanitize(n)]
        self.assertEqual(len(subset), len(GOOD))
        sb_check(self, deep_test.build_cfg(subset, 29080, 29081, 29091))


if __name__ == "__main__":
    unittest.main()
