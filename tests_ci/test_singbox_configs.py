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
import time
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
        # process_name 规则在 stack=system 下等于全局直连（2026-11-23 两次断网），绝不能出现
        self.assertFalse(any("process_name" in r for r in rules))
        i80 = next(i for i, r in enumerate(rules) if r.get("port") == 80 and r.get("outbound") == "direct")
        self.assertEqual(rules[i80 - 1].get("port"), 80)
        self.assertEqual(rules[i80 - 1].get("outbound"), "grp-any")
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


class GoogleGate(unittest.TestCase):
    """Google 地区闸门：判定、重建决策、grp-google 只用 ok 节点（真 sing-box 校验）。"""

    def test_classify(self):
        import google_gate as G
        self.assertEqual(G.classify([("https://notebook.google/?location=unsupported", True)]), "bad")
        self.assertEqual(G.classify([("https://accounts.google.com/x", False),
                                     ("https://accounts.google.com/y", False)]), "ok")
        self.assertEqual(G.classify([(None, False), ("https://a", False)]), "err")
        self.assertEqual(G.classify([]), "err")
        self.assertEqual(G.country_verdict("IR"), "bad")
        self.assertEqual(G.country_verdict("US"), "ok")
        self.assertIsNone(G.country_verdict(None))
        self.assertEqual(G.GL_RE.search(b'ytcfg.set({"GL":"IR","HL":"en"})').group(1), b"IR")

    def test_needs_rebuild(self):
        import tun_supervisor as S
        self.assertTrue(S.gate_needs_rebuild(["a:1", "b:1"], {"a:1": "bad", "b:1": "ok"}))
        self.assertFalse(S.gate_needs_rebuild(["b:1"], {"a:1": "bad", "b:1": "ok"}))
        # 全是 bad：重建也换不出好节点，交给重扫
        self.assertFalse(S.gate_needs_rebuild(["a:1"], {"a:1": "bad"}))
        self.assertFalse(S.gate_needs_rebuild(["a:1"], {}))

    def test_store_roundtrip_keeps_verdicts(self):
        import google_gate as G
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(path)
        old = G.STORE
        try:
            G.STORE = path
            G.save({"1.2.3.4:443": "ok", "5.6.7.8:443": "bad"})
            G.save({"1.2.3.4:443": "err"})          # err 不覆盖已有结论
            self.assertEqual(G.load(), {"1.2.3.4:443": "ok", "5.6.7.8:443": "bad"})
            self.assertEqual(G.load(now=time.time() + 7 * 3600), {})
        finally:
            G.STORE = old
            if os.path.exists(path):
                os.remove(path)

    def test_tun_google_group_uses_only_ok(self):
        need_singbox(self)
        import contextlib
        import io as _io
        import google_gate as G
        import tun_mode
        nodes = []
        for i, name in enumerate(GOOD):
            ob, _ = parsed(name)
            nodes.append(dict(ob, tag="g%d" % i))
        tags = [o["tag"] for o in nodes]
        pinned = {"outbounds": nodes + [
            {"type": "urltest", "tag": t, "outbounds": tags,
             "url": "https://www.gstatic.com/generate_204", "interval": "60s", "tolerance": 400}
            for t in ("grp-general", "grp-fast", "grp-any")] + [{"type": "direct", "tag": "direct"}]}
        verdicts = {G.node_key(nodes[0]): "bad", G.node_key(nodes[1]): "ok",
                    G.node_key(nodes[2]): "ok", G.node_key(nodes[3]): "bad"}
        fd, ppath = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        fd, gpath = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(gpath)
        old_p, old_g = tun_mode.PINNED, G.STORE
        try:
            with open(ppath, "w", encoding="utf-8") as f:
                json.dump(pinned, f)
            tun_mode.PINNED, G.STORE = ppath, gpath
            G.save(verdicts)
            with contextlib.redirect_stdout(_io.StringIO()):
                cfg = tun_mode.build_config()
        finally:
            tun_mode.PINNED, G.STORE = old_p, old_g
            for x in (ppath, gpath):
                if os.path.exists(x):
                    os.remove(x)
        grp = next(o for o in cfg["outbounds"] if o.get("tag") == "grp-google-auto")
        sel = next(o for o in cfg["outbounds"] if o.get("tag") == "grp-google")
        self.assertEqual(sel["type"], "selector")
        self.assertEqual(sel["default"], "grp-google-auto")
        self.assertIn("g0", sel["outbounds"])      # 任何出口都能被临时钉上做浏览器验证
        # 只有 2 个 ok：ok 排最前，后面补没结论的；被判 bad 的绝不进组
        self.assertEqual(sorted(grp["outbounds"][:2]), ["g1", "g2"])
        self.assertNotIn("g0", grp["outbounds"])
        self.assertNotIn("g3", grp["outbounds"])
        rules = cfg["route"]["rules"]
        fam = [r for r in rules if r.get("domain_suffix") == tun_mode.GOOGLE_FAMILY and "port" not in r]
        self.assertEqual(len(fam), 1)
        self.assertEqual(fam[0]["outbound"], "grp-google")
        self.assertIn("google.com", tun_mode.GOOGLE_FAMILY)
        sb_check(self, cfg)


class TunBypass(unittest.TestCase):
    """测速/闸门进程自己绕开 TUN（替代 process_name 规则）。"""

    def test_bypass_verdict(self):
        import tun_supervisor as S
        self.assertTrue(S.bypass_verdict([False, False, False], [True, False, False]))
        self.assertTrue(S.bypass_verdict([True, False, False], [True, True, True]))
        self.assertFalse(S.bypass_verdict([True, True, False], [True, True, True]))   # 被隧道转发
        self.assertFalse(S.bypass_verdict([False, False, False], [False, False, False]))  # 进程本身坏

    def test_bypass_route_modes(self):
        import nodes as N
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        old = N.BYPASS_FILE
        try:
            N.BYPASS_FILE = path + ".missing"
            self.assertEqual(N.bypass_route({"final": "x"}), {"final": "x", "auto_detect_interface": True})
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"mode": "iface", "iface": "WLAN"}, f)
            N.BYPASS_FILE = path
            self.assertEqual(N.bypass_route(), {"default_interface": "WLAN"})
        finally:
            N.BYPASS_FILE = old
            os.remove(path)

    def test_deep_and_gate_configs_check(self):
        need_singbox(self)
        import deep_test
        import google_gate as G
        ob, _ = parsed(next(iter(GOOD)))
        node = {"outbound": dict(ob, tag="n0")}
        cfg = deep_test.build_cfg([node], 29501, 29502, 29503)
        self.assertTrue(cfg["route"].get("auto_detect_interface") or cfg["route"].get("default_interface"))
        sb_check(self, cfg)
        r = G._route()
        self.assertEqual(r.get("final"), "node")


class RescanDecision(unittest.TestCase):
    """tun_supervisor.decide_rescan：何时自动重扫（纯函数）。"""

    def setUp(self):
        import tun_supervisor as S
        self.S = S
        self.now = 1_800_000_000.0

    def d(self, **kw):
        base = dict(now=self.now, deep_mtime=self.now - 3600, google_live=5,
                    last_rescan=0, running=False, requested=False)
        base.update(kw)
        return self.S.decide_rescan(**base)

    def test_healthy_pool_no_rescan(self):
        self.assertIsNone(self.d())

    def test_few_google_exits_triggers(self):
        self.assertIn("2", self.d(google_live=2))

    def test_stale_pool_triggers(self):
        self.assertIsNotNone(self.d(deep_mtime=self.now - 25 * 3600))

    def test_gap_and_running_block(self):
        self.assertIsNone(self.d(google_live=0, last_rescan=self.now - 600))
        self.assertIsNone(self.d(google_live=0, running=True))
        self.assertIsNone(self.d(requested=True, running=True))

    def test_request_bypasses_gap(self):
        self.assertIsNotNone(self.d(requested=True, last_rescan=self.now - 60))

    def test_unknown_health_not_trigger(self):
        self.assertIsNone(self.d(google_live=None))


class DirectSocksPrefilter(unittest.TestCase):
    """TUN 下 TCP 预筛走「只有 direct 出站的 sing-box SOCKS」：必须分得清开着/关着的端口。"""

    def test_open_vs_closed(self):
        need_singbox(self)
        import socket
        import threading
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        open_port = srv.getsockname()[1]
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        closed_port = closed.getsockname()[1]
        closed.close()

        def accept_loop():
            for _ in range(4):
                try:
                    c, _ = srv.accept()
                    c.close()
                except OSError:
                    return
        threading.Thread(target=accept_loop, daemon=True).start()
        old_bin = N.BIN
        N.BIN = SB
        p = None
        try:
            p = N._start_direct_socks(port=29199)
            self.assertIsNotNone(p, "direct socks sing-box did not start")
            ok_open = asyncio.run(N.socks_connect("127.0.0.1", open_port, 3.0, sport=29199))
            ok_closed = asyncio.run(N.socks_connect("127.0.0.1", closed_port, 3.0, sport=29199))
        finally:
            N.BIN = old_bin
            if p:
                p.kill()
                p.wait(timeout=6)
            srv.close()
        self.assertTrue(ok_open)
        self.assertFalse(ok_closed)


if __name__ == "__main__":
    unittest.main()
