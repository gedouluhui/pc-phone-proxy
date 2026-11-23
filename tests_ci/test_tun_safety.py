# -*- coding: utf-8 -*-
"""TUN 模式的两道保险（2026-11-23 18:00 事故后加）。

事故经过：自动重扫在「没有直连规则的旧隧道」下跑完，深测子进程的流量被隧道二次转发，
30 个新出口的测速全是假的（都像 1.8~2 MB/s）；切过去后本机直连一个都连不上，整机外网断了
约 30 分钟，DNS 守护又每 1~3 分钟重建一次隧道。

1. rescan.canary_contaminated：扫之前用测速同款的直连 SOCKS 探被墙地址，能连上就说明
   测速路径被转发，本轮不扫。
2. tun_supervisor.pool_switch_ok：新节点池在切换前已经过一遍闸门实测，能连上的不足 2 个
   就拒绝切换、恢复上一份可用节点池。
"""
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY = os.path.join(ROOT, "pc", "_proxy")
if PROXY not in sys.path:
    sys.path.insert(0, PROXY)


class Canary(unittest.TestCase):
    def setUp(self):
        import rescan
        self.R = rescan

    def test_all_blocked_is_clean(self):
        self.assertFalse(self.R.canary_contaminated([False, False, False]))

    def test_single_hit_is_not_enough(self):
        # 个别运营商/地区偶尔能直连某个地址，不能因此停掉重扫
        self.assertFalse(self.R.canary_contaminated([True, False, False]))

    def test_two_hits_mean_forwarded(self):
        self.assertTrue(self.R.canary_contaminated([True, True, False]))
        self.assertTrue(self.R.canary_contaminated([True, True, True]))

    def test_canaries_are_public_443(self):
        self.assertGreaterEqual(len(self.R.CANARIES), 3)
        for ip, port in self.R.CANARIES:
            self.assertEqual(port, 443)
            self.assertFalse(ip.startswith(("10.", "127.", "192.168.", "172.16.")))


class PoolSwitch(unittest.TestCase):
    def setUp(self):
        import tun_supervisor as S
        self.S = S

    def test_all_err_is_rejected(self):
        # 17:34 的真实情况：新池 30 个出口闸门全部 err
        self.assertFalse(self.S.pool_switch_ok({"k%d" % i: "err" for i in range(30)}))

    def test_one_live_is_rejected(self):
        self.assertFalse(self.S.pool_switch_ok({"a": "ok", "b": "err", "c": "err"}))

    def test_two_live_is_accepted(self):
        # bad = 能连上但 Google 判地区不支持：节点是活的，算数
        self.assertTrue(self.S.pool_switch_ok({"a": "ok", "b": "bad", "c": "err"}))

    def test_no_verdicts_keeps_old_behaviour(self):
        self.assertTrue(self.S.pool_switch_ok({}))

    def test_restore_good_pinned_roundtrip(self):
        S = self.S
        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "singbox_pinned.json")
            good = os.path.join(d, "singbox_pinned.good.json")
            with open(cfg, "w", encoding="utf-8") as f:
                f.write('{"new": true}')
            with open(good, "w", encoding="utf-8") as f:
                f.write('{"good": true}')
            old = (S.PINNED_CFG, S.PINNED_GOOD, S.log)
            S.PINNED_CFG, S.PINNED_GOOD, S.log = cfg, good, (lambda *a: None)
            try:
                self.assertTrue(S.restore_good_pinned())
            finally:
                S.PINNED_CFG, S.PINNED_GOOD, S.log = old
            with open(cfg, encoding="utf-8") as f:
                self.assertIn("good", f.read())
            with open(cfg + ".rejected", encoding="utf-8") as f:
                self.assertIn("new", f.read())

    def test_save_good_pinned_skips_unapplied_pool(self):
        """节点池比隧道进程新（还没切过去）时不能当成「可用备份」。"""
        S = self.S
        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "singbox_pinned.json")
            good = os.path.join(d, "singbox_pinned.good.json")
            pid = os.path.join(d, "tun.pid")
            with open(pid, "w") as f:
                f.write("1")
            with open(cfg, "w") as f:
                f.write("{}")
            now = time.time()
            os.utime(pid, (now - 100, now - 100))
            os.utime(cfg, (now, now))
            old = (S.PINNED_CFG, S.PINNED_GOOD, S.tun_mode.PID)
            S.PINNED_CFG, S.PINNED_GOOD, S.tun_mode.PID = cfg, good, pid
            try:
                S.save_good_pinned()
                self.assertFalse(os.path.exists(good))
                os.utime(cfg, (now - 200, now - 200))
                S.save_good_pinned()
                self.assertTrue(os.path.exists(good))
            finally:
                S.PINNED_CFG, S.PINNED_GOOD, S.tun_mode.PID = old


if __name__ == "__main__":
    unittest.main()
