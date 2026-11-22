# -*- coding: utf-8 -*-
"""CI 回归：低速假死流放行。

看门狗以前只按「累计下载 >20MB」延迟重建，于是一个掉到 10KB/s、
要跑十小时的连接会把重建锁死 10 分钟又 10 分钟。这里钉死判定：
活跃大流量必须保护，年满 60 秒且速率低于 30KB/s 的僵尸流只有在
深测数据存在 3 倍以上备选时才放行。
"""
import datetime
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "pc", "_proxy"))

import watchdog  # noqa: E402


def conn(download_mb, chains=("g0", "grp-general"), age=600):
    return {"download": int(download_mb * 1048576), "chains": list(chains),
            "age": age}


class ZombieReleaseTests(unittest.TestCase):
    def test_fast_download_is_protected(self):
        report = watchdog.classify_bulk({"c1": conn(5)}, {"c1": conn(25)}, 4.0)
        self.assertEqual(len(report["active"]), 1, report)
        self.assertFalse(report["zombie"], report)

    def test_stalled_old_flow_is_zombie(self):
        report = watchdog.classify_bulk({"c1": conn(25)},
                                        {"c1": conn(25.08)}, 4.0)
        self.assertFalse(report["active"], report)
        self.assertEqual(len(report["zombie"]), 1, report)
        self.assertLess(report["zombie"][0]["rate"], 30)

    def test_young_flow_gets_grace(self):
        report = watchdog.classify_bulk({"c1": conn(25, age=30)},
                                        {"c1": conn(25.08, age=34)}, 4.0)
        self.assertEqual(len(report["active"]), 1, report)
        self.assertFalse(report["zombie"], report)

    def test_direct_and_small_flows_ignored(self):
        first = {"c1": conn(100, chains=("direct",)), "c2": conn(1)}
        second = {"c1": conn(100, chains=("direct",)), "c2": conn(1)}
        report = watchdog.classify_bulk(first, second, 4.0)
        self.assertFalse(report["active"] or report["zombie"], report)

    def test_new_flow_uses_lifetime_average(self):
        report = watchdog.classify_bulk({}, {"c1": conn(25, age=1000)}, 4.0)
        self.assertEqual(len(report["zombie"]), 1, report)
        report = watchdog.classify_bulk({}, {"c1": conn(25, age=None)}, 4.0)
        self.assertEqual(len(report["active"]), 1, report)

    def test_counter_regression_does_not_crash(self):
        report = watchdog.classify_bulk({"c1": conn(30)}, {"c1": conn(25)}, 4.0)
        self.assertEqual(report["zombie"][0]["rate"], 0)

    def test_better_candidate_requires_clear_margin(self):
        tags = {"g0": "10.0.0.1"}
        deep = {"10.0.0.1": 50, "10.0.0.2": 200}
        self.assertEqual(watchdog.better_candidate(
            ["g0", "grp-general"], 10, deep, tags), ("10.0.0.2", 200))
        self.assertIsNone(watchdog.better_candidate(
            ["g0"], 50, {"10.0.0.1": 60}, tags))
        self.assertEqual(watchdog.better_candidate(["g0"], 50, deep, tags),
                         ("10.0.0.2", 200))
        self.assertIsNone(watchdog.better_candidate(["g0"], 10, {}, tags))
        self.assertIsNone(watchdog.better_candidate(
            ["g0"], 80, {"10.0.0.2": 150}, tags))

    def test_connection_age_parses_clash_timestamp(self):
        now = datetime.datetime(2026, 11, 23, 12, 0, 0,
                                tzinfo=datetime.timezone.utc)
        age = watchdog._conn_age("2026-11-23T11:58:00.123456789+00:00", now)
        self.assertAlmostEqual(age, 119.876544, places=3)
        self.assertIsNone(watchdog._conn_age("garbage", now))


if __name__ == "__main__":
    unittest.main(verbosity=2)