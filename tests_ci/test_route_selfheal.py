# -*- coding: utf-8 -*-
"""CI 回归：出口存活自愈、PAC 内容校验、探针身份。

2026-11-18 的真实故障链（Claude 在浏览器里硬断）由四个独立缺陷接力造成，
每个缺陷单独看都不报错：

  1. autoroute.py --apply 无参调用 apply_pac()，落到 DEFAULT_GENERAL=9910
     （Geph 没运行）和 DEFAULT_FAST=2086（pinned 配置里没有这个 inbound）；
  2. apply_pac() 不校验端口存活，照样把 fail-closed 的 GENERAL 写出去；
  3. watchdog 的 PAC 自愈只比对 URL 和「服务器活着」，URL 没变 → 永不修复；
  4. autoroute 探测只带 UA，claude.ai 对「只有 UA 的 curl」返 403 挑战页 →
     anthropic 组被判全灭并从 route_map 里消失。

下面把这四个不变量钉死。无第三方依赖，也不写系统设置/不起进程。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "pc", "_proxy"))

import autoroute   # noqa: E402
import pacroute    # noqa: E402
import watchdog    # noqa: E402


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def test_pac_endpoints_roundtrip():
    """pac_endpoints 必须能从渲染出的 PAC 里反解出 GENERAL 的两个端口。

    这是看门狗「内容级自愈」的唯一输入；正则写飘了就会永远返回 None，
    自愈退化成只看 URL（等于没有）。
    """
    pac = pacroute.render_pac("127.0.0.1:2101", "127.0.0.1:2103")
    got = pacroute.pac_endpoints(pac)
    check(got == ("2101", "2103"), "pac_endpoints 解析错误: %r" % (got,))
    # 端口变化必须能被看出来，否则自愈会认为旧表仍然正确
    pac2 = pacroute.render_pac("127.0.0.1:2090", "127.0.0.1:9910")
    check(pacroute.pac_endpoints(pac2) == ("2090", "9910"),
          "pac_endpoints 对不同端口返回了同一个结果")


def test_resolve_ep_skips_dead_port():
    """要求一个没在监听的出口时，必须换成活的那个；一个都没有时返回 None。"""
    check(pacroute.resolve_ep("127.0.0.1:59999", "general") is None or
          not pacroute._port_open(59999),
          "resolve_ep 把死端口当成了可用出口")
    # 本机一个出口都没起时（CI 就是这种状态），必须明确返回 None，
    # 而不是把死端口写进 fail-closed 的 GENERAL 规则。
    live = pacroute.live_eps()
    for ep in live:
        check(pacroute.resolve_ep(ep, "general") == ep,
              "resolve_ep 把活端口 %s 换掉了" % ep)
    if not live:
        check(pacroute.resolve_ep(None, "general") is None,
              "没有任何活出口时 resolve_ep 应返回 None")


def test_apply_pac_refuses_without_live_exit():
    """全死时必须拒绝写 PAC，并回报 ok=False。

    这里只看返回值：apply_pac 在 ok=True 分支才会动注册表，
    CI 上走的是拒绝分支，不会污染 runner。
    """
    if pacroute.live_eps():
        return  # 有活出口的机器上不适用（会真的写注册表）
    info = pacroute.apply_pac("127.0.0.1:59998", "127.0.0.1:59999")
    check(info.get("ok") is False, "没有活出口时 apply_pac 居然返回了成功")
    check("no live local exit" in (info.get("err") or ""),
          "拒绝原因不明确: %r" % (info.get("err"),))


def test_probe_headers_are_browser_like():
    """探针必须发 Accept / Accept-Language / sec-ch-ua。

    只发 UA 时 claude.ai 返 403 挑战页，anthropic 组会被判全灭，
    claude.ai 掉回静态 GENERAL 规则 —— 这正是 2026-11-18 的现象。
    """
    blob = " ".join(autoroute.HDRS).lower()
    for frag in ("accept:", "accept-language:", "sec-ch-ua", "upgrade-insecure"):
        check(frag in blob, "autoroute 探针缺少请求头: %s" % frag)
    check("mozilla" in autoroute.UA.lower(), "autoroute 探针 UA 不是浏览器")
    wblob = " ".join(watchdog.PROBE_HDRS).lower()
    for frag in ("accept-language:", "sec-ch-ua"):
        check(frag in wblob, "watchdog 探针缺少请求头: %s" % frag)
    check("mozilla" in watchdog.PROBE_UA.lower(), "watchdog 探针 UA 不是浏览器")


def test_guard_backoff_and_respawn():
    """PAC 服务里的守夜人：退避期内不拉进程，退避失效才拉一次。

    真实故障场景（2026-11-18）：看门狗被外部 TerminateProcess，日志一行不写、
    状态文件停在最后一刻，出口坏了也没人修。守夜人必须自己判断「活着没」，
    而且不能在「拉起来就秒退」时无脑重试（会变成每 60 秒一个僵尸进程）。
    """
    import io as _io
    import json as _json
    import tempfile
    import time as _time

    tmp = tempfile.mkdtemp(prefix="guard_")
    old_guard, old_pid, old_spawn = pacroute.WD_GUARD, pacroute.WD_PID, pacroute._spawn_watchdog
    spawned = []
    try:
        pacroute.WD_PID = os.path.join(tmp, "watchdog.pid")
        pacroute.WD_GUARD = os.path.join(tmp, "guard.json")
        pacroute._spawn_watchdog = lambda: (spawned.append(1), 4242)[1]

        # 退避中：retry_at 在未来 -> 不拉
        with _io.open(pacroute.WD_GUARD, "w", encoding="utf-8") as f:
            _json.dump({"spawn_at": _time.time(), "retry_at": _time.time() + 900}, f)
        check(pacroute.guard_watchdog() is False, "退避期内仍然拉起了看门狗")
        check(not spawned, "退避期内不该 spawn")

        # 退避失效 -> 拉一次，并且因为上一次是「秒退」把 retry_at 推到未来
        with _io.open(pacroute.WD_GUARD, "w", encoding="utf-8") as f:
            _json.dump({"spawn_at": _time.time() - 5, "retry_at": 0}, f)
        check(pacroute.guard_watchdog() is True, "退避失效后没有拉起看门狗")
        check(len(spawned) == 1, "spawn 次数不对: %d" % len(spawned))
        g = _json.load(_io.open(pacroute.WD_GUARD, encoding="utf-8"))
        check(g["retry_at"] > _time.time(), "秒退后没有设置退避窗口")
    finally:
        pacroute.WD_GUARD, pacroute.WD_PID, pacroute._spawn_watchdog = old_guard, old_pid, old_spawn


def test_hk_gate_needs_candidate():
    """没有香港候选节点时，门控不能反复去重启一个不存在的出口。

    旧行为：每 5 分钟 spawn 一次 start_singbox_node，日志刷
    「HK node (Reddit) down -> restart」，实际 deep 池里 0 个 HK 节点。
    """
    orig = watchdog.hk_candidate
    try:
        watchdog.hk_candidate = lambda *a, **k: None
        watchdog._HK_POOL["at"] = 0.0
        watchdog._HK_POOL["uri"] = None
        check(watchdog.ensure_hk_node() is False,
              "没有候选时 ensure_hk_node 应返回 False")
    finally:
        watchdog.hk_candidate = orig


def test_doctor_module_imports():
    """doctor.py 必须能在无网络、无代理的机器上导入（CI 会跑它）。"""
    import doctor  # noqa: F401
    for name in ("check_ports", "check_pac", "check_sites", "check_exit_identity"):
        check(hasattr(doctor, name), "doctor 缺少检查项: %s" % name)


def main():
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        try:
            fn()
            print("PASS", name)
        except AssertionError as e:
            print("FAIL", name, "->", e)
            return 1
        except Exception as e:
            print("ERROR", name, "->", repr(e))
            return 1
    print("ALL PASS (%d)" % len(tests))
    return 0


if __name__ == "__main__":
    sys.exit(main())
