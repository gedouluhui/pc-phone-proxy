# -*- coding: utf-8 -*-
"""CI 回归：PAC 分流 / SSRF 黑名单 / URI 脱敏。

这些规则一旦回退就是真实 IP 泄漏或凭据泄漏，必须每次 push 都跑。
无第三方依赖，直接 `python tests_ci/test_pacroute.py`。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "pc", "_proxy"))

import nodes  # noqa: E402
import pacroute  # noqa: E402


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def test_pac_private_and_default():
    pac = pacroute.render_pac()
    # 内网 / 链路本地 / CGNAT 必须直连
    for frag in ('"169.254.*"', '"100.6[4-9].*"', 'host.slice(-6) === ".local"',
                 'host.slice(-9) === ".internal"'):
        check(frag in pac, "PAC 缺少内网规则: %s" % frag)
    # 默认兜底必须走代理：开代理就要能打开所有国外站点（国内已在前面直连掉）
    tail = pac.split("function FindProxyForURL")[-1]
    check('return "PROXY ' in tail.split("if (inList(host, GENERAL))")[-1],
          "默认兜底没有走代理，未收录的国外站点会打不开")
    # GENERAL 必须 fail-closed，不能带 "; DIRECT"
    for line in tail.splitlines():
        if "inList(host, GENERAL)" in line:
            check("DIRECT" not in line, "GENERAL 仍是 fail-open: " + line.strip())
            break
    else:
        raise AssertionError("找不到 GENERAL 规则")


def test_sensitive_domains():
    pac = pacroute.render_pac()
    for d in ("pingan.com", "microsoftonline.com", "icloud.com"):
        check('"%s"' % d in pac, "SENSITIVE 缺少 " + d)


def test_ssrf_blacklist():
    bad = ["127.0.0.1", "localhost", "10.0.0.5", "192.168.1.1", "172.16.0.1",
           "169.254.169.254", "100.64.0.1", "::1", "fd00::1", "fe80::1",
           "metadata.google.internal", "printer.local"]
    for h in bad:
        check(nodes.is_forbidden_server(h), "SSRF 未拦截: " + h)
    good = ["1.1.1.1", "8.8.8.8", "example.com", "a.b.c.d.example.org"]
    for h in good:
        check(not nodes.is_forbidden_server(h), "误杀: " + h)


def test_redact_uri():
    cases = [
        "vless://11111111-2222-3333-4444-555555555555@example.com:443?x=1#HK",
        "trojan://secretpass@example.net:443#node",
        "ss://YWVzLTI1Ni1nY206cGFzcw==@example.org:8388",
    ]
    for u in cases:
        r = nodes.redact_uri(u)
        check("11111111" not in r and "secretpass" not in r
              and "YWVzLTI1Ni1nY206cGFzcw" not in r, "未脱敏: " + r)
        check("://" in r, "脱敏结果异常: " + r)
    check(nodes.redact_uri("") == "", "空 URI 应返回空串")


def main():
    tests = [test_pac_private_and_default, test_sensitive_domains,
             test_ssrf_blacklist, test_redact_uri]
    for t in tests:
        t()
        print("PASS", t.__name__)
    print("ALL PASS (%d)" % len(tests))


if __name__ == "__main__":
    main()
