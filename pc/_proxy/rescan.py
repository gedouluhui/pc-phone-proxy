# -*- coding: utf-8 -*-
"""Re-harvest public proxy sources, deep-test the survivors, rebuild the exits.

Only needed when every pinned node has died (weeks later, or on a very
different network). Takes 10-40 minutes. Bootstrap needs *some* working HTTP
proxy to reach the source lists: the currently running fast exit (2103) if it
is up, otherwise direct.
"""
import os
import socket
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def up(port):
    s = socket.socket()
    s.settimeout(0.4)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


def run(script, *args, env=None):
    cmd = [sys.executable, os.path.join(HERE, script)] + list(args)
    print("\n$ " + " ".join(cmd[1:]), flush=True)
    return subprocess.call(cmd, cwd=HERE, env=env, creationflags=0x08000000)


# 大陆直连必然连不上的地址（Google / Facebook 的 443）。测速进程如果能连上它们，说明它的
# 流量其实被当前隧道转发了出去，这一轮深测会把「节点套节点」当成可用节点（2026-11-23 17:10
# 那次重扫就是这样：旧隧道没有直连规则，30 个「1.8~2 MB/s」的新出口切过去后全部连不上）。
CANARIES = [("142.250.80.46", 443), ("172.217.14.206", 443), ("31.13.82.36", 443)]


def canary_contaminated(results):
    """results: [bool 连上了吗, ...] -> True = 测速路径被转发污染（纯函数，tests_ci 覆盖）。

    两个以上被墙地址都连上才算污染：单个地址偶尔能通（运营商/地区差异）不误判。"""
    return sum(1 for r in results if r) >= 2


def direct_path_contaminated():
    """TUN 开着时用「测速同款」的 sing-box 直连 SOCKS 探一次被墙地址。

    返回 (污染?, 说明)。探不了（缺 sing-box / 端口起不来）时返回 (None, 原因)，由调用方决定。"""
    try:
        import asyncio
        import nodes as N
    except Exception as e:
        return None, "导入 nodes 失败: %r" % (e,)
    proc = None
    try:
        proc = N._start_direct_socks()
        if proc is None:
            return None, "直连 SOCKS 起不来"

        async def probe_all():
            async def one(ip, port):
                try:
                    return bool(await N.socks_connect(ip, port, 4.0))
                except Exception:
                    return False
            return await asyncio.gather(*[one(ip, port) for ip, port in CANARIES])

        res = asyncio.run(probe_all())
        return canary_contaminated(res), "被墙地址探测结果 %s" % (list(res),)
    except Exception as e:
        return None, "探测出错: %r" % (e,)
    finally:
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass


def main():
    if os.path.isfile(os.path.join(HERE, "TUN_ACTIVE")):
        bad, why = direct_path_contaminated()
        print("TUN 开着，检查测速路径是否直连：%s" % why, flush=True)
        if bad:
            print("[中止] 测速进程的流量正被当前隧道转发，这时深测会把不可达的节点当成可用。"
                  "本轮不扫，节点池保持不变。重启一次 TUN（启动代理.bat 选 2）后再扫。", flush=True)
            return 3
    env = dict(os.environ)
    boot = "http://127.0.0.1:2103" if up(2103) else ""
    if boot:
        env["BOOT_PROXY"] = boot
        print("bootstrap proxy: " + boot)
    else:
        print("bootstrap: direct (2103 not running)")
    if run("harvest.py", env=env) != 0:
        if boot:
            print("通过 2103 抓取失败，改直连重试 ...", flush=True)
            env["BOOT_PROXY"] = ""
            if run("harvest.py", env=env) != 0:
                print("[失败] 公共源一个都抓不到，检查本机网络。", flush=True)
                return 1
        else:
            print("[失败] 公共源抓不到，检查本机网络。", flush=True)
            return 1
    if run("deep_test.py", "--stage", "all", "--deep-k", "96",
           "--workers", "4") != 0:
        print("[失败] 深测没跑完。", flush=True)
        return 1
    if run("bestroute.py", "--apply") != 0:
        print("[失败] 没能从深测结果里组出可用出口。", flush=True)
        return 1
    # TUN 开着且是自愈任务发起的重扫：请它用新节点池重建隧道（先校验再切换）。
    # 手动双击「重新扫描节点」时也一样，省得用户再点一次启动。
    if os.path.isfile(os.path.join(HERE, "TUN_ACTIVE")):
        try:
            with open(os.path.join(HERE, "REBUILD_REQUEST"), "w", encoding="utf-8") as f:
                f.write("rescan")
            print("\n[OK] 节点已重扫，TUN 会在 1 分钟内自动换用新节点（先校验，坏配置不会生效）。", flush=True)
        except OSError:
            print("\n[OK] 节点已重扫；TUN 模式请双击 启动代理.bat 选 2 换用新节点。", flush=True)
        return 0
    print("\n[OK] 节点已重扫并重建出口，双击 启动代理.bat 完成 PAC 安装。", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
