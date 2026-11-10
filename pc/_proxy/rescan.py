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


def main():
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
    print("\n[OK] 节点已重扫并重建出口，双击 启动代理.bat 完成 PAC 安装。", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
