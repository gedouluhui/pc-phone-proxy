# -*- coding: utf-8 -*-
"""TUN 模式的自愈看门狗。

为什么需要它：TUN 的 sing-box 是 DETACHED 进程，启动脚本退出后没人再看它一眼。
一旦它被系统收走（驱动更新重置网卡、内存压力、Wintun 异常），`pcproxy` 网卡会
跟着消失，用户看到的是「网突然断了」，而不会有人去双击「启动代理」——
分流模式有 watchdog.py 管，TUN 模式此前没有。

策略（保守，宁可不动也别乱动）：
- 只在 TUN_ACTIVE 存在（用户本意是开着）且 tun.pid 里的进程已经不在了时才重建；
- 重建用 tun_mode.build_config 现算配置，先 `sing-box check` 再启动；
- 10 分钟内最多重启 5 次，超过就退避 60 秒，避免和系统性问题互相放大；
- stop 流程（tun_mode stop）会删 TUN_ACTIVE 并杀掉 supervisor。

以管理员身份随隧道一起拉起；普通权限下起不来（建不了网卡），日志会写清楚。
"""
import io
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import tun_mode  # noqa: E402
import proxyctl as P  # noqa: E402

SUP_PID = os.path.join(HERE, "tun_supervisor.pid")
LOG = os.path.join(HERE, "logs", "tun_supervisor.log")


def log(msg):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with io.open(LOG, "a", encoding="utf-8", newline="\n") as f:
            f.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass


def read_pid(path):
    try:
        with io.open(path, encoding="utf-8") as f:
            return int(f.read().strip())
    except Exception:
        return 0


def alive(pid):
    if not pid:
        return False
    try:
        return P.pid_alive(pid) and "sing-box" in P.pid_cmdline(pid).lower()
    except Exception:
        return False


def restart():
    cfg = tun_mode.build_config()
    with io.open(tun_mode.CFG, "w", encoding="utf-8", newline="\n") as f:
        f.write(cfg if isinstance(cfg, str) else json.dumps(cfg, ensure_ascii=False, indent=1))
    rc, out = tun_mode.check_config(tun_mode.CFG)
    if rc != 0:
        log("配置校验失败，放弃本轮重建: " + out[:300])
        return False
    logf = io.open(tun_mode.SB_LOG, "ab")
    try:
        p = subprocess.Popen([P.SING_EXE, "run", "-c", tun_mode.CFG], cwd=HERE,
                             stdout=logf, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL,
                             creationflags=(0x00000008 | 0x00000200))
    finally:
        logf.close()
    time.sleep(2.0)
    if p.poll() is not None:
        log("重建后立即退出 (%s)，见 tun_singbox.log" % p.returncode)
        return False
    with io.open(tun_mode.PID, "w", encoding="utf-8") as f:
        f.write(str(p.pid))
    log("已重建隧道 pid=%d" % p.pid)
    return True


def main():
    with io.open(SUP_PID, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))
    log("supervisor 启动 pid=%d" % os.getpid())
    restarts = []
    while True:
        time.sleep(10)
        if not os.path.isfile(tun_mode.ACTIVE):
            log("TUN_ACTIVE 已删除，退出")
            break
        pid = read_pid(tun_mode.PID)
        if alive(pid):
            continue
        now = time.time()
        restarts = [t for t in restarts if now - t < 600]
        if len(restarts) >= 5:
            log("10 分钟内已重启 5 次，退避 60 秒")
            time.sleep(60)
            continue
        log("隧道进程 %s 已消失，开始重建" % (pid or "?"))
        if restart():
            restarts.append(now)
    try:
        os.remove(SUP_PID)
    except Exception:
        pass


if __name__ == "__main__":
    main()
