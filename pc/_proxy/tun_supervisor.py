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
import socket
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


DETOUR = os.path.join(HERE, "dns_detour.txt")


def dns_ok():
    """系统解析走 TUN 的 DoH；解析不出来就说明 DNS 通道挂了。"""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(6)
        socket.getaddrinfo("www.google.com", 443)
        return True
    except Exception:
        return False
    finally:
        socket.setdefaulttimeout(old)


def candidate_tags():
    try:
        with io.open(tun_mode.CFG, encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return []
    return [o.get("tag") for o in cfg.get("outbounds") or []
            if (o.get("tag") or "").startswith("g")
            and o.get("type") not in ("urltest", "direct")]


def rotate_dns_detour():
    """当前 DoH 出口解析不出东西时，换一颗节点重试。

    免费节点"在组里但连不上 1.1.1.1"是常态，urltest 会卡住；这里直接把
    dns_detour.txt 写成下一颗候选，restart() 会重新读它。
    """
    tags = candidate_tags()
    if not tags:
        return False
    cur = ""
    try:
        with io.open(DETOUR, encoding="utf-8") as f:
            cur = f.read().strip()
    except Exception:
        cur = ""
    nxt = tags[(tags.index(cur) + 1) % len(tags)] if cur in tags else tags[0]
    try:
        with io.open(DETOUR, "w", encoding="utf-8", newline="\n") as f:
            f.write(nxt)
    except Exception:
        return False
    log("DNS 解析失败，换 DoH 出口 -> %s" % nxt)
    return restart()


def stop_current():
    pid = read_pid(tun_mode.PID)
    if alive(pid):
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                           capture_output=True, creationflags=0x08000000)
        except Exception:
            pass
        time.sleep(1.0)


def restart():
    # 2026-11-23：先生成 + 校验新配置，再停旧进程。新配置过不了 sing-box check 时
    # 改用上一份能用的配置（singbox_tun.json），而不是直接放弃——以前 DNS 换出口时
    # 会先停掉活着的隧道，新配置一坏就整机断网。
    new_path = tun_mode.CFG + ".new"
    use = None
    try:
        cfg = tun_mode.build_config()
        with io.open(new_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(cfg if isinstance(cfg, str) else json.dumps(cfg, ensure_ascii=False, indent=1))
        rc, out = tun_mode.check_config(new_path)
        if rc == 0:
            use = new_path
        else:
            log("新配置校验失败，改用上一份配置: " + out[:300])
    except BaseException as e:  # build_config 用 SystemExit 报错
        log("生成新配置失败，改用上一份配置: %r" % (e,))
    if use is None:
        if os.path.isfile(tun_mode.CFG) and tun_mode.check_config(tun_mode.CFG)[0] == 0:
            use = tun_mode.CFG
        else:
            log("新旧配置都不可用，放弃本轮重建")
            return False
    stop_current()
    if use == new_path:
        os.replace(new_path, tun_mode.CFG)
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


def once():
    """计划任务模式：检查一次就退出。

    长驻进程会随父进程/作业对象被一起清掉（实测：由提权子进程拉起的守护在
    某些情况下会消失），改成计划任务每 2 分钟跑一次更可靠——任务本身由系统
    托管，不受启动脚本生死影响。
    """
    if not os.path.isfile(tun_mode.ACTIVE):
        return
    pid = read_pid(tun_mode.PID)
    if alive(pid):
        return
    log("计划任务检查：隧道进程 %s 不在，重建" % (pid or "?"))
    if not restart():
        log("计划任务重建失败，等下一轮")
        return
    if not dns_ok():
        log("重建后 DNS 仍不通，尝试换 DoH 出口")
        rotate_dns_detour()


def main():
    if "--once" in sys.argv:
        once()
        return
    with io.open(SUP_PID, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))
    log("supervisor 启动 pid=%d" % os.getpid())
    restarts = []
    tick = 0
    dns_fails = 0
    while True:
        time.sleep(10)
        if not os.path.isfile(tun_mode.ACTIVE):
            log("TUN_ACTIVE 已删除，退出")
            break
        pid = read_pid(tun_mode.PID)
        if not alive(pid):
            log("隧道进程 %s 已消失，开始重建" % (pid or "?"))
            if restart():
                restarts.append(time.time())
            continue

        # 进程活着，但 DNS 通道可能已经废了：每 60 秒验一次解析。
        tick += 1
        if tick % 6 == 0:
            if dns_ok():
                dns_fails = 0
            else:
                dns_fails += 1
                log("DNS 解析失败（第 %d 次）" % dns_fails)
                if dns_fails >= 2:
                    now = time.time()
                    recent = [t for t in restarts if now - t < 600]
                    if len(recent) < 5 and rotate_dns_detour():
                        restarts.append(now)
                        dns_fails = 0
        continue
    try:
        os.remove(SUP_PID)
    except Exception:
        pass


if __name__ == "__main__":
    main()
