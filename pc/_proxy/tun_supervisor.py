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
    2026-11-23：先经 clash API 实测哪些节点现在能到 1.1.1.1，只在活节点里挑最快的；
    以前按顺序轮换，会连续换到死节点、每次都重建一次隧道（14:10~14:15 连重建 5 次）。
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
    live = [t for _, t in live_tags(DNS_PROBE, tags) if t != cur]
    if live:
        nxt = live[0]
    else:
        nxt = tags[(tags.index(cur) + 1) % len(tags)] if cur in tags else tags[0]
    try:
        with io.open(DETOUR, "w", encoding="utf-8", newline="\n") as f:
            f.write(nxt)
    except Exception:
        return False
    log("DNS 解析失败，换 DoH 出口 -> %s" % nxt)
    return restart()


# ------------------------------------------------------------ 出口健康 / 自动重扫（2026-11-23）
API = "http://127.0.0.1:%d" % tun_mode.CLASH_PORT
DNS_PROBE = "https://1.1.1.1/cdn-cgi/trace"
GOOGLE_PROBE = "https://gemini.google.com/robots.txt"
REBUILD_REQ = os.path.join(HERE, "REBUILD_REQUEST")
RESCAN_REQ = os.path.join(HERE, "RESCAN_REQUEST")
SELFTEST_REQ = os.path.join(HERE, "SELFTEST_REQUEST")
BYPASS_EVERY = 6 * 3600       # 「测速进程能否绕开 TUN」自检结论的有效期
# 国内对照地址：直连必须能连上，证明临时 sing-box 本身是好的（否则「被墙地址连不上」没有意义）
BYPASS_CONTROL = [("110.242.68.66", 443), ("223.5.5.5", 443), ("120.232.145.144", 443)]
# 2026-11-23：闸门判据还没和浏览器实测对上之前，不因闸门结果主动重建隧道（每次重建断流数秒）；
# 闸门结论照样写 google_gate.json，下一次正常重建时用来筛 grp-google 成员。
GATE_REBUILD = False
RESCAN_LOCK = os.path.join(HERE, "rescan.lock")
HEALTH = os.path.join(HERE, "logs", "pool_health.json")
HEALTH_EVERY = 15 * 60        # 每 15 分钟量一次「能上 Google 的出口还剩几个」
RESCAN_GAP = 3 * 3600         # 两次自动重扫至少间隔 3 小时
RESCAN_STALE = 24 * 3600      # 节点池超过 24 小时没刷新就重扫
GOOGLE_MIN = 3                # 能上 Gemini 的出口少于这个数就重扫


def api_delay(tag, url, timeout_ms=5000):
    """经 TUN 自己的 clash API 让某个出口实测一次 url；>0 = 毫秒，0 = 不通。"""
    import urllib.parse
    import urllib.request
    q = urllib.parse.urlencode({"url": url, "timeout": timeout_ms})
    req = "%s/proxies/%s/delay?%s" % (API, urllib.parse.quote(tag), q)
    try:
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with op.open(req, timeout=timeout_ms / 1000.0 + 3) as r:
            d = json.loads(r.read().decode("utf-8", "replace") or "{}").get("delay")
            return int(d) if isinstance(d, int) and d > 0 else 0
    except Exception:
        return 0


def live_tags(url, tags):
    """并发测一遍，返回 [(delay, tag), ...] 升序；clash API 不通时返回 []。"""
    from concurrent.futures import ThreadPoolExecutor
    tags = list(tags or [])
    if not tags:
        return []
    with ThreadPoolExecutor(max_workers=min(12, len(tags))) as ex:
        res = list(ex.map(lambda t: (api_delay(t, url), t), tags))
    return sorted((d, t) for d, t in res if d > 0)


def _load_health():
    try:
        with io.open(HEALTH, encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _save_health(h):
    try:
        os.makedirs(os.path.dirname(HEALTH), exist_ok=True)
        with io.open(HEALTH, "w", encoding="utf-8", newline="\n") as f:
            json.dump(h, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


def rescan_running(now=None):
    now = now or time.time()
    try:
        with io.open(RESCAN_LOCK, encoding="utf-8") as f:
            j = json.load(f)
        pid, at = int(j.get("pid") or 0), float(j.get("at") or 0)
    except Exception:
        return False
    return now - at < 2 * 3600 and bool(pid) and P.pid_alive(pid)


def decide_rescan(now, deep_mtime, google_live, last_rescan, running, requested=False):
    """返回重扫原因（字符串）或 None。纯函数，tests_ci 覆盖。"""
    if running:
        return None
    if requested:
        return "用户/维护请求重扫"
    if now - (last_rescan or 0) < RESCAN_GAP:
        return None
    if google_live is not None and google_live < GOOGLE_MIN:
        return "能上 Gemini 的出口只剩 %d 个" % google_live
    if deep_mtime and now - deep_mtime > RESCAN_STALE:
        return "节点池超过 24 小时没刷新"
    return None


def running_has_direct_rule():
    """正在用的 TUN 配置里有没有「测速进程直连」规则；没有的话先重建再扫，否则测出假结果。"""
    try:
        with io.open(tun_mode.CFG, encoding="utf-8") as f:
            rules = (json.load(f).get("route") or {}).get("rules") or []
        return any("process_name" in r and r.get("outbound") == "direct" for r in rules)
    except Exception:
        return False


def start_rescan(reason):
    py = sys.executable
    logf = io.open(os.path.join(HERE, "logs", "rescan_auto.log"), "ab")
    try:
        env = dict(os.environ, RESCAN_REBUILD="1", PYTHONIOENCODING="utf-8")
        p = subprocess.Popen([py, os.path.join(HERE, "rescan.py")], cwd=HERE, env=env,
                             stdout=logf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                             creationflags=(0x00000008 | 0x00000200 | 0x08000000))
    finally:
        logf.close()
    with io.open(RESCAN_LOCK, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"pid": p.pid, "at": time.time(), "reason": reason}, f, ensure_ascii=False)
    log("自动重扫节点：%s（pid=%d，日志 logs/rescan_auto.log）" % (reason, p.pid))


def running_google_keys():
    """当前隧道 grp-google 成员的 server:port 列表。"""
    try:
        with io.open(tun_mode.CFG, encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return []
    obs = {o.get("tag"): o for o in cfg.get("outbounds") or []}
    grp = obs.get("grp-google-auto") or obs.get("grp-google") or {}
    import google_gate
    return [google_gate.node_key(obs[t]) for t in grp.get("outbounds") or [] if t in obs]


def gate_needs_rebuild(member_keys, verdicts):
    """grp-google 里有被 Google 判「不支持地区」的成员，且换了能变好 -> True（纯函数）。"""
    bad = [k for k in member_keys if verdicts.get(k) == "bad"]
    if not bad:
        return False
    ok_all = [k for k, v in verdicts.items() if v == "ok"]
    ok_members = [k for k in member_keys if verdicts.get(k) == "ok"]
    # 有 ok 的节点却没全部用上，或组里混着 bad 的：按闸门结果重建
    return bool(ok_all) and (len(bad) > 0 and set(ok_members) != set(member_keys))


PINNED_CFG = os.path.join(HERE, "singbox_pinned.json")
PINNED_GOOD = os.path.join(HERE, "singbox_pinned.good.json")
SWITCH_MIN_LIVE = 2   # 新节点池实测至少这么多出口能连上（ok/bad 都算连上）才允许切换


def pool_switch_ok(verdicts, min_live=SWITCH_MIN_LIVE):
    """新节点池能不能切过去（纯函数，tests_ci 覆盖）。

    2026-11-23 17:34 事故：重扫在「没有直连规则的旧隧道」下跑完，深测数据被二次转发污染，
    30 个新出口在本机直连全部连不上；闸门已经测出全部 err，但旧逻辑「继续重建」，
    整机断网 30 分钟。现在：闸门有结论且能连上的不足 min_live 个，就拒绝切换。
    闸门没跑出任何结论（空字典，比如 sing-box 缺失）时不拦，保持旧行为。
    """
    if not verdicts:
        return True
    live = sum(1 for v in verdicts.values() if v in ("ok", "bad"))
    return live >= min_live


def save_good_pinned():
    """当前隧道实测健康时，把生成它的节点池存一份，切换失败时可以回退。"""
    try:
        if not os.path.isfile(PINNED_CFG):
            return
        # 只在「隧道是用当前这份节点池建的」时才存：节点池比隧道进程新，说明还没切过去
        if os.path.getmtime(PINNED_CFG) > os.path.getmtime(tun_mode.PID) + 1:
            return
        import shutil
        shutil.copy2(PINNED_CFG, PINNED_GOOD)
    except Exception:
        pass


def restore_good_pinned():
    """把 singbox_pinned.json 换回上一份实测能用的；没有备份就保持原样。"""
    try:
        if os.path.isfile(PINNED_GOOD):
            import shutil
            if os.path.isfile(PINNED_CFG):
                shutil.copy2(PINNED_CFG, PINNED_CFG + ".rejected")
            shutil.copy2(PINNED_GOOD, PINNED_CFG)
            log("已恢复上一份可用节点池（被拒的新池存为 singbox_pinned.json.rejected）")
            return True
    except Exception as e:
        log("恢复节点池失败: %r" % (e,))
    return False


def run_gate(h, now, source="tun"):
    import google_gate
    obs = google_gate.pinned_outbounds() if source == "pinned" else google_gate.tun_outbounds()
    v = google_gate.check_many(obs, log=log)
    h.update(gate_at=now, gate_ok=sum(1 for x in v.values() if x == "ok"),
             gate_bad=sum(1 for x in v.values() if x == "bad"))
    _save_health(h)
    return v


def bypass_verdict(blocked, control):
    """临时 sing-box 绕开 TUN 了吗（纯函数）。blocked/control: [bool 连上了吗]。

    国内对照至少一个连上（进程本身正常），且被墙地址连上不足 2 个（没被隧道转发）。"""
    return any(control) and sum(1 for b in blocked if b) < 2


def bypass_selftest():
    """TUN 开着时实测：临时 sing-box 用哪种方式能绕开隧道。结论写 logs/bypass_mode.json。"""
    import asyncio
    import nodes as N
    import rescan
    modes = [("auto", None, {"auto_detect_interface": True})]
    for name in N.physical_iface_names():
        modes.append(("iface", name, {"default_interface": name}))
    tried = []
    chosen = {"mode": "none"}
    for mode, iface, route in modes:
        proc = N._start_direct_socks(route=route)
        if proc is None:
            tried.append([mode, iface, "起不来"])
            continue
        try:
            async def run():
                async def one(ip, port):
                    try:
                        return bool(await N.socks_connect(ip, port, 4.0))
                    except Exception:
                        return False
                return await asyncio.gather(*[one(ip, pt) for ip, pt in rescan.CANARIES + BYPASS_CONTROL])
            res = list(asyncio.run(run()))
        finally:
            try:
                proc.kill()
                proc.wait(3)
            except Exception:
                pass
        nb = len(rescan.CANARIES)
        ok = bypass_verdict(res[:nb], res[nb:])
        tried.append([mode, iface, "被墙%s 国内%s" % (res[:nb], res[nb:])])
        if ok:
            chosen = {"mode": mode, "iface": iface}
            break
    chosen.update(at=time.time(), tried=tried)
    try:
        os.makedirs(os.path.dirname(N.BYPASS_FILE), exist_ok=True)
        with io.open(N.BYPASS_FILE, "w", encoding="utf-8") as f:
            json.dump(chosen, f, ensure_ascii=False, indent=1)
    except OSError:
        pass
    log("测速进程绕开 TUN 自检：%s（%s）" % (
        "可用：" + chosen["mode"] + (" " + chosen["iface"] if chosen.get("iface") else "")
        if chosen["mode"] != "none" else "全部失败，TUN 开着时不重扫", tried))
    return chosen["mode"] != "none"


def bypass_ready(now):
    """TUN 开着时，重扫前必须有新鲜且通过的绕开自检。"""
    if not os.path.isfile(tun_mode.ACTIVE):
        return True
    import nodes as N
    m = N.load_bypass_mode()
    if m.get("mode") not in (None, "none") and now - float(m.get("at") or 0) <= BYPASS_EVERY:
        return True
    return bypass_selftest()


def maintain(now=None):
    """计划任务每分钟调用一次：处理重建/重扫请求、Google 地区闸门、出口太少就自动重扫。"""
    now = now or time.time()
    h = _load_health()
    if os.path.isfile(SELFTEST_REQ):
        try:
            os.remove(SELFTEST_REQ)
        except OSError:
            pass
        try:
            bypass_selftest()
        except Exception as e:
            log("绕开 TUN 自检出错: %r" % (e,))
        return
    if os.path.isfile(REBUILD_REQ):
        try:
            os.remove(REBUILD_REQ)
        except OSError:
            pass
        # 新节点池（bestroute 刚写的 singbox_pinned.json）先过 Google 地区闸门，再按它重建
        verdicts = {}
        try:
            verdicts = run_gate(h, now, source="pinned")
        except Exception as e:
            log("新节点池地区闸门出错（继续重建）: %r" % (e,))
        if not pool_switch_ok(verdicts):
            live = sum(1 for v in verdicts.values() if v in ("ok", "bad"))
            log("新节点池实测只有 %d/%d 个出口能连上，拒绝切换，当前隧道保持不动" % (live, len(verdicts)))
            restore_good_pinned()
            return
        log("收到重建请求（新节点池就绪），按新配置重建隧道")
        if not restart():
            log("重建失败，旧隧道已保留")
        return
    requested = os.path.isfile(RESCAN_REQ)
    if requested or now - float(h.get("checked_at") or 0) >= HEALTH_EVERY:
        h["checked_at"] = now
        try:
            verdicts = run_gate(h, now)
        except Exception as e:
            log("地区闸门出错: %r" % (e,))
            verdicts = {}
        members = running_google_keys()
        if GATE_REBUILD and gate_needs_rebuild(members, verdicts):
            if now - float(h.get("last_gate_rebuild") or 0) >= 1800:
                h["last_gate_rebuild"] = now
                _save_health(h)
                log("Google 出口里有被判「不支持地区」的节点，按闸门结果重建隧道")
                restart()
        h["google_live"] = h.get("gate_ok", 0)
        _save_health(h)
        if sum(1 for v in (verdicts or {}).values() if v in ("ok", "bad")) >= SWITCH_MIN_LIVE:
            save_good_pinned()
    google_live = h.get("google_live")
    try:
        deep_mtime = os.path.getmtime(os.path.join(HERE, "node_deep.json"))
    except OSError:
        deep_mtime = 0
    reason = decide_rescan(now, deep_mtime, google_live, h.get("last_rescan"),
                           rescan_running(now), requested)
    if not reason:
        return
    if requested:
        try:
            os.remove(RESCAN_REQ)
        except OSError:
            pass
    # 2026-11-23：以前这里检查 TUN 配置里有没有 process_name 直连规则；那条规则本身会让整机外网全断，
    # 已删除。现在改为：测速进程能自己绕开 TUN（自检通过）才重扫，否则测出的是「节点套节点」假数据。
    try:
        ready = bypass_ready(now)
    except Exception as e:
        log("绕开 TUN 自检出错: %r" % (e,))
        ready = False
    if not ready:
        h["last_rescan"] = now          # 3 小时后再试，别每分钟都自检
        _save_health(h)
        log("测速进程无法绕开 TUN，本轮不重扫，节点池保持不动")
        return
    h["last_rescan"] = now
    _save_health(h)
    start_rescan(reason.replace("能上 Gemini 的出口", "过 Google 地区闸门的出口"))


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
    # 2026-11-23：先用 .new 启动，进程活下来才改名成 singbox_tun.json。以前先改名再启动，
    # 新进程立刻退出时磁盘上的配置已经是新的，running_has_direct_rule() 就会误以为
    # 「正在跑的隧道已有直连规则」，在旧隧道下开始重扫（17:09 事故的一环）。
    logf = io.open(tun_mode.SB_LOG, "ab")
    try:
        p = subprocess.Popen([P.SING_EXE, "run", "-c", use], cwd=HERE,
                             stdout=logf, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL,
                             creationflags=(0x00000008 | 0x00000200))
    finally:
        logf.close()
    time.sleep(2.0)
    if p.poll() is not None:
        # 计划任务与常驻守护可能同时重建（2026-11-23 17:09 实测）：对方先起来、占住网卡和
        # 控制端口，我们这份就会立刻退出。此时隧道其实是好的，不算失败。
        other = read_pid(tun_mode.PID)
        if other and other != p.pid and alive(other):
            log("另一个守护已完成重建（pid=%d），本次不再重复" % other)
            return True
        log("重建后立即退出 (%s)，见 tun_singbox.log" % p.returncode)
        if use == new_path:
            try:
                os.remove(new_path)
            except OSError:
                pass
        return False
    if use == new_path:
        try:
            os.replace(new_path, tun_mode.CFG)
        except OSError:
            # 运行中的 sing-box 不锁配置文件，正常不会到这里；万一失败就复制一份
            try:
                import shutil
                shutil.copyfile(new_path, tun_mode.CFG)
            except OSError:
                pass
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
        # 隧道健在：顺带做出口健康维护（重建/重扫请求、能上 Google 的出口太少就自动重扫）。
        # 任何异常都只记日志，绝不影响正在跑的隧道。
        try:
            maintain()
        except Exception as e:
            log("维护检查出错（隧道未受影响）: %r" % (e,))
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
