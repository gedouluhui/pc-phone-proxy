# -*- coding: utf-8 -*-
"""Keeper for the portable exit chain.  Started hidden by 启动代理.bat.

What it does (all state goes to watchdog_status.json + logs/watchdog.log):

  every  20s  look for the STOP sentinel (关闭代理.bat) and exit cleanly
  every  60s  are 2101 / 2103 / 2090 still listening?  two misses -> rebuild
  every 300s  light gate: ChatGPT through 2101, gstatic 204 through 2103/2090;
              two consecutive misses -> rebuild from the deep-test pool
  every 300s  HK node (Reddit) down -> restart it on the same ports
  every 120s  PAC still installed and served?  env vars still exported?
              (a browser or a cleanup tool can remove them) -> re-apply
  every  90s  read the clash API: which member urltest is using now, log every
              automatic switch with its live delay
  last resort three failed rebuilds in a row -> rescan.py (10-40 min), at most
              once per 12 h.  rescan.py ends by rebuilding the exits itself.

Everything is PID-targeted and image-checked; this never kills by name.
"""
import io
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pacroute           # noqa: E402
import proxyctl as P      # noqa: E402
import sysstate           # noqa: E402

GEN, FAST, CLI, HK, STEAM = 2101, 2103, 2090, 2086, 2096
STOP = os.path.join(HERE, "STOP_WATCHDOG")
PID = os.path.join(HERE, "watchdog.pid")
STATUS = os.path.join(HERE, "watchdog_status.json")
LOG = os.path.join(HERE, "logs", "watchdog.log")
PIDS = ("sing-box.exe",)
# This process runs without a console.  Any console child (curl/tasklist/
# netstat/python) would otherwise open a fresh Windows Terminal window on
# every health check, which the user sees as a black flash.
NOWIN = 0x08000000

PY = os.path.join(os.path.dirname(sys.executable), "python.exe")
if not os.path.isfile(PY):
    PY = sys.executable

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def log(msg):
    line = time.strftime("[%m-%d %H:%M:%S] ") + msg
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with io.open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass
    try:
        print(line, flush=True)
    except Exception:
        pass


def up(port):
    try:
        return P.listen_ok(port)
    except Exception:
        return False


def http_json(url, timeout=3.0):
    with _OPENER.open(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def clash_now(group):
    try:
        j = http_json("http://127.0.0.1:9090/proxies/" + group)
        h = j.get("history") or []
        return j.get("now"), (h[-1].get("delay") if h else None)
    except Exception:
        return None, None


def nudge(group):
    """Force an immediate health re-check of every member in a urltest group.

    The groups only re-evaluate on their own 90s timer, so a member that dies
    right after a cycle can black-hole the gate for up to ~90s even though the
    other members are healthy.  The clash API group delay runs the same
    gstatic probe on all members right now; sing-box then re-picks.  Returns
    the number of members still alive (-1 when the API itself is unreachable,
    which means the failure is the whole process, not one node).
    """
    try:
        q = urllib.parse.urlencode(
            {"url": "http://www.gstatic.com/generate_204", "timeout": "5000"})
        j = http_json("http://127.0.0.1:9090/group/%s/delay?%s" % (group, q),
                      timeout=40)

        def alive_ms(v):
            if isinstance(v, dict):
                return v.get("delay") or 0
            try:
                return int(v)
            except (TypeError, ValueError):
                return 0

        alive = [k for k, v in (j or {}).items() if alive_ms(v) > 0]
        log("nudge %s -> %d/%d alive%s"
            % (group, len(alive), len(j or {}),
               (": " + ",".join(alive[:4])) if alive else ""))
        return len(alive)
    except Exception as e:
        log("nudge %s failed: %r" % (group, e))
        return -1


def curl_probe(url, port, timeout=18):
    args = ["curl", "-sS", "--ssl-no-revoke", "--max-time", str(timeout),
            "-o", "NUL", "-w", "%{http_code} %{size_download}",
            "-x", "http://127.0.0.1:%d" % int(port), url]
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           errors="replace", timeout=timeout + 8,
                           creationflags=NOWIN)
        parts = (p.stdout or "").split()
        code = parts[0] if parts else "000"
        size = int(float(parts[1])) if len(parts) > 1 else 0
        return code, size
    except Exception:
        return "000", 0


def run_script(script, *args, **kw):
    timeout = kw.pop("timeout", 420)
    logfile = kw.pop("logfile", "watchdog_jobs.log")
    path = os.path.join(HERE, "logs", logfile)
    try:
        with open(path, "ab") as lf:
            p = subprocess.run([PY, os.path.join(HERE, script)] + list(args),
                               cwd=HERE, stdout=lf, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL, timeout=timeout,
                               creationflags=NOWIN)
        return p.returncode
    except Exception as e:
        log("run %s failed: %r" % (script, e))
        return -1


def spawn_script(script, logfile):
    path = os.path.join(HERE, "logs", logfile)
    try:
        with open(path, "ab") as lf:
            subprocess.Popen([PY, os.path.join(HERE, script)], cwd=HERE,
                             stdout=lf, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL,
                             creationflags=0x00000008 | 0x08000000)
        return True
    except Exception as e:
        log("spawn %s failed: %r" % (script, e))
        return False


def pac_apply():
    info = pacroute.apply_pac("127.0.0.1:%d" % GEN, "127.0.0.1:%d" % FAST)
    return bool(info.get("ok"))


def rebuild(reason, st):
    now = time.time()
    if now - st["last_rebuild"] < st["rebuild_cooldown"]:
        log("rebuild skipped (cooldown %ds): %s"
            % (st["rebuild_cooldown"] - (now - st["last_rebuild"]), reason))
        return False
    st["last_rebuild"] = now
    log("REBUILD (%s)" % reason)
    rc = run_script("bestroute.py", "--apply", timeout=420, logfile="watchdog_rebuild.log")
    if rc == 0:
        st["rebuild_fail"] = 0
        log("rebuild OK; PAC + env re-applied")
        pac_apply()
        sysstate.apply_env(CLI)
        return True
    st["rebuild_fail"] += 1
    log("rebuild FAILED rc=%s (%d in a row)" % (rc, st["rebuild_fail"]))
    if st["rebuild_fail"] >= 3 and now - st["last_rescan"] > st["rescan_cooldown"]:
        st["last_rescan"] = now
        st["rebuild_fail"] = 0
        if spawn_script("rescan.py", "rescan.log"):
            log("all rebuilds failed -> rescan public sources (10-40 min, logs/rescan.log)")
    return False


def hk_up():
    return up(HK)


def ensure_hk_node():
    if hk_up():
        return True
    log("HK node (Reddit) down -> restart")
    try:
        import start_proxy as S
        return bool(S.ensure_hk())
    except Exception as e:
        log("HK restart failed: %r" % (e,))
        return False


def steam_up():
    """US exit for Steam / Wallpaper Engine: listening AND store says US."""
    if not up(STEAM):
        return False
    try:
        import start_proxy as S
        return bool(S._steam_ok())
    except Exception:
        return False


def ensure_steam_node():
    if steam_up():
        return True
    log("US Steam exit down/wrong region -> restart")
    try:
        import start_proxy as S
        ok = bool(S.ensure_steam())
    except Exception as e:
        log("Steam restart failed: %r" % (e,))
        return False
    if ok:
        # PAC drops the STEAM rule when 2096 was closed at apply time
        pac_apply()
    return ok


def write_status(st):
    data = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pid": os.getpid(),
        "ports": {str(p): up(p) for p in (GEN, FAST, CLI, HK, STEAM)},
        "now": st["now"],
        "rebuilds": st["rebuilds"],
        "rebuild_fail": st["rebuild_fail"],
        "last_rebuild": (time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                       time.gmtime(st["last_rebuild"]))
                         if st["last_rebuild"] else None),
        "gate": st["gate"],
        "last_error": st["last_error"],
    }
    try:
        tmp = STATUS + ".tmp"
        with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        os.replace(tmp, STATUS)
    except OSError:
        pass


def _other_keeper():
    """Return the PID of another live watchdog, or 0.

    2026-11-10: a manually started second keeper overwrote watchdog.pid; when
    it died the file pointed at a dead PID and 启动代理 started a third one.
    Two live keepers keep separate cooldowns and can rebuild the exit chain
    concurrently, so refuse to start on top of one.
    """
    try:
        pid = int(io.open(PID, encoding="utf-8").read().strip())
    except (OSError, ValueError):
        return 0
    if pid and pid != os.getpid() and P.pid_image(pid).lower().startswith("python"):
        return pid
    return 0


def main():
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    other = _other_keeper()
    if other:
        log("another watchdog is already running pid=%d -> exit" % other)
        return 0
    try:
        with open(PID, "w") as f:
            f.write(str(os.getpid()))
    except OSError:
        pass
    log("watchdog start pid=%d" % os.getpid())
    st = {
        "now": {}, "gate": {}, "rebuilds": 0, "rebuild_fail": 0,
        "last_rebuild": 0.0, "last_rescan": 0.0, "last_error": "",
        "rebuild_cooldown": 600, "rescan_cooldown": 12 * 3600,
    }
    last = {}
    fails = {"ports": 0, "general": 0, "fast": 0, "steam": 0}
    try:
        while True:
            if os.path.isfile(STOP):
                log("STOP sentinel -> exit")
                break
            now = time.time()

            # ---- ports -------------------------------------------------
            if now - last.get("ports", 0) >= 60:
                last["ports"] = now
                ok = all(up(p) for p in (GEN, FAST, CLI))
                if not ok:
                    fails["ports"] += 1
                    missing = [p for p in (GEN, FAST, CLI) if not up(p)]
                    log("port check failed %d/2, missing %s"
                        % (fails["ports"], missing))
                    if fails["ports"] >= 2:
                        fails["ports"] = 0
                        st["rebuilds"] += 1
                        st["last_error"] = "ports " + str(missing)
                        rebuild("ports missing " + str(missing), st)
                else:
                    fails["ports"] = 0

            # ---- light gate --------------------------------------------
            if now - last.get("gate", 0) >= 300:
                last["gate"] = now

                def gate_fail(role, reason, dead):
                    """Count one strike; a totally dead group or dead core
                    rebuilds immediately instead of waiting another cycle."""
                    fails[role] += 1
                    log("%s gate FAIL %d/2 (%s)" % (role, fails[role], reason))
                    if fails[role] >= 2 or dead:
                        fails[role] = 0
                        st["rebuilds"] += 1
                        st["last_error"] = "%s gate %s" % (role, reason)
                        rebuild("%s gate failed" % role, st)

                code, size = curl_probe("https://chatgpt.com/", GEN)
                gok = code == "200" and size > 50000
                if not gok:
                    n = nudge("grp-general")
                    if n >= 0:
                        time.sleep(2)
                        c2, s2 = curl_probe("https://chatgpt.com/", GEN)
                        if c2 == "200" and s2 > 50000:
                            gok = True
                            code, size = c2, s2
                            log("ChatGPT gate recovered right after nudge")
                    if not gok and n == 0:
                        code, size = "%s (group dead)" % code, size
                st["gate"]["general"] = {"code": code, "size": size, "ok": gok}
                if gok:
                    if fails["general"]:
                        log("ChatGPT gate back to OK")
                    fails["general"] = 0
                else:
                    dead = ("group dead" in str(code)) or n < 0
                    gate_fail("general", "%s/%s" % (code, size), dead)

                fcode, _ = curl_probe("http://www.gstatic.com/generate_204", FAST)
                fok = fcode in ("204", "200")
                if not fok:
                    n = nudge("grp-fast")
                    if n >= 0:
                        time.sleep(2)
                        fcode, _ = curl_probe("http://www.gstatic.com/generate_204",
                                              FAST)
                        fok = fcode in ("204", "200")
                        if fok:
                            log("fast gate recovered right after nudge")
                st["gate"]["fast"] = {"code": fcode, "ok": fok}
                if fok:
                    fails["fast"] = 0
                else:
                    gate_fail("fast", fcode, n == 0 or n < 0)

                ccode, _ = curl_probe("http://www.gstatic.com/generate_204", CLI)
                st["gate"]["cli"] = {"code": ccode, "ok": ccode in ("204", "200")}

            # ---- HK node (Reddit) --------------------------------------
            if now - last.get("hk", 0) >= 300:
                last["hk"] = now
                ensure_hk_node()

            # ---- US Steam exit (Steam store / Wallpaper Engine) --------
            if now - last.get("steam", 0) >= 300:
                last["steam"] = now
                if steam_up():
                    fails["steam"] = 0
                else:
                    fails["steam"] += 1
                    log("Steam US gate FAIL %d/2" % fails["steam"])
                    if fails["steam"] >= 2:
                        fails["steam"] = 0
                        ensure_steam_node()

            # ---- PAC + env ---------------------------------------------
            if now - last.get("pac", 0) >= 120:
                last["pac"] = now
                url = pacroute._wget("AutoConfigURL")
                if url != sysstate.pac_url() or not pacroute.server_alive():
                    log("PAC missing/stale (%s, want %s) -> re-apply"
                        % (url, sysstate.pac_url()))
                    pac_apply()
                try:
                    if not sysstate.env_ok(CLI):
                        log("env proxy vars missing/drifted -> re-apply")
                        sysstate.apply_env(CLI)
                except Exception as e:
                    log("env check error: %r" % (e,))

            # ---- which member is active now ----------------------------
            if now - last.get("switch", 0) >= 90:
                last["switch"] = now
                for role, grp in (("general", "grp-general"), ("fast", "grp-fast")):
                    name, delay = clash_now(grp)
                    if not name:
                        continue
                    prev = st["now"].get(role)
                    if prev != name:
                        if prev:
                            log("auto-switch %s: %s -> %s (delay %sms)"
                                % (role, prev, name, delay))
                        st["now"][role] = name

            # ---- heartbeat ---------------------------------------------
            if now - last.get("status", 0) >= 60:
                last["status"] = now
                write_status(st)

            time.sleep(20)
    except BaseException as e:
        try:
            log("watchdog crashed: %r" % (e,))
        except Exception:
            pass
        raise
    finally:
        write_status(st)
        for p in (PID,):
            try:
                os.remove(p)
            except OSError:
                pass
        try:
            os.remove(STOP)
        except OSError:
            pass
        log("watchdog exit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
