# -*- coding: utf-8 -*-
import io
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import proxyctl as P  # noqa: E402

STOP = os.path.join(HERE, "STOP_WATCHDOG")
PIDF = os.path.join(HERE, "watchdog.pid")
LOG = os.path.join(HERE, "logs", "watchdog.out")

pid = None
try:
    pid = int(io.open(PIDF).read().strip())
except Exception:
    pass

if pid and P.pid_alive(pid):
    img = P.pid_image(pid).lower()
    print("old watchdog pid=%d image=%s" % (pid, img))
    if not img.startswith("python"):
        sys.exit("pid %d is not python; refusing to touch it" % pid)
    with io.open(STOP, "w", encoding="utf-8", newline="\n") as f:
        f.write("stop")
    for _ in range(25):
        if not P.pid_alive(pid):
            break
        time.sleep(2)
    if P.pid_alive(pid):
        print("still alive after sentinel; killing pid", pid)
        subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                       capture_output=True, creationflags=0x08000000)
        time.sleep(1)
    print("old watchdog stopped" if not P.pid_alive(pid) else "old watchdog STILL ALIVE")
try:
    os.remove(STOP)
except OSError:
    pass

cands = [os.path.join(os.path.dirname(HERE), "runtime", "python", "pythonw.exe"),
         os.path.join(os.path.dirname(sys.executable), "pythonw.exe")]
pyw = next((c for c in cands if os.path.isfile(c)), sys.executable)
os.makedirs(os.path.dirname(LOG), exist_ok=True)
with open(LOG, "ab") as logf:
    p = subprocess.Popen([pyw, os.path.join(HERE, "watchdog.py")], cwd=HERE,
                         stdout=logf, stderr=subprocess.STDOUT,
                         stdin=subprocess.DEVNULL,
                         creationflags=0x00000008 | 0x08000000)
with io.open(PIDF, "w", encoding="utf-8", newline="\n") as f:
    f.write(str(p.pid))
time.sleep(2.0)
print("new watchdog pid=%d alive=%s exe=%s" % (p.pid, P.pid_alive(p.pid), pyw))
