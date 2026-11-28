#!/usr/bin/env python3
"""Run PC tests and turn failures into visible GitHub Actions annotations."""
import os
import re
import subprocess
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOG = ROOT / "_ci_test_output.log"

# Windows runners may give Python a legacy console code page while the child is
# explicitly UTF-8. Never let printing a Chinese test name abort the wrapper.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


def annotations(output):
    names = []
    for line in output.splitlines():
        match = re.match(r"^(?:FAIL|ERROR):\s+(.+)$", line.strip())
        if match and match.group(1) not in names:
            names.append(match.group(1))
    if not names and output.strip():
        names.append("see _ci_test_output.log for the complete failure")
    result = []
    for name in names[:30]:
        safe = name.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        result.append("::error::PC regression: " + safe)
    return result


def main():
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    process = subprocess.Popen([sys.executable, "-B", "-m", "unittest", "discover",
                                "-s", "tests_ci", "-v"], cwd=str(ROOT), env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, encoding="utf-8", errors="replace")
    lines = []
    with open(LOG, "w", encoding="utf-8", newline="\n") as log:
        for line in process.stdout:
            lines.append(line)
            log.write(line)
            log.flush()
            print(line, end="", flush=True)
    process.wait()
    output = "".join(lines)
    if process.returncode:
        for line in annotations(output):
            print(line)
    print("PC regression rc=%d log=%s" % (process.returncode, LOG))
    return process.returncode


if __name__ == "__main__":
    try:
        _exit = main()
    except BaseException:
        traceback.print_exc()
        try:
            with open(LOG, "a", encoding="utf-8", newline="\n") as stream:
                traceback.print_exc(file=stream)
        except OSError:
            pass
        print("::error::PC regression wrapper failed; see traceback above")
        _exit = 1
    raise SystemExit(_exit)
