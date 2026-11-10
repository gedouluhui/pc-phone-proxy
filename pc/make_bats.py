# -*- coding: utf-8 -*-
"""Generate the two ASCII .bat launchers with CRLF line endings."""
import io
import os

HERE = os.path.dirname(os.path.abspath(__file__))

START = r"""@echo off
setlocal
title Portable Proxy - start
cd /d "%~dp0"
set "PY=%~dp0..\runtime\python\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" -u "_proxy\start_proxy.py"
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" echo [OK] Proxy is running. Reopen the browser if a page still fails.
if "%RC%"=="2" echo [NOTE] Proxy is running but the ChatGPT gate failed; see _proxy\logs\report.html
if not "%RC%"=="0" if not "%RC%"=="2" echo [FAIL] exit code %RC%, see _proxy\logs\
pause
"""

STOP = r"""@echo off
setlocal
title Portable Proxy - stop
cd /d "%~dp0"
set "PY=%~dp0..\runtime\python\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" -u "_proxy\stop_proxy.py"
echo.
pause
"""

for name, text in (("start-proxy.bat", START), ("stop-proxy.bat", STOP)):
    data = text.replace("\r\n", "\n").replace("\n", "\r\n").encode("ascii")
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(data)
    print(name, len(data), "bytes")
