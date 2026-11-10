@echo off
setlocal
title Portable Proxy - stop
cd /d "%~dp0"
set "PY=%~dp0..\runtime\python\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" -u "_proxy\stop_proxy.py"
echo.
pause
