@echo off
setlocal
title Portable Proxy - TUN global mode (needs admin)
cd /d "%~dp0"
set "PY=%~dp0..\runtime\python\python.exe"
if not exist "%PY%" set "PY=python"
echo TUN creates a virtual adapter and asks for UAC (Administrator).
echo Stop it with stop-proxy.bat -- it will ask for UAC again.
"%PY%" -u "_proxy\tun_mode.py" start
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" echo [OK] TUN global mode is running.
if not "%RC%"=="0" echo [FAIL] exit code %RC%, see _proxy\logs\tun.log
pause
