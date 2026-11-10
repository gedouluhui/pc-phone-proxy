@echo off
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
