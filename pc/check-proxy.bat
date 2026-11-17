@echo off
setlocal
title Portable Proxy - health check
cd /d "%~dp0"
set "PY=%~dp0..\runtime\python\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" -u "_proxy\doctor.py"
echo.
pause
