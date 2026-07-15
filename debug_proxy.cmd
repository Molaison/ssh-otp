@echo off
setlocal EnableExtensions
set "SCRIPT_DIR=%~dp0"
if not defined SSH_TOTP_PYTHON call "%SCRIPT_DIR%find_python.cmd"
if errorlevel 1 exit /b %errorlevel%
"%SSH_TOTP_PYTHON%" "%SCRIPT_DIR%debug_proxy_win.py" %*
exit /b %errorlevel%
