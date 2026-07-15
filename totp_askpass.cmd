@echo off
setlocal EnableExtensions
set "DIR=%~dp0"
if not defined SSH_TOTP_PYTHON call "%DIR%find_python.cmd"
if errorlevel 1 exit /b %errorlevel%
"%SSH_TOTP_PYTHON%" "%DIR%totp_askpass.py" %*
exit /b %errorlevel%
