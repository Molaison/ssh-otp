@echo off
rem sshotp.cmd -- Windows launcher for the OTP-aware ssh wrapper.
rem Use as VS Code "remote.SSH.path" and for PowerShell/cmd `ssh` alias.
setlocal EnableExtensions
set "DIR=%~dp0"
if not defined SSH_TOTP_PYTHON call "%DIR%find_python.cmd"
if errorlevel 1 exit /b %errorlevel%
"%SSH_TOTP_PYTHON%" "%DIR%ssh_totp.py" %*
exit /b %errorlevel%
