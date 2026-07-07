@echo off
rem sshotp.cmd -- Windows launcher for the OTP-aware ssh wrapper.
rem Use as VS Code "remote.SSH.path" and for PowerShell/cmd `ssh` alias.
setlocal EnableExtensions
set "DIR=%~dp0"
call :findpy PYEXE
"%PYEXE%" "%DIR%ssh_totp.py" %*
exit /b %errorlevel%

:findpy
if defined SSH_TOTP_PYTHON ( set "%~1=%SSH_TOTP_PYTHON%" & exit /b 0 )
for %%P in (py.exe python3.exe python.exe) do (
  for /f "delims=" %%I in ('where %%P 2^>nul') do ( set "%~1=%%I" & exit /b 0 )
)
set "%~1=C:\Users\ADMIN\scoop\apps\miniconda3\current\python.exe"
exit /b 0
