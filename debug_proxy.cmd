@echo off
setlocal
set "SCRIPT_DIR=%~dp0"

if defined SSH_TOTP_PYTHON (
  "%SSH_TOTP_PYTHON%" "%SCRIPT_DIR%debug_proxy_win.py" %*
  exit /b %ERRORLEVEL%
)

"C:\Users\ADMIN\scoop\apps\miniconda3\current\python.exe" "%SCRIPT_DIR%debug_proxy_win.py" %*
exit /b %ERRORLEVEL%
