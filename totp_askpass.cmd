@echo off
if defined SSH_TOTP_PYTHON (
  "%SSH_TOTP_PYTHON%" "%~dp0totp_askpass.py" %*
) else (
  "C:\Users\ADMIN\scoop\apps\miniconda3\current\python.exe" "%~dp0totp_askpass.py" %*
)
