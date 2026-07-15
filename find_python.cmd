@echo off
rem Resolve Python for all Windows ssh-otp launchers without machine-specific paths.
setlocal EnableExtensions
set "PYEXE=%SSH_TOTP_PYTHON%"
if defined PYEXE goto found
for %%P in (py.exe python3.exe python.exe) do (
  for /f "delims=" %%I in ('where %%P 2^>nul') do (
    set "PYEXE=%%I"
    goto found
  )
)
echo ssh-otp: Python 3 was not found. Install Python or set SSH_TOTP_PYTHON. 1>&2
endlocal
exit /b 127

:found
endlocal & set "SSH_TOTP_PYTHON=%PYEXE%"
exit /b 0
