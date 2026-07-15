@echo off
rem otpctl -- manage the SSH multiplex master(s) on Windows (cmd/PowerShell).
rem   otpctl up     [host]   open/refresh master, answering OTP once (default x)
rem   otpctl status [host]   check whether a master is alive
rem   otpctl down   [host]   close the master
setlocal EnableExtensions
set "DIR=%~dp0"
set "ACTION=%~1"
set "HOSTS=%~2"
if "%HOSTS%"=="" set "HOSTS=x"
if /i "%ACTION%"=="up"     ( "%DIR%sshotp.cmd" -MNf %HOSTS% && echo otp: master up ^(%HOSTS%^) & exit /b %errorlevel% )
if /i "%ACTION%"=="status" ( "%DIR%sshotp.cmd" -O check %HOSTS% & exit /b %errorlevel% )
if /i "%ACTION%"=="down"   ( "%DIR%sshotp.cmd" -O exit %HOSTS% & exit /b %errorlevel% )
echo usage: otpctl up^|status^|down [host]   (default host: x)
exit /b 2
