@echo off
rem PATH shim for cmd/PowerShell: route `ssh` through the OTP wrapper.
"%~dp0..\sshotp.cmd" %*
exit /b %errorlevel%
