@echo off
setlocal
set "OUT=%USERPROFILE%\Desktop\ipad-manager-diagnostics.tar.gz"
wsl.exe --distribution Ubuntu --user root -- /usr/bin/ipad-manager-diagnostics "/mnt/c/Users/%USERNAME%/Desktop/ipad-manager-diagnostics.tar.gz"
if not errorlevel 1 echo Diagnostics exported to %OUT%
exit /b %errorlevel%
