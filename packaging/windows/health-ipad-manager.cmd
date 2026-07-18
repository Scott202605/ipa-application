@echo off
wsl.exe --distribution Ubuntu --user root -- /usr/bin/ipad-manager-health
exit /b %errorlevel%
