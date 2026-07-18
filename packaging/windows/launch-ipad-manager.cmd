@echo off
setlocal
wsl.exe --distribution Ubuntu -- /usr/bin/ipad-manager-launch
if errorlevel 1 (
  echo IPAd Manager failed to start. Run the IPAd Manager health check from the Start menu.
  pause
)
exit /b %errorlevel%
