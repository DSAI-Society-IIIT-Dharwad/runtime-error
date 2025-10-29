@echo off
echo ========================================
echo   Generating Network Activity
echo ========================================
echo.
echo This will generate network activity to capture real traffic.
echo Make sure to have the Home Net Guardian running!
echo.

echo Starting network activity...
echo.

REM Generate some DNS lookups and web traffic
echo Performing DNS lookups...
nslookup google.com
nslookup facebook.com
nslookup youtube.com
nslookup github.com

echo.
echo Generating web traffic...
curl -s https://www.google.com > nul
curl -s https://www.github.com > nul
curl -s https://httpbin.org/ip > nul

echo.
echo Pinging various hosts...
ping -n 3 8.8.8.8 > nul
ping -n 3 1.1.1.1 > nul

echo.
echo Network activity generated!
echo Check the Home Net Guardian dashboard for new devices.
echo.
pause
