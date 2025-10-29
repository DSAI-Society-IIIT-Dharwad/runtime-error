@echo off
echo ========================================
echo   Wireshark Network Capture
echo ========================================
echo.
echo This will start Wireshark to capture real network traffic.
echo.
echo Instructions:
echo 1. Select your Wi-Fi interface
echo 2. Start capture
echo 3. Browse the internet, use other devices
echo 4. Stop after 2-3 minutes
echo 5. Save as .pcap file in the 'data' folder
echo.

REM Try to start Wireshark
start "" "C:\Program Files\Wireshark\Wireshark.exe" 2>nul
if errorlevel 1 (
    echo Wireshark not found in default location.
    echo Please install Wireshark or run it manually.
    echo.
    echo Download from: https://www.wireshark.org/download.html
)

pause
