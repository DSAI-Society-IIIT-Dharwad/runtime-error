@echo off
echo ========================================
echo   Capturing Real Network Traffic
echo ========================================
echo.
echo This will capture network traffic for 60 seconds
echo to see real devices on your network.
echo.
echo Press Ctrl+C to stop early, or wait 60 seconds.
echo.
pause

REM Create capture directory
if not exist "real_captures" mkdir real_captures

REM Get current timestamp for filename
for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
set "YY=%dt:~2,2%" & set "YYYY=%dt:~0,4%" & set "MM=%dt:~4,2%" & set "DD=%dt:~6,2%"
set "HH=%dt:~8,2%" & set "Min=%dt:~10,2%" & set "Sec=%dt:~12,2%"
set "timestamp=%YYYY%%MM%%DD%_%HH%%Min%%Sec%"

echo Starting packet capture...
echo Filename: real_captures\traffic_%timestamp%.pcap
echo.

REM Try netsh first (built into Windows)
netsh trace start capture=yes tracefile=real_captures\traffic_%timestamp%.etl provider=Microsoft-Windows-TCPIP maxsize=100
timeout /t 60 /nobreak
netsh trace stop

echo.
echo Capture completed!
echo File saved as: real_captures\traffic_%timestamp%.etl
echo.
echo To convert to PCAP format, you can use:
echo - Microsoft Message Analyzer
echo - etl2pcapng tool
echo - Or upload the .etl file directly to the web interface
echo.
pause
