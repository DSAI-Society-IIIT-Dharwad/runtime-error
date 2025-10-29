@echo off
echo ========================================
echo   Home Net Guardian - Starting...
echo ========================================
echo.
echo This will start the application and show live logs.
echo Press Ctrl+C to stop the application.
echo.
echo ========================================
echo.

REM Navigate to the project directory
cd /d "%~dp0"

REM Stop any existing containers
echo Stopping existing containers...
docker-compose down
echo.

REM Start the application with live output
echo Starting Home Net Guardian...
echo.
echo Frontend will be available at: http://localhost:5173
echo Backend API will be available at: http://localhost:8000
echo.
echo ========================================
echo   Live Logs (Press Ctrl+C to stop)
echo ========================================
echo.

REM Start containers and follow logs
docker-compose up

REM This will only run if user presses Ctrl+C
echo.
echo ========================================
echo   Shutting down...
echo ========================================
docker-compose down

pause

