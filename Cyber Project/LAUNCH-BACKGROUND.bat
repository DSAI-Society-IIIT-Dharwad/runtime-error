@echo off
echo ========================================
echo   Home Net Guardian - Quick Start
echo ========================================
echo.

REM Navigate to the project directory
cd /d "%~dp0"

REM Stop any existing containers
echo Stopping existing containers...
docker-compose down >nul 2>&1
echo.

REM Start the application in background
echo Starting Home Net Guardian in background...
docker-compose up -d --build

REM Wait a moment for containers to start
timeout /t 5 /nobreak >nul

REM Show status
echo.
echo ========================================
echo   Status
echo ========================================
docker-compose ps
echo.
echo ========================================
echo   Application is running!
echo ========================================
echo.
echo   Frontend: http://localhost:5173
echo   Backend:  http://localhost:8000
echo   API Docs: http://localhost:8000/docs
echo.
echo To view logs: docker-compose logs -f
echo To stop:      docker-compose down
echo.
echo Opening frontend in your default browser...
echo.

REM Open the frontend in default browser
start http://localhost:5173

pause

