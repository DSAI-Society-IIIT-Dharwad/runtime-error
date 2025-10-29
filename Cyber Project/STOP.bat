@echo off
echo ========================================
echo   Home Net Guardian - Stopping...
echo ========================================
echo.

REM Navigate to the project directory
cd /d "%~dp0"

REM Stop all containers
echo Stopping all containers...
docker-compose down

echo.
echo ========================================
echo   Application stopped successfully!
echo ========================================
echo.

pause

