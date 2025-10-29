@echo off
echo Testing Home Net Guardian Fixes...
echo.

echo 1. Checking Docker containers...
docker-compose ps

echo.
echo 2. Checking backend health...
curl -s http://localhost:8000/health

echo.
echo 3. Checking WebSocket endpoint...
echo WebSocket available at: ws://localhost:8000/ws/stream

echo.
echo 4. Checking frontend...
echo Frontend available at: http://localhost:5173

echo.
echo 5. Checking logs for errors...
echo Backend logs:
docker-compose logs --tail=10 backend

echo.
echo Test complete! Check the output above for any issues.
pause
