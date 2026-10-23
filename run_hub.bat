@echo off
title WakeX Hub - PC Remote Power & Workspace Orchestrator
cd /d "%~dp0"
echo ============================================================
echo   WAKEX HUB - REMOTE POWER & WORKSPACE ORCHESTRATOR
echo ============================================================
echo.
echo Starting FastAPI Web Server and WebSocket Engine...
echo Access locally on PC:     http://localhost:8000
echo Access on Mobile via LAN: http://[YOUR-PC-IP]:8000
echo.
python server.py
if errorlevel 1 (
    if exist "%LOCALAPPDATA%\Python\bin\python.exe" (
        "%LOCALAPPDATA%\Python\bin\python.exe" server.py
    ) else (
        py -3 server.py
    )
)
pause
