@echo off
title AetherCommand Hub - PC Remote Power & Workspace Orchestrator
cd /d "%~dp0"
echo ============================================================
echo   AETHERCOMMAND HUB - ASUS TUF F15 WORKSTATION ORCHESTRATOR
echo ============================================================
echo.
echo Starting FastAPI Web Server and WebSocket Engine...
echo Access locally on PC:     http://localhost:8000
echo Access on Mobile via LAN: http://[YOUR-PC-IP]:8000
echo.
"%LOCALAPPDATA%\Python\bin\python.exe" server.py
pause
