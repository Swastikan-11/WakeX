@echo off
title AetherCommand - Register Auto-Start with Windows
cd /d "%~dp0"

echo Registering AetherCommand Hub to start automatically with Windows...
set "STARTUP_VBS=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\AetherCommand_Startup.vbs"
set "HUB_BAT=%~dp0run_hub.bat"

:: Create a VBScript in Windows Startup folder that runs run_hub.bat invisibly
(
  echo Set WshShell = CreateObject^("WScript.Shell"^)
  echo WshShell.Run chr^(34^) ^& "%HUB_BAT%" ^& chr^(34^), 0
  echo Set WshShell = Nothing
) > "%STARTUP_VBS%"

echo.
echo [SUCCESS] AetherCommand Hub will now automatically launch silently on boot!
echo Startup launcher created at:
echo %STARTUP_VBS%
echo.
pause
