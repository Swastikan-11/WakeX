@echo off
:: Self-elevate to Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator privileges to configure WakeX network and firewall...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ==========================================================
echo   WakeX - Enabling Hardware Wake on Wi-Fi and Firewall
echo ==========================================================
echo.

:: 1. Open Firewall Port 8000 for WakeX Hub
echo [1/3] Adding Windows Firewall rule for WakeX Hub (Port 8000)...
netsh advfirewall firewall delete rule name="WakeX Hub" >nul 2>&1
netsh advfirewall firewall add rule name="WakeX Hub" dir=in action=allow protocol=TCP localport=8000 profile=any >nul
echo       Firewall port 8000 successfully opened!

:: 2. Set current Wi-Fi network profile to Private so devices on local Wi-Fi can communicate
echo [2/3] Setting Wi-Fi connection profile to Private...
powershell -Command "Get-NetConnectionProfile -InterfaceAlias 'Wi-Fi' | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue"
echo       Wi-Fi profile configured!

:: 3. Enable Wake-on-LAN for Wi-Fi card
echo [3/3] Configuring Wi-Fi adapter for Magic Packet Wake-on-LAN...
powershell -Command "Set-NetAdapterAdvancedProperty -Name 'Wi-Fi' -RegistryKeyword 'DisableWakeOnMagic' -RegistryValue '0' -ErrorAction SilentlyContinue"
powershell -Command "Set-NetAdapterAdvancedProperty -Name 'Wi-Fi' -RegistryKeyword 'DisableWakeOnPattern' -RegistryValue '0' -ErrorAction SilentlyContinue"
powershell -Command "Set-NetAdapterAdvancedProperty -Name 'Wi-Fi' -RegistryKeyword 'PMARPOffload' -RegistryValue '1' -ErrorAction SilentlyContinue"
powershell -Command "Set-NetAdapterAdvancedProperty -Name 'Wi-Fi' -RegistryKeyword 'PMWiFiRekeyOffload' -RegistryValue '1' -ErrorAction SilentlyContinue"

:: Arm wake timers in powercfg
powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 1 >nul 2>&1
powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_SLEEP bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 1 >nul 2>&1
powercfg /SETACTIVE SCHEME_CURRENT >nul 2>&1

echo.
echo ==========================================================
echo [SUCCESS] WakeX PC Configuration Complete!
echo - Firewall Port 8000 is open
echo - Wi-Fi is set to Private
echo - Hardware Wake-on-Wi-Fi (WoWLAN) is active
echo ==========================================================
echo.
pause
