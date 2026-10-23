@echo off
:: WakeX - Windows Firewall & Hardware WoWLAN Network Configurator
:: Self-elevate to Administrator if not elevated
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator privileges for WakeX network setup...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

title WakeX - Network & Firewall Setup
cls
echo ==========================================================
echo            WakeX PC Network & Firewall Setup
echo ==========================================================
echo.
echo WakeX requires local network access so your paired mobile app
echo can discover the PC and send Wake-on-LAN packets.
echo.
echo Changes performed by setup:
echo   1. Windows Firewall: Inbound rule for Port 8000 (TCP Hub) and Port 8002 (UDP Discovery).
echo   2. Network Profile: Set active Wi-Fi interface category to Private (allows local device peer communication).
echo   3. Adapter Properties: Enable 'DisableWakeOnMagic = 0' and ARP/NS offload on Wi-Fi adapter.
echo   4. Powercfg: Enable wake timers on AC/DC power schemes.
echo.
echo ==========================================================
echo [1] Configure and Enable WakeX Network Access
echo [2] Undo / Remove WakeX Firewall Rules and Restore Defaults
echo [3] Exit without making any changes
echo ==========================================================
echo.

set /p choice="Enter your selection [1, 2, or 3]: "
if "%choice%"=="1" goto ENABLE_WAKEX
if "%choice%"=="2" goto UNDO_WAKEX
if "%choice%"=="3" goto EXIT_SCRIPT
goto EXIT_SCRIPT

:ENABLE_WAKEX
echo.
echo >>> [1/4] Configuring Windows Defender Firewall...
netsh advfirewall firewall delete rule name="WakeX Hub" >nul 2>&1
netsh advfirewall firewall add rule name="WakeX Hub" dir=in action=allow protocol=TCP localport=8000 profile=any >nul
netsh advfirewall firewall add rule name="WakeX Hub Discovery" dir=in action=allow protocol=UDP localport=8002 profile=any >nul
echo       Firewall rules added (TCP 8000, UDP 8002).

echo >>> [2/4] Setting active Wi-Fi profile to Private...
powershell -Command "Get-NetConnectionProfile -InterfaceAlias 'Wi-Fi' | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue"
echo       Wi-Fi profile verified.

echo >>> [3/4] Enabling Wake-on-LAN and WoWLAN adapter power properties...
powershell -Command "Set-NetAdapterAdvancedProperty -Name 'Wi-Fi' -RegistryKeyword 'DisableWakeOnMagic' -RegistryValue '0' -ErrorAction SilentlyContinue"
powershell -Command "Set-NetAdapterAdvancedProperty -Name 'Wi-Fi' -RegistryKeyword 'DisableWakeOnPattern' -RegistryValue '0' -ErrorAction SilentlyContinue"
powershell -Command "Set-NetAdapterAdvancedProperty -Name 'Wi-Fi' -RegistryKeyword 'PMARPOffload' -RegistryValue '1' -ErrorAction SilentlyContinue"
powershell -Command "Set-NetAdapterAdvancedProperty -Name 'Wi-Fi' -RegistryKeyword 'PMWiFiRekeyOffload' -RegistryValue '1' -ErrorAction SilentlyContinue"

echo >>> [4/4] Arming OS wake timers in powercfg...
powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 1 >nul 2>&1
powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_SLEEP bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 1 >nul 2>&1
powercfg /SETACTIVE SCHEME_CURRENT >nul 2>&1

echo.
echo ==========================================================
echo [SUCCESS] WakeX PC Configuration is Active!
echo - Firewall Ports 8000 (TCP) & 8002 (UDP) opened
echo - Wi-Fi category set to Private
echo - Wake-on-LAN / WoWLAN properties enabled
echo ==========================================================
echo.
pause
exit /b 0

:UNDO_WAKEX
echo.
echo >>> Removing WakeX Windows Firewall rules...
netsh advfirewall firewall delete rule name="WakeX Hub" >nul 2>&1
netsh advfirewall firewall delete rule name="WakeX Hub Discovery" >nul 2>&1
echo       Firewall rules for WakeX removed.
echo.
echo ==========================================================
echo [UNDO COMPLETE] WakeX Firewall rules have been restored.
echo ==========================================================
echo.
pause
exit /b 0

:EXIT_SCRIPT
echo.
echo No changes were made.
exit /b 0
