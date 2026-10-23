# WakeX Hub (Production Release 2.2.0)
### Secure, Local-First Multi-Device PC Remote Power & Orchestration Platform

WakeX is a software-only, local-first remote power management and workspace orchestration suite engineered for Windows PCs (e.g., ASUS TUF Gaming F15) and secondary Linux workstations (Ubuntu/Debian), with companion native Android mobile app support.

---

## 🔒 Honest Security & Isolation Architecture

* **Zero Cloud / Zero Phone-Home:** Operates strictly on private local intranet (LAN/Wi-Fi) or encrypted peer-to-peer WireGuard/Tailscale meshes. No accounts, no third-party cloud servers, and no telemetry tracking.
* **Cryptographic Client Pairing:** Clients (phones and browsers) pair using a 6-digit one-time code generated from the Hub. Upon pairing, a 256-bit cryptographically secure shared secret is provisioned and stored in local device storage.
* **HMAC-SHA256 Request Authentication:** Every remote power command and sensitive API request is signed with HMAC-SHA256 over `METHOD:PATH:TIMESTAMP:NONCE:BODY_SHA256`.
* **Replay & Skew Defense:** Requests with timestamp drift greater than 60 seconds or reused nonces are blocked with `HTTP 403 Forbidden`.
* **Multi-Device Target Isolation:** Power operations (Shutdown, Restart, Sleep, Hibernate, Lock) are strictly tied to authenticated `target_device_id`s. Dispatching commands targeting a secondary PC (Device B) forwards exclusively to Device B's remote agent; the Host PC (Device A) **NEVER** touches or powers off its own OS.
* **Safe Display Wake (No Cleartext Keystrokes):** Remote screen unlock awakens DPMS monitors and dismisses the lock screen curtain/wallpaper to reveal the physical login prompt. Cleartext password transmission and blind keystroke simulation (`SendKeys`) have been completely purged for user safety.
* **Anti-Brute-Force Rate Limiting:** 5 consecutive failed authentication attempts automatically locks out the requesting IP for 5 minutes (`HTTP 429 Too Many Requests`).
* **Audit Logging:** Every command execution, client connection, and power operation is recorded with timestamps in `wakex_audit.log`.

---

## 🚀 Key Features

1. **Native Double-Click Hub (`WakeX.exe`):**
   - **Zero manual terminal or development server commands!**
   - Packaged with PyInstaller into a standalone executable running silently in the Windows system tray (`pystray`).
   - Automatically initializes the local REST/WebSocket server, LAN discovery beacon, and background scheduler.

2. **Hardware Wake-on-LAN & Wake-on-Wi-Fi (WoWLAN):**
   - Transmits standard 102-byte Magic Packets (`0xFF * 6 + MAC * 16`).
   - Multi-adapter support: broadcasts across Ethernet and Wi-Fi MACs over ports 9 and 7 to both global broadcast (`255.255.255.255`) and subnet broadcast (`192.168.x.255`).
   - Automated self-elevating setup script ([enable_wowlan.bat](enable_wowlan.bat)) to configure AC/DC wake timers, Wi-Fi driver power management, and Windows Firewall port rules.

3. **Instant LAN Discovery Beacon:**
   - Hub runs a lightweight UDP discovery responder on port 8002.
   - The Android mobile app auto-discovers the PC in ~50ms upon tapping "Auto-Detect PC", eliminating the need to type changing IP addresses.

4. **Power Deck & Workspace Orchestrator:**
   - ⚡ **Turn On**: Sends hardware Magic Packet to target MAC address.
   - 🔓 **Unlock**: Awakens monitor and dismisses lock screen curtain to reveal PIN/password box.
   - 🔒 **Lock**: Instantly locks active user desktop session (`user32.dll LockWorkStation` / `loginctl lock-session`).
   - 🌙 **Sleep**: Low-power Modern Standby / S3 sleep.
   - 🔄 **Restart**: Graceful operating system reboot.
   - 💤 **Hibernate (0-Watt)**: Cold hibernation with RAM dump to disk for zero power draw.
   - 🛑 **Shut Down**: Clean, graceful system shutdown.
   - 💼 **Workspace Launcher**: Scans Start Menu applications (`Get-StartApps`) and launches scheduled batches of software and browser tabs.

5. **🐧 Native Linux Support (WakeX Agent):**
   - Secondary Linux computers (Ubuntu/Debian) run the lightweight daemon: `agent/wakex_agent.py`.
   - Installer script: `agent/install_linux.sh` registers a persistent `systemd` service on port 8001.

6. **📱 Native Android Mobile App (`WakeX.apk`):**
   - Native Java client compiled for Target SDK 35 (Android 15) and Min SDK 26.
   - Native UDP WoL broadcaster sends Magic Packets from phone hardware even before the PC web server is up.
   - 6-second watchdog timer prevents blank/frozen screens if the host PC is unreachable.
   - Network state detector alerts user if the phone is on Cellular 5G/4G instead of home Wi-Fi.

---

## 📂 Quick Start & Setup Guide

### 1. Launch the Hub on Host PC
1. Double-click `WakeX.exe` in this folder.
2. The WakeX icon will appear in your Windows system tray.
3. If this is your first time connecting on a new Wi-Fi network, right-click and run `enable_wowlan.bat` as Administrator to open Windows Firewall port 8000/8002 and set your network profile to `Private`.

### 2. Connect Your Android Phone
1. Connect your phone to the **same Wi-Fi network** as your PC.
2. Install [WakeX.apk](WakeX.apk) on your phone.
3. Open the app: it will auto-detect your PC via the UDP beacon and pair seamlessly.
4. If prompted for a pairing code:
   - On the PC dashboard, click **"🔑 Phone Pairing Code"**.
   - Enter the 6-digit one-time code on your phone to finalize cryptographic pairing.

---

## 🔧 Troubleshooting Guide

| Issue | Cause | Solution |
|---|---|---|
| **App stuck on black screen or times out** | Phone is on Cellular 5G/4G or PC firewall is blocking port 8000. | • Check phone Wi-Fi: connect to home Wi-Fi (e.g. `Home_WiFi`).<br>• Run `enable_wowlan.bat` on PC as Administrator.<br>• Tap `⚙ IP` in app and verify IP matches current PC address (`192.168.1.100:8000`). |
| **"Turn On" does not wake PC from cold shutdown** | Motherboard cuts standby power in S5 or Wi-Fi card powers down. | • Connect laptop to AC power adapter (laptops disable Wi-Fi WoWLAN on battery).<br>• Ensure BIOS has `PCIe PME Event Wake` enabled and `ErP/Deep Sleep` disabled.<br>• For 100% reliable wake from cold shutdown (S5), use an Ethernet cable. Wi-Fi WoWLAN operates best from Sleep/Modern Standby. |
| **"Authentication Required: Missing cryptographic client headers"** | Device is connecting from remote LAN without pairing credentials. | • Click **"🔑 Phone Pairing Code"** on the PC dashboard.<br>• Enter the 6-digit code in the phone app to pair the device. |
| **PC IP address changed after router reboot** | Router assigned a new DHCP address to the PC. | • In the phone app, tap **"🔍 Auto-Detect PC (UDP Beacon)"**. The app will discover the new IP automatically in under a second. |

---

## 🛡️ Documentation & Compliance

* [PRIVACY.md](PRIVACY.md): Zero telemetry, zero cloud storage policy.
* [SECURITY.md](SECURITY.md): Threat model, rate limiting, and target isolation architecture.
* [LICENSES_AND_CREDITS.md](LICENSES_AND_CREDITS.md): Attribution and open source software credits.
* [CHANGELOG.md](CHANGELOG.md): Detailed version history and release notes.
* [tests/test_wakex.py](tests/test_wakex.py): Automated test suite covering auth, isolation, and capabilities.
