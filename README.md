# WakeX v3.0.0
### Secure, Local-First Multi-Device PC Remote Power & Orchestration Platform

WakeX is a software-only, local-first remote power management and workspace orchestration suite engineered for Windows PCs and secondary Linux workstations, with companion native Android mobile app support.

---

## 🔒 Honest Security & Isolation Architecture

* **Zero Cloud / Zero Phone-Home:** Operates strictly on private local intranet (LAN/Wi-Fi) or encrypted peer-to-peer WireGuard/Tailscale meshes. No accounts, no third-party cloud servers, and no telemetry tracking.
* **Cryptographic Client Pairing:** Clients (phones and browsers) pair using an ephemeral X25519 Diffie-Hellman handshake authenticated with a single-use 6-digit PIN. Secrets are derived locally via HKDF-SHA256 and never cross the network.
* **Android Keystore Hardware Token Storage:** On Android companions, pairing secrets are encrypted via AES-256 GCM using a master key generated inside the hardware-backed Android KeyStore (`WakeXSecretMasterKey`), preventing secret extraction by malicious apps or backups.
* **HMAC-SHA256 Request Authentication:** Every remote power command and sensitive API request is signed with HMAC-SHA256 over `METHOD:PATH:TIMESTAMP:NONCE:BODY_SHA256`.
* **Replay & Skew Defense:** Requests with timestamp drift greater than 60 seconds or reused nonces are blocked with `HTTP 401/403`. Requests predating Hub startup are unconditionally rejected.
* **Multi-Device Target Isolation:** Power operations (Shutdown, Restart, Sleep, Hibernate, Lock) are strictly tied to authenticated `target_device_id`s. Dispatching commands targeting a secondary PC (Device B) forwards exclusively to Device B's remote agent; the Host PC (Device A) **NEVER** touches or powers off its own OS.
* **Safe Display Wake (No Cleartext Keystrokes):** Remote screen unlock awakens DPMS monitors and dismisses the lock screen curtain/wallpaper to reveal the physical login prompt. Cleartext password transmission and blind keystroke simulation (`SendKeys`) have been completely purged for user safety.
* **Anti-Brute-Force Rate Limiting:** 5 consecutive failed authentication attempts automatically locks out the requesting IP for 5 minutes (`HTTP 429 Too Many Requests`).
* **Audit Logging:** Every command execution, client connection, and power operation is recorded with timestamps in `wakex_audit.log` without secrets or PINs.

---

## 🚀 Key Features

1. **Native Double-Click Hub (`WakeX.exe`):**
   - Packaged with PyInstaller into a standalone executable running silently in the Windows system tray (`pystray`).
   - Win32 Named Mutex single-instance guard prevents duplicate processes.
   - Right-click tray menu option: **"🔑 Pair Mobile (Show One-Time PIN)"** displays a topmost Windows notification with the 6-digit PIN.
   - **"🚀 Start on Windows Boot"** tray toggle manages registry autostart cleanly.
   - Local rotating logs (2MB max, 2 backups).

2. **Hardware Wake-on-LAN & Wake-on-Wi-Fi (WoWLAN):**
   - Transmits standard 102-byte Magic Packets (`0xFF * 6 + MAC * 16`).
   - Multi-adapter support: broadcasts across Ethernet and Wi-Fi MACs over ports 9 and 7 to both global broadcast (`255.255.255.255`) and subnet broadcast (`192.168.x.255`).
   - Automated self-elevating setup script ([enable_wowlan.bat](enable_wowlan.bat)) to configure AC/DC wake timers, Wi-Fi driver power management, and Windows Firewall port rules, with a clean interactive Undo option.
   - **Test WoL Button:** Instant self-test button in the dashboard broadcasts verification packets and reports target MAC and subnet routing status.

3. **System Readiness Diagnostics Checker:**
   - Deep inspection of physical network adapters, AC power status, sleep states (S0ix/S3), Fast Startup registry keys, and firewall rules.
   - Actionable plain-language verdicts explaining which adapter will wake the PC from cold shutdown (Ethernet) vs. modern standby sleep (Wi-Fi).

4. **Instant LAN Discovery Beacon & Auto IP Re-Binding:**
   - Hub runs a lightweight UDP discovery responder on port 8002.
   - The Android mobile app auto-discovers the PC in ~50ms upon launch.
   - **Automatic IP Re-Binding:** If your router reboots and reassigns your PC a different IP address, the app automatically probes port 8002, scans the local `/24` subnet, updates the stored target, and reloads without user intervention.

5. **Power Deck & Workspace Orchestrator:**
   - ⚡ **Turn On**: Sends hardware Magic Packet to target MAC address.
   - 🔓 **Unlock**: Awakens monitor and dismisses lock screen curtain to reveal PIN/password box.
   - 🔒 **Lock**: Instantly locks active user desktop session (`user32.dll LockWorkStation` / `loginctl lock-session`).
   - 🌙 **Sleep**: Low-power Modern Standby / S3 sleep.
   - 🔄 **Restart**: Graceful operating system reboot.
   - 💤 **Hibernate (0-Watt)**: Cold hibernation with RAM dump to disk for zero power draw.
   - 🛑 **Shut Down**: Clean, graceful system shutdown.
   - 💼 **Workspace Launcher**: Scans Start Menu applications (`Get-StartApps`) and launches scheduled batches of software and browser tabs.

6. **🎨 Dark / Light Theme & 3-Step Onboarding:**
   - Cyberpunk Neon Red / OLED Stealth Black theme and high-contrast Light Theme with 1-tap toggle.
   - WCAG AA compliant with minimum 48×48px touch targets.
   - Interactive 3-Step Guided Tour for first-time network setup, cryptographic pairing, and wake nuances.
   - In-app "About & Help" dialog displaying version v3.0.0, build date, MIT license, and physical hardware limits.

7. **📱 Android Companion (`WakeX.apk`), App Widget & QS Tile:**
   - Native Java client compiled for Target SDK 35 (Android 15) and Min SDK 26.
   - **Home-Screen App Widget:** 1-tap "Wake PC" directly from your Android phone home screen without launching the full app.
   - **Quick Settings Tile:** Accessible from the pull-down notification shade for instant wake.
   - Hardware-backed Android KeyStore encryption for pairing credentials.
   - Adaptive background lifecycle management saving mobile battery.

---

## 📂 Quick Start in 5 Steps

### 1. Launch the Hub on Windows PC
1. Run `WakeX.exe` (or `python hub_launcher.py`).
2. The WakeX icon will appear in your Windows system tray.
3. If this is your first time connecting on a new Wi-Fi network, right-click and run `enable_wowlan.bat` as Administrator to configure Windows Firewall (ports 8000/8002) and Wi-Fi WoWLAN properties.

### 2. Connect Your Android Phone
1. Connect your phone to the **same Wi-Fi network** as your PC.
2. Install `WakeX.apk` on your phone.
   *(Note: If updating from an older test build signed with the legacy key, uninstall the previous build first).*
3. Open the app: it will auto-detect your PC via the UDP beacon and load the command center.

### 3. Pair Your Phone Cryptographically
1. If prompted for a pairing code:
   - Right-click the WakeX tray icon and select **"🔑 Pair Mobile (Show One-Time PIN)"** (or click **"🔑 Phone Pairing Code"** in the web dashboard).
   - Enter the 6-digit one-time code on your phone to finalize ephemeral X25519 PAKE hardware pairing.

### 4. Setup a Linux Secondary Target (Optional)
1. On your remote Linux machine, run:
   ```bash
   sudo ./agent/install_linux.sh
   ```
2. Note the generated Device ID and Token.
3. In WakeX Hub, tap **"➕ Pair Secondary PC"**, enter the Linux machine's IP, Port (8001), MAC, and Token.

### 5. Send Power Commands
- Tap **"⚡ Turn On"** to wake sleeping or powered-down workstations.
- Tap **"🌙 Sleep"**, **"❄️ Hibernate"**, **"🔄 Restart"**, **"🛑 Shutdown"**, or **"🔒 Lock"** with target isolation.

---

## 🛡️ Windows SmartScreen & Antivirus Notice

Because `WakeX.exe` is a newly built, independent open-source executable that is not code-signed with an expensive commercial EV certificate, Windows Defender SmartScreen or antivirus scanners may flag it with an "Unknown Publisher" or false-positive warning.

To verify binary authenticity:
1. Compare the SHA-256 checksum of your downloaded binary against the official hashes published in `SHA256SUMS.txt` and the GitHub Release notes:
   ```powershell
   Get-FileHash WakeX.exe -Algorithm SHA256
   ```
2. In the Windows SmartScreen prompt, click **"More info"** -> **"Run anyway"**.
3. All source code is completely open, auditable, and buildable from source with zero proprietary blobs.

---

## 📦 Building from Source

### Prerequisites
- Python 3.10+ (tested through 3.14)
- Android SDK Build-Tools (33.0.1 or 35.0.0), platform `android-33` or higher, JDK 17/21
- Git

### Build Windows Hub Executable
```powershell
pip install -r requirements.txt
pyinstaller WakeX.spec
# Executable produced at dist\WakeX.exe
```

### Build Android Companion APK
```powershell
powershell -ExecutionPolicy Bypass -File .\build_apk.ps1
# APK produced at WakeX.apk (signed with release key)
```

---

## ⚠️ Honest Hardware Limits & Physical Realities

1. **Cold Power-Off (0W S5) over Wi-Fi is physically impossible without specialized hardware:**
   - When a PC is fully shut down (`S5` state, 0W draw), standard Wi-Fi controller chips (Intel, MediaTek, Realtek) lose auxiliary power and cannot maintain association with the Wi-Fi router.
   - **Cold wake requires a wired Ethernet cable** connected to a motherboard with `ErP/EuP` disabled and `PCIe Power On` enabled in BIOS.
   - **Wi-Fi wake (WoWLAN)** functions when the PC is in **Sleep / Modern Standby (S0ix)** while connected to wall AC power.
2. **AC Power Required for Laptop WoWLAN:**
   - Laptop firmware intentionally powers down wireless cards when running on battery power to prevent rapid battery drainage.
3. **Screen Unlock does NOT bypass Windows Hello / Password Authentication:**
   - By security design, WakeX does not store, log, or replay your Windows user password or PIN. "Unlock Screen" awakens the display hardware via Win32 DPMS signals and raises the lock curtain, leaving the PC ready for facial recognition (Windows Hello IR camera), fingerprint sensor, or manual PIN entry.
4. **Linux Remote Agent Privileges:**
   - For secondary Linux systems, executing `shutdown` or `suspend` requires root permissions or a systemd service running as root (`agent/wakex-agent.service`).
5. **Router Client Isolation:**
   - If your home router has "AP Isolation" or "Guest Network Isolation" enabled, it drops UDP broadcasts and direct peer-to-peer packets between your phone and PC.

---

## 🔧 Troubleshooting Guide

| Issue | Cause | Solution |
|---|---|---|
| **App stuck on black screen or times out** | Phone is on Cellular 5G/4G or PC firewall is blocking port 8000. | • Check phone Wi-Fi: connect to home Wi-Fi (e.g. `Home_WiFi`).<br>• Run `enable_wowlan.bat` on PC as Administrator.<br>• Tap `⚙ IP` in app and verify IP matches current PC address. |
| **"Turn On" does not wake PC from cold shutdown** | Motherboard cuts standby power in S5 or Wi-Fi card powers down. | • Connect laptop to AC power adapter (laptops disable Wi-Fi WoWLAN on battery).<br>• Ensure BIOS has `PCIe PME Event Wake` enabled and `ErP/Deep Sleep` disabled.<br>• For 100% reliable wake from cold shutdown (S5), use an Ethernet cable. Wi-Fi WoWLAN operates best from Sleep/Modern Standby. |
| **"Authentication Required: Missing cryptographic client headers"** | Device is connecting from remote LAN without pairing credentials. | • Right-click tray icon -> **"🔑 Pair Mobile (Show One-Time PIN)"**.<br>• Enter the 6-digit code in the phone app to pair the device. |
| **PC IP address changed after router reboot** | Router assigned a new DHCP address to the PC. | • The app automatically scans the `/24` subnet and re-binds. Alternatively, tap **"🔍 Auto-Detect PC (UDP Beacon)"**. |

---

## 🛡️ Documentation & Compliance

* [docs/HARDWARE_CHECKLIST.md](docs/HARDWARE_CHECKLIST.md): Step-by-step verification checklist for all 6 actions across Windows and Linux.
* [LICENSE](LICENSE): MIT Open Source License.
* [PRIVACY.md](PRIVACY.md): Zero telemetry, zero cloud storage policy.
* [SECURITY.md](SECURITY.md): Threat model, rate limiting, and target isolation architecture.
* [LICENSES_AND_CREDITS.md](LICENSES_AND_CREDITS.md): Attribution and open source software credits.
* [CHANGELOG.md](CHANGELOG.md): Detailed version history and release notes.
