# Changelog

All notable changes to the WakeX project are documented here.

## [3.0.0] - 2026-10-23
### Final Release & Packaging Pass
- **Full Client-Side X25519 PAKE Handshake:**
  - Vendored Public Domain `TweetNaCl.js` (`static/tweetnacl.min.js`) enabling native client-side Curve25519 scalar multiplication and HKDF key derivation on plain HTTP LAN dashboards and Android WebViews without `crypto.subtle`.
  - Updated `submitClientPairing()` in `static/app.js` to execute two-step `/api/auth/pair/exchange` and `/api/auth/pair/authenticate` seamlessly.
- **Hub Supervisor & Single-Instance Guard:**
  - Added Win32 Named Mutex (`WakeX_Hub_SingleInstance_Mutex`) in `hub_launcher.py` preventing duplicate background processes and duplicate system tray icons.
  - Implemented local rotating log handler (`RotatingFileHandler`, max 2MB, 2 backups) with zero plaintext PINs or secrets logged.
  - Added tray menu toggle for "Start on Windows Boot" (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).
  - High-contrast Neon Red (`#ff2a44`) on OLED Black (`#050508`) power symbol tray icon.
- **Security Reset & Device De-Authorization:**
  - Added authenticated `POST /api/auth/reset` endpoint in `server.py` that clears paired clients, pending sessions, and replay nonces.
  - Added interactive "⚠️ Reset Security" button in dashboard header and pairing dialog with confirmation safeguard.
- **Android Lifecycle & Battery Optimization:**
  - Implemented `onPause()`, `onResume()`, and `onDestroy()` lifecycle methods in `MainActivity.java` pausing WebView JavaScript timers and background rendering when hidden.
  - Implemented adaptive web lifecycle via `visibilitychange` in `app.js` throttling background WebSocket reconnection attempts from 3s to 20s.
  - Externalized Android companion strings into `res/values/strings.xml`.
- **End-to-End Simulated LAN Test Suite:**
  - Added `tests/test_simulated_lan.py` testing full phone PAKE pairing, remote agent registration, target-isolated power command execution, whitelist validation, and clean teardown.
- **Automated Security & Vulnerability Audits:**
  - Pinned all dependencies in `requirements.txt`.
  - Ran `pip-audit`: 0 known vulnerabilities found.
  - Ran Gitleaks deep scan across all git commits: 0 leaks found.
  - 55 automated pytest tests passing; 7 Android Java unit tests passing.
- **Packaging & Release Hygiene:**
  - Open source MIT License adopted.
  - Updated `enable_wowlan.bat` with interactive menu offering clean Undo option.

## [2.4.1] - 2026-10-23
### Security Hardening, Ephemeral X25519 PAKE Pairing, & Architecture Auditing
- **Ephemeral X25519 PAKE-Style Pairing Protocol:**
  - Replaced legacy static pairing with ephemeral X25519 Diffie-Hellman key exchange (`POST /api/auth/pair/exchange` and `POST /api/auth/pair/authenticate`).
  - Derived long-term 256-bit client secrets purely from ECDH shared secret using HKDF-SHA256 (the secret is never derived from or keyed with the PIN).
  - Mutual transcript authentication keyed with the single-use 6-digit PIN. Passive eavesdroppers learn nothing; active attackers receive at most 1 online guess per attempt.
  - Per-PIN 5-attempt brute-force revocation enforced globally across all source IPs. Single-use PIN consumption and 5-minute expiry.
  - *Migration Note: Existing paired devices must re-pair.*
- **Linux Agent Hardening (Root Daemon Port 8001):**
  - Purged legacy unsigned token bypass. Strict HMAC-SHA256 signature verification enforced across all endpoints.
  - Added `--host` parameter defaulting to the host's LAN IP instead of exposing all network interfaces unconditionally.
  - Replaced all `subprocess.run(..., shell=True)` and `subprocess.Popen(..., shell=True)` calls across the entire codebase with discrete argument lists (`["systemctl", "poweroff"]`, etc.), eliminating shell injection vectors.
- **Plain HTTP Web Crypto Resilience:**
  - Android WebView prioritizes native `window.AndroidWakeX.signRequest()` Keystore bridge.
  - Browser dashboards on plain HTTP (`http://<LAN-IP>:8000`) fall back to vendored, MIT-licensed `js-sha256` verified against standard RFC 4231 test vectors.
- **Process Start Time Replay Immunity:**
  - Hub enforces rejection of any request timestamped prior to process start (`req_ts < PROCESS_START_TIME - 5.0`), preventing replay attacks across restarts without file I/O overhead.
- **WoL Port Cleanup:**
  - Removed UDP port 0 from Magic Packet broadcasts across backend and frontend (strictly ports 9 and 7).
- **Test Suite Expansion:**
  - Added `tests/test_coverage_and_network.py` verifying UDP discovery responses, Hub IP re-binding on DHCP change, strict WoL ports, and mock executions for all 6 power actions across Windows and Linux.
  - Expanded `android_build/test/WakeXUnitTest.java` with UDP discovery payload parsing, IP re-bind detection, and connection watchdog state machine tests (now 52 pytest tests + 7 Android Java tests passing).
- **Keystore Hygiene & Repository Secrets Sanitization:**
  - Legacy `android_build/wakex.keystore` and password marked compromised and untracked.
  - Updated `build_apk.ps1` to generate and manage release signing keystores outside the git repository (`~/.wakex/`).
  - Added `*.keystore` and `*.jks` to `.gitignore`. Untracked `config/devices.json` and added clean template `config/devices.example.json`.
  - Added manual hardware verification results table to `docs/HARDWARE_CHECKLIST.md`.

## [2.4.0] - 2026-10-23
### Full Verification, Resilience, and UX Polish
- **Frontend Fault Tolerance & Resilience:** Enhanced `apiFetch` in `static/app.js` with `AbortController` timeouts (12s default) and plain-language actionable error translators for connection timeouts and network dropouts.
- **Automated Frontend Resilience Suite:** Added `tests/test_frontend_resilience.py` testing unauthenticated request handling, 401 pairing modal triggers, 429 rate limiting, malformed payload validation, and UI static asset integrity.
- **Android Companion Unit Testing:** Added `android_build/test/WakeXUnitTest.java` testing Magic Packet generation, MAC sanitization, HMAC-SHA256 signature interoperability, and tamper detection directly against RFC 4231 test vectors.
- **Android Lint & Code Quality:** Purged locale-dependent string operations in `MainActivity.java`, `WakeXAppWidgetProvider.java`, and `WakeXTileService.java` using `Locale.ROOT`; externalized all UI widget strings into `res/values/strings.xml` achieving 0 errors in Android SDK Lint.
- **Home-Screen App Widget:** Added native `WakeXAppWidgetProvider.java` and `res/layout/widget_wakex.xml` providing 1-tap "Wake PC" from the Android home screen without loading the full WebView.
- **3-Step Onboarding Wizard:** Added interactive first-time setup guide explaining Wi-Fi network detection, cryptographic pairing PIN, and hardware wake differences (Ethernet cold-wake vs. Wi-Fi AC-standby wake).
- **Stealth Theme & Accessibility:** Added persistent Neon Red / Stealth Black (`#050508`) and high-contrast Light Theme with zero-flicker `<head>` restoration and WCAG AA 48x48px minimum touch targets.
- **Manual Hardware Verification Checklist:** Authored `docs/HARDWARE_CHECKLIST.md` detailing exact BIOS/UEFI, OS power management, driver configuration, and verification steps for all 6 actions across Windows and Linux.
