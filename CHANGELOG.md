# Changelog

All notable changes to the WakeX project are documented here.

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
  - Legacy `android_build/wakex.keystore` and password `[REDACTED]` marked compromised and untracked.
  - Updated `build_apk.ps1` to generate and manage release signing keystores outside the git repository (`~/.wakex/`).
  - Added `*.keystore` and `*.jks` to `.gitignore`. Untracked `config/devices.json` and added clean template `config/devices.example.json`.
  - Added manual hardware verification results table to `docs/HARDWARE_CHECKLIST.md`.

## [2.4.0] - 2026-10-23
### Full Verification, Resilience, and UX Polish
- **Frontend Fault Tolerance & Resilience:** Enhanced `apiFetch` in `static/app.js` with `AbortController` timeouts (12s default) and plain-language actionable error translators for connection timeouts and network dropouts.
- **Automated Frontend Resilience Suite:** Added `tests/test_frontend_resilience.py` testing unauthenticated request handling, 401 pairing modal triggers, 429 rate limiting, malformed payload validation, and UI static asset integrity (36 total passing tests across the repo).
- **Android Companion Unit Testing:** Added `android_build/test/WakeXUnitTest.java` testing Magic Packet generation, MAC sanitization, HMAC-SHA256 signature interoperability, and tamper detection directly against RFC 4231 test vectors.
- **Android Lint & Code Quality:** Purged locale-dependent string operations in `MainActivity.java`, `WakeXAppWidgetProvider.java`, and `WakeXTileService.java` using `Locale.ROOT`; externalized all UI widget strings into `res/values/strings.xml` achieving 0 errors in Android SDK Lint.
- **Home-Screen App Widget:** Added native `WakeXAppWidgetProvider.java` and `res/layout/widget_wakex.xml` providing 1-tap "Wake PC" from the Android home screen without loading the full WebView.
- **3-Step Onboarding Wizard:** Added interactive first-time setup guide explaining Wi-Fi network detection, cryptographic pairing PIN, and hardware wake differences (Ethernet cold-wake vs. Wi-Fi AC-standby wake).
- **Stealth Theme & Accessibility:** Added persistent Neon Red / Stealth Black (`#050508`) and high-contrast Light Theme with zero-flicker `<head>` restoration and WCAG AA 48×48px minimum touch targets.
- **Manual Hardware Verification Checklist:** Authored `docs/HARDWARE_CHECKLIST.md` detailing exact BIOS/UEFI, OS power management, driver configuration, and verification steps for all 6 actions across Windows and Linux.
- **Updated Binaries:** Rebuilt and smoke-tested single-file Windows tray binary (`WakeX.exe`, 40.7 MB) and Android package (`WakeX.apk`, 172.7 KB, Target SDK 35).

## [2.3.0] - 2026-10-23
### Multi-Platform Agent Hardening & Parity
- **Agent Cryptographic Auth:** Hardened `agent/wakex_agent.py` to support dual-mode authentication: timing-safe Device Token (`hmac.compare_digest`) and full HMAC-SHA256 signature verification over `METHOD:PATH:TIMESTAMP:NONCE:BODY_SHA256`.
- **Agent Anti-Replay & Anti-Tamper:** Added 60s timestamp tolerance window and in-memory nonce cache to the standalone agent.
- **Agent Rate Limiting:** 5 failed attempts locks out the client IP for 5 minutes (`HTTP 429`).
- **Hub-to-Agent Cryptographic Dispatch:** `engine/devices.py` automatically generates timestamp, nonce, and HMAC-SHA256 signatures when dispatching remote commands to paired agents.
- **Agent Action Whitelist:** Strict command validation blocks unknown actions or shell injection attempts before touching the OS.
- **Dynamic Platform Capability Filtering:** Remote agents and the local host inspect real capabilities (`sleep`, `hibernate`, `lock`, `unlock`) and report them via `/api/devices`. The Web UI power deck dynamically dims and labels unsupported actions.
- **systemd Security Hardening:** Added `ReadWritePaths=/opt/wakex-agent` to `agent/wakex-agent.service` alongside `ProtectSystem=full`.

### Storage Resilience & Crash Safety
- **Atomic JSON Storage (`engine/storage.py`):** Replaced non-atomic file writes across `devices.py`, `security.py`, `workspace.py`, and `scheduler.py` with atomic write patterns (`mkstemp`, `fsync`, and atomic `os.replace`).
- **Automated Backup Recovery:** Implemented `.bak` file maintenance; automatic recovery from backup if a config file is truncated or corrupted by sudden power cuts.

### Android Companion Features
- **Quick Settings Tile:** Created `WakeXTileService.java` (`BIND_QUICK_SETTINGS_TILE`) providing immediate 1-tap "Wake PC" from the Android notification shade without opening the app.
- **Automated UDP Beacon Discovery:** Android app checks for the 50ms UDP beacon on port 8002 before falling back to full /24 subnet scan.

### Hardware Readiness Diagnostics
- **WoL Readiness Engine (`engine/readiness.py`):** Deep inspection of physical network adapters, AC power status, sleep states (S0ix/S3), Fast Startup registry keys, and firewall rules.
- **Readiness Deck:** Interactive diagnostic card in the Web UI with actionable guidance.

## [2.2.0] - 2026-10-23
### Security & Authentication Hardening
- **Cryptographic Client Pairing:** Implemented 6-digit one-time pairing codes and 256-bit entropy device secrets stored locally in `config/paired_clients.json`.
- **HMAC-SHA256 Request Verification:** Destructive power and configuration endpoints require signed requests over `METHOD:PATH:TIMESTAMP:NONCE:BODY_SHA256`.
- **Anti-Replay Protection:** Added 60-second timestamp drift validation and in-memory nonce cache to block duplicate/replayed requests (`HTTP 403`).
- **Anti-Brute-Force Rate Limiting:** Enforced 5-minute lockout after 5 consecutive failed authentications (`HTTP 429`).
- **Audit Logging:** Added persistent audit logging (`wakex_audit.log`) tracking client IDs, IPs, timestamps, targets, and action results.
- **Unsafe Unlock Remediation:** Purged cleartext credential transmission and blind PowerShell `SendKeys` simulation. Replaced with safe display wake and lock screen curtain dismissal.
- **Power Action Idempotency Guard:** Caches recent action results by client and nonce to prevent duplicate OS executions on network retries.

### Networking & Connectivity
- **LAN Auto-Discovery Beacon:** Added lightweight UDP discovery daemon on port 8002 responding to `WAKEX_DISCOVER` pings in ~50ms.
- **Dynamic Subnet WoL Broadcast:** Upgraded Wake-on-LAN to broadcast across `255.255.255.255`, active subnet broadcast (`192.168.1.255`), and dual ports (9 and 7).
- **Windows Firewall & WoWLAN Automation:** Enhanced `enable_wowlan.bat` with self-elevating UAC support to open port 8000/8002, switch Wi-Fi profile to `Private`, and configure Wi-Fi Magic Packet wake properties.

### Mobile & Frontend UX
- **Android Anti-Hang Watchdog:** Implemented 6-second watchdog timer in `MainActivity.java` to prevent black-screen hangs on packet drops.
- **Network State Banner:** In-app real-time indicator alerting users if phone is on Cellular Data instead of home Wi-Fi.
- **Web Crypto Client Signer:** Implemented pure browser `window.crypto.subtle` HMAC signing in `static/app.js` for zero-framework client authentication.
- **Pairing UI:** Added Phone Pairing modal on PC deck and Mobile Pairing input dialog.

### Testing & Infrastructure
- Expanded test suite in `tests/test_wakex.py` to 20 automated tests validating HMAC signing, replay rejection, target isolation, WoL packet structure, and rate limiting.
- Modernized FastAPI lifecycle from deprecated `@app.on_event("startup")` to async lifespan context managers.

## [2.1.0] - 2026-10-09
- Initial multi-device target isolation architecture.
- Added Linux remote daemon agent (`agent/wakex_agent.py`) and systemd installer.
- Added Start Menu application indexing (`engine/workspace.py`) and workspace scheduler.
- Purged prototype `1234` PIN from all source code and documentation.
