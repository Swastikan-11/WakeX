# Changelog

All notable changes to the WakeX project are documented here.

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
