# WakeX Security & Threat Model

**Version:** 3.0.0  
**Security Architecture:** Local-First Zero-Trust Architecture (Cryptographic Verification)

WakeX controls high-privilege system power operations (**Shutdown, Restart, Sleep, Hibernate, Lock, Unlock Display, and Wake-on-LAN**). Consequently, security, target isolation, and defensive cryptography are strictly enforced.

---

## 1. Threat Model & Safeguards

| Threat Vector | Mitigation Strategy | Implementation Status |
|---|---|---|
| **Wi-Fi Eavesdropping / Passive Sniffing** | Pairing uses ephemeral X25519 key exchange with HKDF-SHA256 derivation. Long-term client secret is never transmitted across the network. Handshake transcript mutual authentication is keyed with the single-use 6-digit PIN. | **ENFORCED** |
| **PIN Offline Brute-Force Attacks** | Secret is derived purely from X25519 ECDH, never from the PIN. Passive eavesdroppers learn nothing from network traffic. Active attackers get exactly one online guess per attempt. | **ENFORCED** |
| **PIN Online Guessing & Distributed Brute-Force** | 6-digit PIN is single-use, expires in 5 minutes, and is limited to 5 attempts *globally across all source IPs* per PIN. Exceeding 5 attempts immediately revokes the PIN. | **ENFORCED** |
| **Unauthorized LAN Access / Hacker on Wi-Fi** | All power operations, schedules, and agent endpoints require HMAC-SHA256 request verification using 256-bit client secrets. Unauthenticated calls are rejected with `HTTP 401`. | **ENFORCED** |
| **Packet Replay Attacks** | Every request requires Unix timestamp (`X-WakeX-Timestamp`) within 60s of server time and a unique random nonce (`X-WakeX-Nonce`). Reused nonces or skewed timestamps trigger `HTTP 403 Forbidden`. Requests dated prior to hub start time (`req_ts < PROCESS_START_TIME - 5.0`) are unconditionally rejected. | **ENFORCED** |
| **Plain HTTP Crypto Vulnerability** | Android WebView prioritizes native `AndroidWakeX.signRequest()` Keystore bridge. Web dashboards on plain HTTP (`http://<LAN-IP>:8000`) fall back to vendored `TweetNaCl.js` and `js-sha256` verified against RFC 4231 vectors. | **ENFORCED** |
| **Remote Linux Agent Compromise (Port 8001)** | Root daemon binds to LAN interface (`--host`), rejects unsigned tokens, enforces HMAC-SHA256 signature verification over every request, and uses discrete argument lists (no `shell=True`). | **ENFORCED** |
| **Credential Sniffing over Wi-Fi** | Windows/Linux credentials and passwords are **never** transmitted over the network. Keystroke simulation (`SendKeys`) was purged. Screen unlock only awakens monitors and dismisses the lock screen wallpaper curtain. | **ENFORCED** |
| **Cross-Device Accidental Shutdown (Host vs. Target)** | Target device ID verification in `devices.py`. Remote commands are dispatched exclusively via HTTP to the remote agent. Local Host OS commands are isolated and never invoked for remote targets. | **ENFORCED** |
| **Command Injection via Power APIs** | Actions are strictly whitelisted against an allowed enum (`shutdown`, `restart`, `sleep`, `hibernate`, `lock`, `unlock`, `abort`). All subprocess calls execute with discrete argument lists without shell interpretation. | **ENFORCED** |
| **Token Theft via Cloud Backups** | Android `allowBackup="false"` prevents APK settings and tokens from being extracted into unencrypted Google cloud backups. | **ENFORCED** |
| **Duplicate OS Execution (Double Taps)** | Server-side idempotency guard caches command results for 30s by client and nonce, returning cached results on duplicate network packets. | **ENFORCED** |

---

## 2. PAKE-Style Pairing Protocol (X25519 + HKDF + PIN Auth)

> [!IMPORTANT]
> **Protocol Notice:** WakeX v3.0.0 uses an ephemeral X25519 PAKE-style handshake. **Existing paired devices must re-pair.**

```
Mobile Client (Phone)                                Hub (PC)
      |                                                 |
      |             1. User requests 6-digit PIN        |
      |             Tray displays single-use PIN (5m)   |
      |                                                 |
      |  2. POST /api/auth/pair/exchange                |
      |  {client_id, pubKey_client, nonce_client}       |
      |------------------------------------------------>|
      |                                                 |  Generate Ephemeral X25519 keypair
      |                                                 |  Compute ECDH: shared_secret
      |  3. Return 200 OK                               |  Derive: client_secret via HKDF
      |  {session_id, pubKey_hub, nonce_hub}            |
      |<------------------------------------------------|
      |                                                 |
      |  Compute ECDH: shared_secret                    |
      |  Derive: client_secret via HKDF                 |
      |  transcript = id:pubC:nC:pubH:nH                |
      |  proof = HMAC-SHA256(PIN, "CLIENT:" + trans)    |
      |                                                 |
      |  4. POST /api/auth/pair/authenticate            |
      |  {session_id, PIN, proof}                       |
      |------------------------------------------------>|
      |                                                 |  Verify PIN attempts <= 5
      |                                                 |  Verify proof == expected
      |                                                 |  Register client in paired_clients.json
      |  5. Return 200 OK                               |  Destroy session and PIN
      |<------------------------------------------------|
      |                                                 |
```

---

## 3. What WakeX Protects Against & What It Does Not

### What WakeX Protects Against
1. **Wi-Fi Eavesdroppers:** Passive packet capture on unencrypted or shared Wi-Fi networks yields no usable secrets (ephemeral ECDH + HKDF).
2. **Replay Attacks:** Captured legitimate power packets cannot be re-sent later to force an unauthorized shutdown.
3. **Target Cross-Contamination:** A compromised or misrouted request for Device B will never execute on Device A (Host).
4. **Command Injection:** Strict whitelist parsing ensures no shell command interpolation.

### What WakeX Does NOT Protect Against (System Boundaries)
1. **Compromised Host or Phone OS:** If an attacker has root or administrative malware on the host PC or paired phone, they can access local storage.
2. **Plain HTTP In-Transit Tampering (without AP Isolation):** When accessing the web dashboard over plain HTTP on an untrusted Wi-Fi router without AP Isolation, an active Man-in-the-Middle attacker could modify unencrypted web page assets. Use the Android companion app (which validates signatures internally) or operate on a trusted private network.
3. **Physical Access:** WakeX does not prevent someone sitting physically at the PC from pressing the physical power button or keyboard.

---

## 4. Local Audit Logging
All authentication events, pairing exchanges, and power execution dispatches are appended locally to `wakex_audit.log`:
- Log files are strictly local to the machine.
- Plaintext passwords, tokens, client secrets, and 6-digit PINs are **never** recorded in logs.
- Log entries record timestamp, action, client ID, and outcome status.

---

## 5. Security Verification & CI Testing
Every commit and release is verified against:
- Automated pytest security suite (`tests/test_wakex.py`, `tests/test_coverage_and_network.py`, `tests/test_frontend_resilience.py`, `tests/test_simulated_lan.py`).
- Android companion unit tests (`android_build/test/WakeXUnitTest.java`).
- Gitleaks secret scanning across working tree and entire Git history.
- Dependency audit (`pip-audit`) with 0 known vulnerabilities.

---

## 6. How to Report Security Issues
If you discover a vulnerability or security flaw in WakeX, please do NOT file a public issue on GitHub.
Instead, report it privately via GitHub Security Advisories or contact the maintainer at `Swastikan-11@users.noreply.github.com`.
All verified vulnerabilities will be patched promptly with credited attributions in `CHANGELOG.md`.
