# WakeX Security & Threat Model

**Version:** 2.4.0  
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
| **Plain HTTP Crypto Vulnerability** | Android WebView prioritizes native `AndroidWakeX.signRequest()` Keystore bridge. Web dashboards on plain HTTP (`http://<LAN-IP>:8000`) fall back to vendored `js-sha256` verified against RFC 4231 vectors. | **ENFORCED** |
| **Remote Linux Agent Compromise (Port 8001)** | Root daemon binds to LAN interface (`--host`), rejects unsigned tokens, enforces HMAC-SHA256 signature verification over every request, and uses discrete argument lists (no `shell=True`). | **ENFORCED** |
| **Credential Sniffing over Wi-Fi** | Windows/Linux credentials and passwords are **never** transmitted over the network. Keystroke simulation (`SendKeys`) was purged. Screen unlock only awakens monitors and dismisses the lock screen wallpaper curtain. | **ENFORCED** |
| **Cross-Device Accidental Shutdown (Host vs. Target)** | Target device ID verification in `devices.py`. Remote commands are dispatched exclusively via HTTP to the remote agent. Local Host OS commands are isolated and never invoked for remote targets. | **ENFORCED** |
| **Command Injection via Power APIs** | Actions are strictly whitelisted against an allowed enum (`shutdown`, `restart`, `sleep`, `hibernate`, `lock`, `unlock`, `abort`). All subprocess calls execute with discrete argument lists without shell interpretation. | **ENFORCED** |
| **Token Theft via Cloud Backups** | Android `allowBackup="false"` prevents APK settings and tokens from being extracted into unencrypted Google cloud backups. | **ENFORCED** |
| **Duplicate OS Execution (Double Taps)** | Server-side idempotency guard caches command results for 30s by client and nonce, returning cached results on duplicate network packets. | **ENFORCED** |

---

## 2. PAKE-Style Pairing Protocol (X25519 + HKDF + PIN Auth)

> [!IMPORTANT]
> **Protocol Update Notice:** WakeX v2.4.0 replaced legacy static pairing with an ephemeral X25519 PAKE-style handshake. **Existing paired devices must re-pair.**

```
Mobile Client (Phone)                                Hub (PC)
      |                                                 |
      |             1. User requests 6-digit PIN        |
      |             Tray displays single-use PIN (5m)   |
      |                                                 |
      |  2. POST /api/auth/pair/exchange               |
      |  Client X25519 Ephemeral Pubkey (Base64)        |
      | ----------------------------------------------> |
      |                                                 | Generates Hub X25519 Ephemeral Keypair
      |                                                 | Computes ECDH Shared Secret
      |                                                 | Derives Client Secret via HKDF-SHA256
      |  3. Returns session_id + Hub Pubkey (Base64)   |
      | <---------------------------------------------- |
      |                                                 |
      | Computes ECDH Shared Secret                     |
      | Derives Client Secret via HKDF-SHA256           |
      | Computes client_proof =                         |
      |   HMAC-SHA256(PIN, transcript || "client_auth")|
      |                                                 |
      |  4. POST /api/auth/pair/authenticate           |
      |  session_id + client_id + client_proof          |
      | ----------------------------------------------> | Verifies client_proof using PIN
      |                                                 | Checks attempts (< 5 across all IPs)
      |                                                 | Marks PIN consumed
      |                                                 | Computes hub_proof =
      |                                                 |   HMAC-SHA256(PIN, transcript || "hub_auth")
      |  5. Returns hub_proof + device metadata         |
      | <---------------------------------------------- |
      |                                                 |
      | Verifies hub_proof                              |
      | Mutual Auth Complete!                           |
```

- **Passive Eavesdropper Security:** The client secret is derived purely from the Diffie-Hellman secret `X25519(priv_client, pub_hub)`. A Wi-Fi packet capture seeing public keys and proofs cannot compute the shared secret or brute-force the PIN offline.
- **Active Attacker Defense:** An attacker attempting to authenticate without physical access to the tray PIN receives an immediate attempt counter decrement. After 5 failed attempts from any IP, the PIN is permanently revoked.

---

## 3. Remote Agent Security (Linux Port 8001)

The standalone root daemon (`agent/wakex_agent.py`):
1. **Host Binding:** Defaults to `--host <LAN-IP>` rather than exposing all interfaces unconditionally.
2. **Strict Cryptographic Authentication:** Enforces full HMAC-SHA256 signature verification over `METHOD:PATH:TIMESTAMP:NONCE:BODY_SHA256` matching the Hub. Legacy unsigned token bypass is purged.
3. **No Shell Execution:** Uses discrete argument lists (`["systemctl", "poweroff"]`, etc.) with `shell=False`.
4. **Action Whitelist:** Only accepts `shutdown`, `restart`, `sleep`, `hibernate`, `lock`, `unlock`, and `status`.

---

## 4. Signing Key & Keystore Management

- **Compromise Status of Legacy Keystore:** The legacy `android_build/wakex.keystore` (legacy test password) has been marked compromised and purged from git tracking.
- **External Release Keystores:** APK build scripts now store release signing keystores outside the workspace at `~/.wakex/wakex_release.keystore` (or path configured in `$env:WAKEX_KEYSTORE_PATH`).
- **Reinstallation Requirement:** Android devices with an older build signed with the legacy key must uninstall the existing app before installing new release APK builds due to Android's signature verification policy.

---

## 5. Hardware Wake-on-LAN Architecture

Wake-on-LAN sends an industry-standard 102-byte Magic Packet:
- 6 bytes of `0xFF`
- 16 repetitions of the target device's 6-byte IEEE 802 MAC address
- Broadcasted via UDP strictly to ports 9 and 7 across subnet broadcast (`192.168.1.255` / `255.255.255.255`). UDP port 0 was removed.

Physical hardware testing records are maintained in [docs/HARDWARE_CHECKLIST.md](docs/HARDWARE_CHECKLIST.md).

---

## 6. Reporting a Vulnerability

If you discover a security vulnerability in WakeX, please report it responsibly:
- **Preferred Method:** Open a [Private Security Advisory on GitHub](https://github.com/Swastikan-11/WakeX/security/advisories/new).
- **Alternative:** File an issue marked with the `security` label on the [WakeX GitHub Issues tracker](https://github.com/Swastikan-11/WakeX/issues).
- Please do not submit sensitive exploit details or reproduction scripts through public discussion forums until an advisory is reviewed and patched.

---

## 7. Security Boundaries & Operational Limits

1. **LAN-Only Scope:** WakeX is designed for trusted local-area networks (home/office). **Do NOT expose port 8000 directly to the public internet** via port-forwarding without a secure tunnel (e.g. WireGuard, Tailscale) or a reverse proxy.
2. **Plain HTTP vs. TLS:** WakeX uses application-layer HMAC-SHA256 signing and ephemeral X25519 PAKE for authentication and anti-replay protection. For end-to-end transport confidentiality against eavesdroppers on untrusted local Wi-Fi, place WakeX behind a reverse proxy (e.g. Caddy, Nginx) with HTTPS enabled.
3. **Upgrade Re-Pairing:** Security protocol updates (such as the v2.4.0 X25519 PAKE upgrade) intentionally invalidate previous pairing state to enforce modern cryptography. Existing devices must re-pair via the tray menu PIN after major upgrades.
