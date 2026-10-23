# WakeX Security & Threat Model

**Version:** 2.2.0  
**Security Status:** Production Hardened (Local Cryptographic Verification)

WakeX controls high-privilege system power operations (**Shutdown, Restart, Sleep, Hibernate, Lock, Unlock Display, and Wake-on-LAN**). Consequently, security and safety isolation are paramount.

---

## 1. Threat Model & Safeguards

| Threat Vector | Mitigation Strategy | Implementation Status |
|---|---|---|
| **Unauthorized LAN Access / Hacker on Wi-Fi** | All power operations, schedules, and pairing actions are guarded by HMAC-SHA256 request verification using 256-bit client secrets. Unauthenticated calls are rejected with `HTTP 401`. | **ENFORCED** |
| **Packet Replay Attacks** | Every request requires Unix timestamp (`X-WakeX-Timestamp`) within 60s of server time and a unique random nonce (`X-WakeX-Nonce`). Reused nonces or skewed timestamps trigger `HTTP 403 Forbidden`. | **ENFORCED** |
| **Credential Sniffing over Wi-Fi** | Windows credentials and passwords are **never** transmitted over the network. Keystroke simulation (`SendKeys`) was purged. Screen unlock only awakens monitors and dismisses the lock screen wallpaper curtain. | **ENFORCED** |
| **Brute-Force Pairing / Auth Attacks** | IP-level rate-limiting tracks failures. >5 failed attempts within 3 minutes results in an automatic 5-minute lockout (`HTTP 429 Too Many Requests`). | **ENFORCED** |
| **Default Credential Exploits** | Prototype `1234` PIN completely removed. Client pairing generates 256-bit entropy random keys. | **ENFORCED** |
| **Cross-Device Accidental Shutdown (Host vs. Target)** | Target device ID verification in `devices.py`. Remote commands are dispatched exclusively via HTTP to the remote agent. Local Host OS commands are isolated and never invoked for remote targets. | **ENFORCED** |
| **Remote Agent Impersonation** | Remote agents require dedicated cryptographic tokens (`X-WakeX-Device-Token`) negotiated during pairing. | **ENFORCED** |
| **Command Injection via Power APIs** | Actions are strictly whitelisted against an allowed enum (`shutdown`, `restart`, `sleep`, `hibernate`, `lock`, `unlock`, `abort`). No raw shell input is accepted. | **ENFORCED** |
| **Token Theft via Cloud Backups** | Android `allowBackup="false"` prevents APK settings and tokens from being extracted into unencrypted Google cloud backups. | **ENFORCED** |
| **Duplicate OS Execution (Double Taps)** | Server-side idempotency guard caches command results for 30s by client and nonce, returning cached results on duplicate network packets. | **ENFORCED** |

---

## 2. Multi-Device Safety Guarantee

### Problem
In multi-computer environments, a critical safety vulnerability occurs if the Host/Hub defaults to executing power actions locally when targeting a secondary PC (e.g. Device B or C).

### WakeX Guarantee
Inside `engine/devices.py::dispatch_power_command`:
1. The requested `target_device_id` is queried from the local registry.
2. If `target.get("is_current") == True`:
   - Command is executed locally on Host Device A.
3. If `target.get("is_current") == False`:
   - **Local Host OS APIs (`os_power.execute_*`) are STRICTLY BYPASSED.**
   - An authenticated HTTP POST request is dispatched to `http://{target.ip}:{target.port}/api/agent/power` with header `X-WakeX-Device-Token: {target.auth_token}`.
   - If the remote agent is offline, unreachable, or times out, the Hub returns `DEVICE_UNREACHABLE`. **It NEVER falls back to executing on the local Host.**

---

## 3. Cryptographic Standards

- **Request Authentication:** HMAC-SHA256 computed over `METHOD:PATH:TIMESTAMP:NONCE:BODY_SHA256`.
- **Client Secrets:** 32-byte (256-bit) entropy tokens generated via `secrets.token_hex(32)`.
- **Timing Attacks:** Token and hash comparisons utilize `hmac.compare_digest` to prevent side-channel timing analysis.
- **Clock Drift Window:** 60 seconds maximum allowed drift.
- **Audit Logging:** Structured log entries in `wakex_audit.log` recording timestamp, client ID, IP, target device, and execution outcome.

---

## 4. Hardware Wake-on-LAN Architecture

Wake-on-LAN sends an industry-standard 102-byte Magic Packet:
- 6 bytes of `0xFF`
- 16 repetitions of the target device's 6-byte IEEE 802 MAC address
- Broadcasted via UDP to port 9 and port 7 across subnet broadcast (`192.168.1.255` / `255.255.255.255`).

### Hardware Prerequisites & Limitations
1. **NIC Standby Power:** The motherboard and Network Interface Card must maintain `+5VSB` standby electrical power. If the PC is unplugged from the wall or AC power is severed, WoL cannot function.
2. **BIOS / UEFI Settings:** `Wake on Magic Packet`, `PCIe PME Event Wake`, or `ErP/EuP` power-saving modes must be configured in BIOS:
   - Disable **Deep Sleep** or **ErP Ready** (which cuts NIC power in S5).
   - Enable **Power On By PCI-E Device**.
3. **Wi-Fi Limitations:** Most laptop Wi-Fi cards power down in S5 (cold shutdown) when on battery. Wake-on-LAN is 100% reliable over Ethernet cables; Wake-on-WLAN (WoWLAN) requires AC adapter connected and Modern Standby (S0ix) or S3 Sleep support.
