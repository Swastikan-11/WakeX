# WakeX Privacy Policy

**Last Updated:** October 2026  
**Status:** In Force

WakeX ("WakeX Hub", "WakeX Agent", "WakeX Android App") is designed with a **zero-cloud, privacy-first, local-network architecture**. WakeX does not operate central servers, does not collect analytics, and does not sell or share any user or device data with third parties.

---

## 1. Data Collection & Transmission

### Zero Cloud Transmission
- **No telemetry, analytics, or behavioral tracking** are implemented.
- **Zero data is sent outside your local area network (LAN)** unless you explicitly configure a private VPN/mesh network (such as Tailscale or WireGuard) under your personal control.
- WakeX does not communicate with any external vendor servers, advertisement networks, or data brokers.

---

## 2. Information Handled Locally

All operational data is stored strictly on your local machine in the `config/` directory:

| Data Type | Purpose | Storage Method | Retention |
|---|---|---|---|
| **Device Names & Custom Labels** | User identification of target PCs | Plaintext in `config/devices.json` | Until device is deleted/unpaired |
| **IP Addresses & Port Numbers** | Routing power commands across LAN | Plaintext in `config/devices.json` | Until device is deleted/unpaired |
| **MAC Addresses** | Generating 102-byte Wake-on-LAN Magic Packets | Plaintext in `config/devices.json` | Until device is deleted/unpaired |
| **Master Security PIN** | Authenticating user commands on dashboard & API | **Salted PBKDF2-HMAC-SHA256 hash** (100,000 iterations); raw PIN is **never stored** | Stored in `config/settings.json` until reset |
| **Session Tokens** | 256-bit cryptographically random tokens for API sessions | Plaintext in `config/settings.json` | Stored locally until PIN change |
| **Agent Authentication Tokens** | Mutual authentication between Hub and remote Agents | Stored in `config/devices.json` and agent config | Until unpair or re-registration |
| **Desktop Snapshots** | Telemetry preview within the local dashboard | Transmitted ephemerally in-memory (JPEG) | **Never saved to disk; 0 retention** |

---

## 3. Security of Authentication Credentials

- **Zero Hardcoded Backdoors:** The default `1234` prototype PIN has been completely purged from the codebase, APIs, and default configurations.
- **First-Time Setup Required:** On initial launch, the user is required to create a unique Master Security PIN.
- **Cryptographic Storage:** Passwords and PINs are protected with salted PBKDF2-HMAC-SHA256. Plaintext credentials are never written to disk or logs.
- **Brute-Force Protection:** More than 5 consecutive invalid PIN attempts triggers an automatic 5-minute IP address lockout (HTTP 429).

---

## 4. Device Deletion and Data Purging

When you click **Delete / Unpair** on any device in the WakeX interface:
- All stored network identifiers (IP address, MAC address, port) are permanently deleted from `config/devices.json`.
- Associated authentication tokens are immediately revoked and purged.
- No historical records or telemetry logs for that device are retained.

---

## 5. Android Application Permissions

The WakeX Android APK requests strictly the minimum permissions required for operation:

* `android.permission.INTERNET`: Required to communicate with your local PC's WakeX server over Wi-Fi/LAN.
* `android.permission.ACCESS_NETWORK_STATE`: Used to detect network connectivity.
* `android.permission.WAKE_LOCK`: Ensures the phone remains awake long enough to dispatch the network request.
* `android:allowBackup="false"`: Insecure Android cloud backup of application preferences is explicitly disabled to prevent token extraction.

No access to camera, microphone, contacts, location, telephony, or external storage is requested or utilized.

---

## 6. Open Source Transparency

WakeX is fully open and inspectable. All source code, APIs, and daemon scripts reside in your local installation directory for independent audit and verification.
