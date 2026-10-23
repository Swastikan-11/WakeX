# WakeX Manual Hardware Verification Checklist

A comprehensive testing and verification manual covering all **6 core actions** on **Windows 10/11** and **Linux (systemd)** across **Ethernet (Wake-on-LAN)** and **Wi-Fi (Wake-on-Wireless-LAN)**.

---

## 1. Physical & BIOS/UEFI Pre-Requisites

| Setting / Check | Ethernet (WoL) | Wi-Fi (WoWLAN) | Explanation & Verification |
| :--- | :---: | :---: | :--- |
| **AC Power Connection** | Recommended | **Mandatory** | Laptops disable WoWLAN and cut radio power when running on battery to conserve charge. Always test with AC adapter plugged in. |
| **BIOS: PCIe / LAN Wake** | **Enabled** | N/A | In UEFI/BIOS under *Advanced Power Management* (APM), enable **"Power On By PCI-E"** or **"Wake on LAN"**. |
| **BIOS: ErP / EuP Ready** | **Disabled** (or S4+S5) | Disabled | Deep sleep ErP `<0.5W` cuts all +5VSB standby auxiliary power to Ethernet PHY chips, preventing WoL from S5 cold shutdown. |
| **Physical RJ45 LED** | **Blinking / Steady Amber/Green** | N/A | When the PC is shutdown (S5) or sleeping (S3/S0ix), the Ethernet port link LED must remain illuminated. If it turns completely black, standby power is cut by BIOS or driver. |
| **Wi-Fi AP Keep-Alive** | N/A | **Required** | Ensure router does not enforce AP Isolation / Client Isolation. The Wi-Fi access point must broadcast multicast packets on port 9. |

---

## 2. Operating System Configuration

### Windows 10 / 11

1. **Ethernet Driver Setup:**
   - Open Device Manager (`devmgmt.msc`) -> **Network adapters** -> Right-click Ethernet adapter -> **Properties**.
   - **Power Management Tab:**
     - Check: `Allow this device to wake the computer`.
     - Check: `Only allow a magic packet to wake the computer`.
   - **Advanced Tab:**
     - `Wake on Magic Packet` -> **Enabled**.
     - `Energy Efficient Ethernet` / `Green Ethernet` -> **Disabled** (prevents link negotiation dropout).
     - `Shutdown Wake-On-Lan` -> **Enabled**.
2. **Wi-Fi Adapter Setup (Modern Standby WoWLAN):**
   - Device Manager -> **Network adapters** -> Wi-Fi Controller (e.g. Intel AX200/AX210, MediaTek MT7921, Realtek) -> **Properties** -> **Advanced Tab**.
   - Set `Wake on Magic Packet` -> **Enabled** (if exposed by driver vendor).
   - Set `Wake on Pattern Match` -> **Enabled**.
   - *Quick Setup:* Run `enable_wowlan.bat` as Administrator from the WakeX root directory.
3. **Windows Fast Startup Nuance:**
   - Windows 10/11 "Fast Startup" uses a hybrid hibernate (S4) shutdown. Some legacy Realtek/Intel drivers fail to arm WoL in hybrid state. If waking fails after shutdown, test with Fast Startup disabled (`powercfg /h off` or via Control Panel Power Options).

### Linux (Debian, Ubuntu, Arch, Fedora)

1. **Ethernet WoL Enablement:**
   ```bash
   sudo apt-get install ethtool
   sudo ethtool -s eth0 wol g
   ```
   Verify with `sudo ethtool eth0 | grep "Wake-on"`. It must report `Wake-on: g`.
2. **Persistent systemd link configuration (`/etc/systemd/network/50-wired.link`):**
   ```ini
   [Match]
   Name=eth0

   [Link]
   WakeOnLan=magic
   ```
3. **Wi-Fi WoWLAN Enablement:**
   ```bash
   sudo iw phy phy0 wowlan enable magic-packet
   ```
   Verify with `sudo iw phy phy0 wowlan show`. It should output `WoWLAN is enabled: * wake up on magic packet`.

---

## 3. The 6 Power Actions: Verification Matrix

### Action 1: Wake (Turn On / WoL / WoWLAN)

| Channel | Initial State | Trigger Action | Expected Hardware Response | Verification Sign |
| :--- | :--- | :--- | :--- | :--- |
| **Ethernet** | Cold Power Off (S5) | Tap **"⚡ Turn On"** in WakeX UI, Tile, or Widget | Motherboard relays power on; fans spin; PC boots into OS. | Machine reaches login screen within normal boot time (~10-20s). WakeX Hub comes online. |
| **Ethernet** | Sleep (S3 / S0ix) | Tap **"⚡ Turn On"** | Instant resume; display awakens; network reconnects within 2-3s. | WakeX shows device status indicator turn green ("Online & Ready"). |
| **Wi-Fi** | Sleep (Modern Standby S0ix, AC connected) | Tap **"⚡ Turn On"** | Wi-Fi chip matches magic packet; host CPU awakens from low-power state. | Screen powers on, lockscreen displayed. |
| **Wi-Fi** | Cold Power Off (S5) | Tap **"⚡ Turn On"** | *Physical limitation:* Wi-Fi radio is unpowered in 0W S5 state. | WakeX correctly identifies this in Readiness Diagnostics and recommends Ethernet for cold-power wake. |

### Action 2: Sleep (Suspend)

| Channel | Trigger Action | Expected Hardware Response | Verification Sign |
| :--- | :--- | :--- | :--- |
| **Windows (Host/Remote)** | Tap **"🌙 Sleep"** in WakeX | Monitors turn off; CPU fans stop or enter silent low-RPM; power LED breathes/blinks. | Audio mutes; network switches to 10 Mbps WoL standby; WakeX Hub status flips to offline in 3s. |
| **Linux (Remote Agent)** | Tap **"🌙 Sleep"** in WakeX | `systemctl suspend` called; system enters S3/S0ix sleep state. | System power indicator blinks; fans power down. |

### Action 3: Hibernate

| Channel | Trigger Action | Expected Hardware Response | Verification Sign |
| :--- | :--- | :--- | :--- |
| **Windows** | Tap **"❄️ Hibernate"** in WakeX | System writes RAM contents to `hiberfil.sys` on NVMe/SSD, then cuts 100% of main system power. | Power LED shuts completely dark (same appearance as full shutdown). Machine can be woken up via Ethernet WoL. |
| **Linux** | Tap **"❄️ Hibernate"** in WakeX | `systemctl hibernate` called; RAM dumped to swap. | System powers off completely. Resumes with all previously opened windows intact. |

### Action 4: Restart

| Channel | Trigger Action | Expected Hardware Response | Verification Sign |
| :--- | :--- | :--- | :--- |
| **Windows** | Tap **"🔄 Restart"** in WakeX | Windows initiates reboot sequence (`shutdown /r /t 0`). | Display cycles through restart spinner; BIOS POST appears; OS re-boots and WakeX Hub auto-starts. |
| **Linux** | Tap **"🔄 Restart"** in WakeX | Agent calls `systemctl reboot`. | System restarts and daemon auto-reconnects on system boot. |

### Action 5: Shutdown

| Channel | Trigger Action | Expected Hardware Response | Verification Sign |
| :--- | :--- | :--- | :--- |
| **Windows** | Tap **"🛑 Shutdown"** in WakeX | Windows closes apps and powers down (`shutdown /s /t 0`). | Displays go black; fans stop; motherboard power relay clicks. Ethernet RJ45 link LED stays on for WoL. |
| **Linux** | Tap **"🛑 Shutdown"** in WakeX | Agent executes `systemctl poweroff`. | Machine halts and powers down cleanly. |

### Action 6: Lock & Unlock Screen

| Channel | Trigger Action | Expected Hardware Response | Verification Sign |
| :--- | :--- | :--- | :--- |
| **Lock (Windows)** | Tap **"🔒 Lock"** | Calls Win32 `LockWorkStation`. | Immediate display of Windows Lock / Login Screen. |
| **Lock (Linux)** | Tap **"🔒 Lock"** | Calls `loginctl lock-session`. | Active desktop session immediately locks. |
| **Unlock (Windows)** | Tap **"🔓 Unlock"** | Sends `SC_MONITORPOWER` to wake displays, sends synthetic input to raise the lock screen curtain. | Monitor wakes from DPMS sleep; curtain lifts ready for Windows Hello facial recognition, fingerprint, or PIN. |
| **Unlock (Linux)** | Tap **"🔓 Unlock"** | Calls `loginctl unlock-session || xset dpms force on`. | Monitor powers on; display manager presents unlock prompt. |

---

## 4. Hardware Verification Results Table (Action × OS × Medium)

> [!IMPORTANT]
> The table below records physical verification on target machines. Automated pytest test suites verify mock dispatches and packet byte structures; physical electrical wake and sleep transitions must be confirmed and filled in here on real hardware.

| Action | Target OS | Network Medium | Initial State | Expected Physical Hardware Behavior | Physical Test Status | Tested Date & Hardware Model |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| **Wake (WoL)** | Windows 10/11 | Ethernet | Cold Off (S5) | Motherboard relays on, fans spin, boots to login | `[ ] PENDING` | Real PC test pending |
| **Wake (WoL)** | Windows 10/11 | Ethernet | Sleep (S3/S0ix) | Instant resume, monitors wake, network links | `[ ] PENDING` | Real PC test pending |
| **Wake (WoWLAN)** | Windows 10/11 | Wi-Fi (AC plugged) | Modern Standby (S0ix) | Wi-Fi chip wakes CPU, lockscreen displayed | `[ ] PENDING` | Real PC test pending |
| **Wake (WoL)** | Linux (systemd) | Ethernet | Cold Off (S5) | PC powers on via ethtool `wol g` magic packet | `[ ] PENDING` | Real PC test pending |
| **Wake (WoL)** | Linux (systemd) | Ethernet | Suspend (S3) | Resumes to display manager | `[ ] PENDING` | Real PC test pending |
| **Wake (WoWLAN)** | Linux (systemd) | Wi-Fi (AC plugged) | Suspend (S3) | Resumes via iw WoWLAN magic packet | `[ ] PENDING` | Real PC test pending |
| **Sleep** | Windows 10/11 | Wi-Fi / Ethernet | Active Session | Enters S3/S0ix, power LED breathes, fans stop | `[ ] PENDING` | Real PC test pending |
| **Sleep** | Linux (systemd) | Wi-Fi / Ethernet | Active Session | `systemctl suspend` triggers low power sleep | `[ ] PENDING` | Real PC test pending |
| **Hibernate** | Windows 10/11 | Wi-Fi / Ethernet | Active Session | RAM written to hiberfil.sys, 0W cold powerdown | `[ ] PENDING` | Real PC test pending |
| **Hibernate** | Linux (systemd) | Wi-Fi / Ethernet | Active Session | `systemctl hibernate` dumps RAM to swap & halts | `[ ] PENDING` | Real PC test pending |
| **Restart** | Windows 10/11 | Wi-Fi / Ethernet | Active Session | Clean shutdown & reboot (`shutdown /r /t 0`) | `[ ] PENDING` | Real PC test pending |
| **Restart** | Linux (systemd) | Wi-Fi / Ethernet | Active Session | Clean reboot (`systemctl reboot`) | `[ ] PENDING` | Real PC test pending |
| **Shutdown** | Windows 10/11 | Wi-Fi / Ethernet | Active Session | Clean power off (`shutdown /s /t 0`) | `[ ] PENDING` | Real PC test pending |
| **Shutdown** | Linux (systemd) | Wi-Fi / Ethernet | Active Session | Clean power off (`systemctl poweroff`) | `[ ] PENDING` | Real PC test pending |
| **Lock** | Windows 10/11 | Wi-Fi / Ethernet | Active Session | Immediate lock screen via LockWorkStation | `[ ] PENDING` | Real PC test pending |
| **Lock** | Linux (systemd) | Wi-Fi / Ethernet | Active Session | Immediate lock screen via loginctl lock-session | `[ ] PENDING` | Real PC test pending |
| **Unlock (Display)** | Windows 10/11 | Wi-Fi / Ethernet | Locked / Monitors Off | DPMS wake + curtain dismissed (no credentials) | `[ ] PENDING` | Real PC test pending |
| **Unlock (Display)** | Linux (systemd) | Wi-Fi / Ethernet | Locked / Monitors Off | loginctl unlock-session / DPMS wake | `[ ] PENDING` | Real PC test pending |

---

## 5. Troubleshooting Checklist

- [ ] **PC does not wake from cold power-off over Ethernet:**
  - Verify Ethernet cable is plugged directly into a router/switch (not a USB-C hub that loses power when laptop shuts down).
  - Verify motherboard BIOS has `ErP/EuP` disabled and `PCIe Power On` enabled.
  - Verify the RJ45 port LED is lit while PC is off.
- [ ] **PC does not wake over Wi-Fi:**
  - Verify laptop is connected to wall AC charger (Wi-Fi sleep is disabled on battery).
  - Verify PC was put to **Sleep**, not full Shutdown.
  - Verify Router does not have "AP Isolation" or "Wireless Client Isolation" turned on.
- [ ] **Mobile app cannot reach PC:**
  - Verify both phone and PC are connected to the same Wi-Fi SSID / local subnet (e.g. `192.168.1.x`).
  - Check Windows Defender Firewall rule for port 8000 (TCP) and 8002 (UDP).
  - Tap the IP display in the mobile app to initiate automatic subnet scan and re-binding.
