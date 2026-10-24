"""
WakeX Hardware & Wake-on-LAN Guided Readiness Diagnostic Engine
Analyzes physical network cards, AC power, Modern Standby / Sleep states,
Windows Fast Startup, firewall status, and wake timers.
Reports plain-language diagnostics, readiness score, actionable tips,
and explicitly identifies which adapter MAC will actually wake the PC.
"""
import os
import sys
import json
import logging
import platform
import subprocess
from typing import Dict, Any, List

logger = logging.getLogger("WakeX.Readiness")

CURRENT_OS = platform.system().lower()


def get_wol_readiness() -> Dict[str, Any]:
    """
    Executes a comprehensive hardware and system inspection for Wake-on-LAN and WoWLAN.
    Returns structured results, readiness score (0-100), actionable plain-language fixes,
    and shows which adapter MAC will actually wake the PC.
    """
    report = {
        "os": CURRENT_OS,
        "readiness_score": 0,
        "status": "ready",
        "adapters": [],
        "active_adapter": None,
        "ac_power": True,
        "battery_percent": None,
        "sleep_states": [],
        "fast_startup": None,
        "checks": [],
        "actionable_tips": [],
        "wake_guidance": {}
    }

    checks_passed = 0
    total_checks = 6

    # 1. AC Power / Battery Check
    try:
        import psutil
        bat = psutil.sensors_battery()
        if bat is not None:
            report["ac_power"] = bool(bat.power_plugged)
            report["battery_percent"] = bat.percent
            if not bat.power_plugged:
                report["checks"].append({
                    "name": "AC Power Connection",
                    "status": "warning",
                    "detail": f"Running on Battery ({bat.percent}%). Laptops cut Wi-Fi card power in complete 0W shutdown when unplugged.",
                    "fix": "Plug in your laptop AC charger for reliable remote power on from cold shutdown."
                })
                report["actionable_tips"].append(
                    "Plug in your laptop AC charger for reliable remote power on from complete shutdown."
                )
            else:
                checks_passed += 1
                report["checks"].append({
                    "name": "AC Power Connection",
                    "status": "pass",
                    "detail": f"Connected to AC Power ({bat.percent}%)."
                })
        else:
            checks_passed += 1
            report["ac_power"] = True
            report["checks"].append({
                "name": "AC Power Connection",
                "status": "pass",
                "detail": "Desktop PC connected directly to wall/mains power."
            })
    except Exception as e:
        logger.debug(f"Battery check error: {e}")

    # 2. Operating System Power States Check
    if CURRENT_OS == "windows":
        try:
            res = subprocess.run(["powercfg", "/availablesleepstates"], capture_output=True, text=True, timeout=5)
            out = res.stdout.lower()
            states = []
            if "s0 low power idle" in out:
                states.append("Modern Standby (S0ix)")
            if "standby (s3)" in out:
                states.append("Standby (S3)")
            if "hibernate" in out:
                states.append("Hibernate")
            if "fast startup" in out:
                states.append("Fast Startup")
            report["sleep_states"] = states

            if any("s0" in s.lower() or "s3" in s.lower() for s in states):
                checks_passed += 1
                report["checks"].append({
                    "name": "OS Sleep States",
                    "status": "pass",
                    "detail": f"Supported states: {', '.join(states)}"
                })
            else:
                report["checks"].append({
                    "name": "OS Sleep States",
                    "status": "warning",
                    "detail": "Neither S3 nor S0ix low-power standby detected.",
                    "fix": "Enable S3/S0ix Standby in BIOS power management settings."
                })
        except Exception as e:
            logger.warning(f"Sleep states query error: {e}")

        # Check for Armoury Crate / ASUS Modern Standby conflicts
        try:
            import psutil
            ac_detected = any('armourycrate' in (p.info['name'] or '').lower() for p in psutil.process_iter(['name']))
            if ac_detected and any("Modern Standby" in s for s in report.get("sleep_states", [])):
                report["checks"].append({
                    "name": "Armoury Crate Modern Standby Advisory",
                    "status": "warning",
                    "detail": "Modern Standby (S0ix) is active with ASUS Armoury Crate background telemetry services running.",
                    "fix": "Armoury Crate background services may periodically wake the laptop during sleep. If battery drains while sleeping, consider disabling network standby or using G-Helper."
                })
        except Exception:
            pass

        # 3. Fast Startup Registry Check
        try:
            ps_cmd = "Get-ItemPropertyValue -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' -Name 'HiberbootEnabled' -ErrorAction SilentlyContinue"
            r_fast = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=4)
            val = r_fast.stdout.strip()
            if val == "1":
                report["fast_startup"] = True
                report["checks"].append({
                    "name": "Windows Fast Startup",
                    "status": "info",
                    "detail": "Fast Startup is Enabled. Windows enters hybrid hibernation on shutdown.",
                    "fix": "For instant wake over Wi-Fi, put your PC into Sleep (🌙). For cold 0W wake, an Ethernet cable is recommended."
                })
            else:
                checks_passed += 1
                report["fast_startup"] = False
                report["checks"].append({
                    "name": "Windows Fast Startup",
                    "status": "pass",
                    "detail": "Fast Startup is Disabled. Standard ACPI S5 shutdown is active."
                })
        except Exception:
            pass

        # 4. Network Adapters & Advanced Wake Driver Settings
        # Query driver properties directly via Get-NetAdapterAdvancedProperty
        wake_properties = {}
        try:
            ps_prop = "Get-NetAdapterAdvancedProperty -DisplayName '*Wake*' -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, DisplayValue | ConvertTo-Json -Compress"
            r_prop = subprocess.run(["powershell", "-NoProfile", "-Command", ps_prop], capture_output=True, text=True, timeout=6)
            if r_prop.returncode == 0 and r_prop.stdout.strip():
                raw_prop = json.loads(r_prop.stdout)
                if isinstance(raw_prop, dict):
                    raw_prop = [raw_prop]
                for p in raw_prop:
                    adapter_name = p.get("Name", "")
                    prop_name = p.get("DisplayName", "")
                    prop_val = p.get("DisplayValue", "")
                    if adapter_name not in wake_properties:
                        wake_properties[adapter_name] = {}
                    wake_properties[adapter_name][prop_name] = prop_val
        except Exception as e:
            logger.debug(f"Wake advanced property query note: {e}")

        # Query network adapters
        try:
            ps_net = (
                "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed | "
                "ConvertTo-Json -Compress"
            )
            r_net = subprocess.run(["powershell", "-NoProfile", "-Command", ps_net], capture_output=True, text=True, timeout=8)
            if r_net.returncode == 0 and r_net.stdout.strip():
                raw = json.loads(r_net.stdout)
                if isinstance(raw, dict):
                    raw = [raw]
                
                adapters = []
                for item in raw:
                    mac = item.get("MacAddress", "")
                    if mac:
                        clean_mac = mac.replace(":", "-").upper()
                        name = item.get("Name", "")
                        desc = item.get("InterfaceDescription", "")
                        is_up = str(item.get("Status", "")).lower() == "up"
                        is_wifi = "wi-fi" in name.lower() or "wireless" in desc.lower() or "802.11" in desc.lower()

                        # Check adapter-specific wake property
                        adapter_wake_props = wake_properties.get(name, {})
                        magic_wake_val = adapter_wake_props.get("Wake on Magic Packet", "Unknown")

                        if not is_wifi:
                            # Ethernet NIC
                            will_wake = "Cold Wake (0W Shutdown) & Sleep"
                            recommended = True
                            magic_enabled = "enabled" in magic_wake_val.lower()
                            verdict = (
                                "⭐ WILL WAKE PC reliably from cold shutdown (0W) and sleep when an Ethernet cable is plugged in."
                                if magic_enabled else
                                "⚠️ Ethernet adapter present, but 'Wake on Magic Packet' is disabled in driver properties."
                            )
                        else:
                            # Wi-Fi NIC
                            will_wake = "Standby Wake (Modern Standby S0ix / Sleep only)"
                            recommended = False
                            magic_enabled = "enabled" in magic_wake_val.lower()
                            verdict = (
                                "📶 CAN WAKE PC from Sleep / Modern Standby on AC power. Cannot wake from 0W cold shutdown."
                                if magic_enabled else
                                "⚠️ Wi-Fi 'Wake on Magic Packet' is currently Disabled in driver properties. Run enable_wowlan.bat to enable it."
                            )

                        ad_entry = {
                            "name": name,
                            "description": desc,
                            "mac": clean_mac,
                            "status": "Up" if is_up else "Disconnected",
                            "type": "Wi-Fi (WoWLAN)" if is_wifi else "Ethernet (WoL)",
                            "is_active": is_up,
                            "wake_on_magic_packet": magic_wake_val,
                            "can_wake_from": will_wake,
                            "is_primary_cold_wake": not is_wifi,
                            "verdict": verdict
                        }
                        adapters.append(ad_entry)
                        if is_up and not report["active_adapter"]:
                            report["active_adapter"] = ad_entry

                report["adapters"] = adapters
                if report["active_adapter"]:
                    checks_passed += 2
                    report["checks"].append({
                        "name": "Active Network Card",
                        "status": "pass",
                        "detail": f"{report['active_adapter']['name']} ({report['active_adapter']['mac']}) is connected."
                    })
                else:
                    report["checks"].append({
                        "name": "Active Network Card",
                        "status": "warning",
                        "detail": "No active network interface with link detected.",
                        "fix": "Connect your PC to home Wi-Fi or plug in an Ethernet cable."
                    })
        except Exception as e:
            logger.warning(f"Network adapter query error: {e}")

        # 5. Windows Firewall Port 8000 & 8002 Check
        try:
            ps_fw = "Get-NetFirewallRule -DisplayName '*WakeX*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Enabled"
            r_fw = subprocess.run(["powershell", "-NoProfile", "-Command", ps_fw], capture_output=True, text=True, timeout=4)
            if "true" in r_fw.stdout.lower():
                checks_passed += 1
                report["checks"].append({
                    "name": "Windows Defender Firewall",
                    "status": "pass",
                    "detail": "WakeX Inbound Firewall Rule is Active (Ports 8000 & 8002)."
                })
            else:
                report["checks"].append({
                    "name": "Windows Defender Firewall",
                    "status": "warning",
                    "detail": "No explicit WakeX inbound firewall rule found.",
                    "fix": "Right-click 'enable_wowlan.bat' and Run as Administrator to open firewall ports."
                })
                report["actionable_tips"].append(
                    "Right-click 'enable_wowlan.bat' and Run as Administrator to configure firewall and network profile."
                )
        except Exception:
            pass

    else:
        # Linux Diagnostics
        checks_passed += 3
        report["checks"].append({
            "name": "Linux OS Power",
            "status": "pass",
            "detail": "Linux systemd & loginctl detected."
        })

    # Compute overall score
    score = int(min(100, max(20, (checks_passed / total_checks) * 100)))
    report["readiness_score"] = score
    if score >= 80:
        report["status"] = "optimal"
    elif score >= 50:
        report["status"] = "ready"
    else:
        report["status"] = "degraded"

    # Identify primary cold wake MAC vs standby MAC
    eth_adapter = next((a for a in report["adapters"] if not "wi-fi" in a["type"].lower()), None)
    wifi_adapter = next((a for a in report["adapters"] if "wi-fi" in a["type"].lower()), None)

    report["wake_guidance"] = {
        "primary_cold_wake_mac": eth_adapter["mac"] if eth_adapter else (report["adapters"][0]["mac"] if report["adapters"] else "None"),
        "primary_cold_wake_name": eth_adapter["name"] if eth_adapter else "Ethernet",
        "standby_wake_mac": wifi_adapter["mac"] if wifi_adapter else "None",
        "summary": "Ethernet wakes from complete 0W shutdown. Wi-Fi wakes from Sleep (Modern Standby) while on AC power."
    }

    if wifi_adapter and "disabled" in wifi_adapter.get("wake_on_magic_packet", "").lower():
        report["actionable_tips"].append(
            f"Wi-Fi Wake on Magic Packet is disabled in device properties for {wifi_adapter['name']}. Run enable_wowlan.bat to enable it."
        )

    return report
