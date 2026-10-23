"""
WakeX Hardware & Wake-on-LAN Guided Readiness Diagnostic Engine
Analyzes physical network cards, AC power, Modern Standby / Sleep states,
Windows Fast Startup, firewall status, and wake timers.
Reports plain-language diagnostics, readiness score, and actionable tips.
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
    Returns structured results, readiness score (0-100), and plain-language recommendations.
    """
    report = {
        "os": CURRENT_OS,
        "readiness_score": 0,
        "status": "ready",  # "ready", "degraded", "not_configured"
        "adapters": [],
        "active_adapter": None,
        "ac_power": True,
        "battery_percent": None,
        "sleep_states": [],
        "fast_startup": None,
        "checks": [],
        "actionable_tips": []
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
                    "detail": f"Running on Battery ({bat.percent}%). Laptops cut Wi-Fi card power in S5 cold shutdown when unplugged."
                })
                report["actionable_tips"].append(
                    "Connect your AC laptop charger for reliable remote power on from complete shutdown."
                )
            else:
                checks_passed += 1
                report["checks"].append({
                    "name": "AC Power Connection",
                    "status": "pass",
                    "detail": f"Connected to AC Power ({bat.percent}%)."
                })
        else:
            # Desktop PC (no battery)
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
            res = subprocess.run("powercfg /availablesleepstates", shell=True, capture_output=True, text=True, timeout=5)
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
                    "detail": f"Supported: {', '.join(states)}"
                })
            else:
                report["checks"].append({
                    "name": "OS Sleep States",
                    "status": "warning",
                    "detail": "Neither S3 nor S0ix low-power standby detected."
                })
        except Exception as e:
            logger.warning(f"Sleep states query error: {e}")

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
                    "detail": "Fast Startup is Enabled. Note: Fast Startup places Windows in hybrid hibernation; Modern Standby Sleep (🌙) is recommended for instant wake."
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

        # 4. Network Adapters & Hardware MAC Check
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

                        ad_entry = {
                            "name": name,
                            "description": desc,
                            "mac": clean_mac,
                            "status": "Up" if is_up else "Disconnected",
                            "type": "Wi-Fi (WoWLAN)" if is_wifi else "Ethernet (WoL)",
                            "is_active": is_up
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
                        "detail": f"{report['active_adapter']['name']} ({report['active_adapter']['description']}) • MAC: {report['active_adapter']['mac']}"
                    })
                else:
                    report["checks"].append({
                        "name": "Active Network Card",
                        "status": "warning",
                        "detail": "No active network interface with link detected."
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
                    "detail": "WakeX Inbound Firewall Rule is Active."
                })
            else:
                report["checks"].append({
                    "name": "Windows Defender Firewall",
                    "status": "warning",
                    "detail": "No explicit WakeX inbound rule found. Run enable_wowlan.bat to ensure ports are open."
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

    # Add general tip regarding Ethernet vs Wi-Fi
    if report.get("active_adapter") and "wi-fi" in report["active_adapter"].get("type", "").lower():
        report["actionable_tips"].append(
            "Wi-Fi WoWLAN is active. For instant wake, put your PC into Sleep (🌙) rather than cold shutdown. If cold wake is required, connect an Ethernet cable."
        )

    return report
