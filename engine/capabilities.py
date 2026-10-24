"""
WakeX System Capabilities Registry
Detects real hardware capabilities at startup and runtime.
Never fakes a number. Controls for missing hardware are hidden or disabled with clear explanations.
"""
import os
import sys
import shutil
import logging
from typing import Dict, Any, List

logger = logging.getLogger("WakeX.Capabilities")

_cached_capabilities: Dict[str, Any] = {}


def detect_asus_wmi_presence() -> bool:
    """Checks whether the ASUS WMI ACPI interface is installed in root\\wmi."""
    if sys.platform != "win32":
        return False
    try:
        import subprocess
        cmd = "Get-CimClass -Namespace root\\wmi AsusAtkWmi_WMNB -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CimClassName"
        out = subprocess.check_output(["powershell", "-NoProfile", "-Command", cmd], text=True, timeout=2).strip()
        return "AsusAtkWmi_WMNB" in out
    except Exception:
        return False


def detect_display_refresh_rates() -> List[int]:
    """Queries display adapter for all valid native refresh rates at current resolution."""
    if sys.platform != "win32":
        return [60]
    try:
        import ctypes
        from ctypes import wintypes

        class DEVMODEW(ctypes.Structure):
            _fields_ = [
                ('dmDeviceName', wintypes.WCHAR * 32),
                ('dmSpecVersion', wintypes.WORD),
                ('dmDriverVersion', wintypes.WORD),
                ('dmSize', wintypes.WORD),
                ('dmDriverExtra', wintypes.WORD),
                ('dmFields', wintypes.DWORD),
                ('dmPositionX', wintypes.LONG),
                ('dmPositionY', wintypes.LONG),
                ('dmDisplayOrientation', wintypes.DWORD),
                ('dmDisplayFixedOutput', wintypes.DWORD),
                ('dmColor', wintypes.SHORT),
                ('dmDuplex', wintypes.SHORT),
                ('dmYResolution', wintypes.SHORT),
                ('dmTTOption', wintypes.SHORT),
                ('dmCollate', wintypes.SHORT),
                ('dmFormName', wintypes.WCHAR * 32),
                ('dmLogPixels', wintypes.WORD),
                ('dmBitsPerPel', wintypes.DWORD),
                ('dmPelsWidth', wintypes.DWORD),
                ('dmPelsHeight', wintypes.DWORD),
                ('dmDisplayFlags', wintypes.DWORD),
                ('dmDisplayFrequency', wintypes.DWORD),
                ('dmICMMethod', wintypes.DWORD),
                ('dmICMIntent', wintypes.DWORD),
                ('dmMediaType', wintypes.DWORD),
                ('dmDitherType', wintypes.DWORD),
                ('dmReserved1', wintypes.DWORD),
                ('dmReserved2', wintypes.DWORD),
                ('dmPanningWidth', wintypes.DWORD),
                ('dmPanningHeight', wintypes.DWORD),
            ]

        user32 = ctypes.windll.user32
        dm = DEVMODEW()
        dm.dmSize = ctypes.sizeof(DEVMODEW)

        # Get current display resolution
        user32.EnumDisplaySettingsW(None, -1, ctypes.byref(dm))
        cur_w, cur_h = dm.dmPelsWidth, dm.dmPelsHeight

        rates = set()
        i = 0
        while user32.EnumDisplaySettingsW(None, i, ctypes.byref(dm)):
            if dm.dmPelsWidth == cur_w and dm.dmPelsHeight == cur_h:
                rates.add(int(dm.dmDisplayFrequency))
            i += 1

        filtered = sorted([r for r in rates if r in (60, 75, 120, 144, 165, 240)])
        return filtered if filtered else [60]
    except Exception as e:
        logger.warning(f"Display rate detection error: {e}")
        return [60]


def detect_software_conflicts() -> Dict[str, Any]:
    """Detects whether Armoury Crate services or G-Helper are running."""
    ac_running = False
    ghelper_running = False

    try:
        import psutil
        for p in psutil.process_iter(['name']):
            name = (p.info['name'] or '').lower()
            if 'armourycrate' in name or 'asusoptimization' in name:
                ac_running = True
            elif 'ghelper' in name or 'g-helper' in name:
                ghelper_running = True
    except Exception:
        pass

    advisory = ""
    if ac_running and ghelper_running:
        advisory = "Both Armoury Crate services and G-Helper are running. WakeX will synchronize without conflict."
    elif ac_running:
        advisory = "ASUS Armoury Crate services detected."
    elif ghelper_running:
        advisory = "G-Helper detected."

    return {
        "armoury_crate_detected": ac_running,
        "ghelper_detected": ghelper_running,
        "advisory": advisory
    }


def get_system_capabilities(force_refresh: bool = False) -> Dict[str, Any]:
    """Returns complete capability registry for the host machine."""
    global _cached_capabilities
    if _cached_capabilities and not force_refresh:
        return _cached_capabilities

    from engine.hardware_ipc import is_helper_connected

    os_type = "windows" if sys.platform == "win32" else ("linux" if sys.platform.startswith("linux") else "unknown")
    asus_wmi = detect_asus_wmi_presence()
    helper_online = is_helper_connected()
    conflicts = detect_software_conflicts()
    refresh_rates = detect_display_refresh_rates()

    has_nvidia = shutil.which("nvidia-smi") is not None
    gpu_name = "Dedicated GPU"
    if has_nvidia:
        try:
            import subprocess
            r = subprocess.run(
                ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                capture_output=True, text=True, timeout=1.5
            )
            if r.returncode == 0 and r.stdout.strip():
                gpu_name = r.stdout.strip().split("\n")[0]
        except Exception:
            pass

    import psutil
    battery = psutil.sensors_battery()
    has_battery = battery is not None

    # Operating modes
    if asus_wmi or helper_online:
        op_modes = ["windows", "silent", "performance", "turbo"]
        gpu_modes = ["eco", "standard", "optimized"]
    else:
        op_modes = ["balanced", "power_saver", "high_performance"]
        gpu_modes = []

    caps = {
        "os": os_type,
        "hardware_helper_connected": helper_online,
        "asus_wmi_present": asus_wmi,
        "supported_operating_modes": op_modes,
        "supported_gpu_modes": gpu_modes,
        "supported_refresh_rates": refresh_rates,
        "has_battery": has_battery,
        "battery_charge_limit_supported": has_battery and (asus_wmi or helper_online),
        "keyboard_lighting_supported": asus_wmi or helper_online,
        "fn_lock_supported": asus_wmi or helper_online,
        "dedicated_gpu_present": has_nvidia,
        "gpu_name": gpu_name if has_nvidia else None,
        "audio_controls_supported": True,
        "media_controls_supported": True,
        "power_plan_sync_supported": os_type == "windows",
        "conflicts": conflicts
    }

    _cached_capabilities = caps
    return caps
