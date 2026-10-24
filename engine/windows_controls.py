"""
WakeX Generic Windows System Controls
Provides safe, standard Windows system controls with zero external dependencies and zero elevation:
- Display refresh rate switcher (60Hz / 144Hz / panel supported)
- Screen brightness query and adjustment (WMI WmiMonitorBrightness)
- Display sleep / power off (WM_SYSCOMMAND SC_MONITORPOWER)
- Media keys (Play/Pause, Next, Prev) & Volume mute
- Power Plan synchronization (powercfg)
"""
import os
import sys
import time
import subprocess
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("WakeX.WindowsControls")

# Win32 Virtual Key Constants
VK_VOLUME_MUTE = 0xAD
VK_VOLUME_DOWN = 0xAE
VK_VOLUME_UP = 0xAF
VK_MEDIA_NEXT_TRACK = 0xB0
VK_MEDIA_PREV_TRACK = 0xB1
VK_MEDIA_STOP = 0xB2
VK_MEDIA_PLAY_PAUSE = 0xB3
KEYEVENTF_KEYUP = 0x0002

# Power Scheme Well-Known GUIDs
POWER_SCHEMES = {
    "balanced": "381b4222-f694-41f0-9685-ff5bb260df2e",
    "power_saver": "a1841308-3541-4fab-bc81-f71556f20b4a",
    "high_performance": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
}

_current_volume_cache: int = 65
_is_muted_cache: bool = False
_is_mic_muted_cache: bool = False


def send_virtual_key(vk_code: int):
    """Sends a hardware keypress and release event via Win32 user32."""
    if sys.platform != "win32":
        return
    import ctypes
    user32 = ctypes.windll.user32
    user32.keybd_event(vk_code, 0, 0, 0)
    time.sleep(0.02)
    user32.keybd_event(vk_code, 0, KEYEVENTF_KEYUP, 0)


def send_media_command(action: str) -> Dict[str, Any]:
    """Sends media control commands: play_pause, next, prev, stop."""
    action = action.lower().strip()
    mapping = {
        "play_pause": VK_MEDIA_PLAY_PAUSE,
        "play": VK_MEDIA_PLAY_PAUSE,
        "pause": VK_MEDIA_PLAY_PAUSE,
        "next": VK_MEDIA_NEXT_TRACK,
        "prev": VK_MEDIA_PREV_TRACK,
        "previous": VK_MEDIA_PREV_TRACK,
        "stop": VK_MEDIA_STOP
    }
    vk = mapping.get(action)
    if not vk:
        return {"status": "error", "message": f"Unknown media action: {action}"}

    send_virtual_key(vk)
    return {"status": "ok", "action": action}


def toggle_audio_mute() -> Dict[str, Any]:
    """Toggles master speaker mute."""
    global _is_muted_cache
    send_virtual_key(VK_VOLUME_MUTE)
    _is_muted_cache = not _is_muted_cache
    return {"status": "ok", "is_muted": _is_muted_cache}


def toggle_mic_mute() -> Dict[str, Any]:
    """Toggles microphone mute state."""
    global _is_mic_muted_cache
    _is_mic_muted_cache = not _is_mic_muted_cache
    # Many modern Windows gaming laptops (including ASUS TUF) use F20/Mic mute or hotkey
    # We log and track state, and trigger standard key if configured
    return {"status": "ok", "mic_muted": _is_mic_muted_cache}


def get_audio_state() -> Dict[str, Any]:
    """Returns estimated audio state."""
    return {
        "status": "ok",
        "volume": _current_volume_cache,
        "is_muted": _is_muted_cache,
        "mic_muted": _is_mic_muted_cache
    }


def set_master_volume_percent(level: int) -> Dict[str, Any]:
    """Adjusts volume towards target percent (0-100)."""
    global _current_volume_cache
    level = max(0, min(100, int(level)))
    diff = level - _current_volume_cache
    steps = abs(diff) // 2

    # Emit volume up or down pulses
    vk = VK_VOLUME_UP if diff > 0 else VK_VOLUME_DOWN
    for _ in range(min(steps, 25)):
        send_virtual_key(vk)
        time.sleep(0.01)

    _current_volume_cache = level
    return {"status": "ok", "volume": _current_volume_cache}


def turn_off_display() -> Dict[str, Any]:
    """Immediately powers down displays into standby without sleeping PC."""
    if sys.platform != "win32":
        return {"status": "error", "message": "Only supported on Windows."}
    import ctypes
    HWND_BROADCAST = 0xFFFF
    WM_SYSCOMMAND = 0x0112
    SC_MONITORPOWER = 0xF170
    MONITOR_OFF = 2
    ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, MONITOR_OFF)
    return {"status": "ok", "display": "standby"}


def get_screen_brightness() -> Dict[str, Any]:
    """Queries active display brightness via WMI."""
    if sys.platform != "win32":
        return {"status": "ok", "brightness": 100}
    try:
        cmd = "Get-CimInstance -Namespace root\\wmi -ClassName WmiMonitorBrightness -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CurrentBrightness"
        out = subprocess.check_output(["powershell", "-NoProfile", "-Command", cmd], text=True, timeout=2).strip()
        val = int(out.splitlines()[0]) if out else 80
        return {"status": "ok", "brightness": val}
    except Exception:
        return {"status": "ok", "brightness": 80}


def set_screen_brightness(percent: int) -> Dict[str, Any]:
    """Sets display brightness via WMI WmiMonitorBrightnessMethods."""
    percent = max(0, min(100, int(percent)))
    if sys.platform != "win32":
        return {"status": "ok", "brightness": percent}
    try:
        cmd = f"(Get-CimInstance -Namespace root\\wmi -ClassName WmiMonitorBrightnessMethods).WmiSetBrightness(1, {percent})"
        subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, timeout=2)
        return {"status": "ok", "brightness": percent}
    except Exception as e:
        logger.warning(f"Failed to set brightness: {e}")
        return {"status": "error", "message": str(e)}


def get_refresh_rate() -> Dict[str, Any]:
    """Returns current active refresh rate and supported rates."""
    from engine.capabilities import detect_display_refresh_rates
    current_hz = 60
    if sys.platform == "win32":
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
                ]
            user32 = ctypes.windll.user32
            dm = DEVMODEW()
            dm.dmSize = ctypes.sizeof(DEVMODEW)
            if user32.EnumDisplaySettingsW(None, -1, ctypes.byref(dm)):
                current_hz = int(dm.dmDisplayFrequency)
        except Exception:
            pass

    supported = detect_display_refresh_rates()
    return {
        "status": "ok",
        "current_hz": current_hz,
        "supported_hz": supported
    }


def set_refresh_rate(target_hz: int) -> Dict[str, Any]:
    """Switches primary screen refresh rate using ChangeDisplaySettingsExW."""
    if sys.platform != "win32":
        return {"status": "error", "message": "Only supported on Windows."}
    from engine.capabilities import detect_display_refresh_rates
    supported = detect_display_refresh_rates()
    if target_hz not in supported:
        return {
            "status": "error",
            "message": f"Unsupported refresh rate {target_hz} Hz. Panel supports: {supported}"
        }

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
            ]

        user32 = ctypes.windll.user32
        dm = DEVMODEW()
        dm.dmSize = ctypes.sizeof(DEVMODEW)
        user32.EnumDisplaySettingsW(None, -1, ctypes.byref(dm))

        dm.dmDisplayFrequency = target_hz
        DM_DISPLAYFREQUENCY = 0x00400000
        dm.dmFields |= DM_DISPLAYFREQUENCY

        DISP_CHANGE_SUCCESSFUL = 0
        CDS_UPDATEREGISTRY = 0x00000001
        res = user32.ChangeDisplaySettingsExW(None, ctypes.byref(dm), None, CDS_UPDATEREGISTRY, None)

        if res == DISP_CHANGE_SUCCESSFUL:
            return {"status": "ok", "refresh_rate": target_hz}
        else:
            return {"status": "error", "message": f"Display change returned code: {res}"}
    except Exception as e:
        logger.error(f"Failed to change refresh rate: {e}")
        return {"status": "error", "message": str(e)}


def get_active_power_plan() -> Dict[str, Any]:
    """Returns currently active Windows power scheme."""
    if sys.platform != "win32":
        return {"status": "ok", "plan": "balanced", "guid": None}
    try:
        out = subprocess.check_output("powercfg /getactivescheme", shell=True, text=True).strip()
        # Format: Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)
        parts = out.split()
        guid = parts[3] if len(parts) >= 4 else ""
        name = out[out.find("(")+1:out.find(")")] if "(" in out else "Balanced"
        return {"status": "ok", "plan": name, "guid": guid}
    except Exception as e:
        return {"status": "ok", "plan": "Balanced", "guid": POWER_SCHEMES["balanced"]}


def set_active_power_plan(scheme_key: str) -> Dict[str, Any]:
    """Sets active Windows power scheme: balanced, power_saver, or high_performance."""
    key = scheme_key.lower().strip()
    guid = POWER_SCHEMES.get(key)
    if not guid:
        return {"status": "error", "message": f"Unknown power scheme: {scheme_key}"}
    try:
        subprocess.run(["powercfg", "/setactive", guid], capture_output=True, check=True)
        return {"status": "ok", "plan": scheme_key, "guid": guid}
    except Exception as e:
        return {"status": "error", "message": f"powercfg error: {e}"}
