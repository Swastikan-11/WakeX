"""
WakeX Hardware Helper IPC Client & Hardware Dispatcher
Provides safe, typed communication between the non-elevated WakeX Hub and the elevated Hardware Helper.
Zero shell execution. Zero arbitrary file access.
Includes FakeHardwareBackend for automated testing and simulated environments.
"""
import os
import sys
import json
import time
import logging
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger("WakeX.HardwareIPC")

PIPE_NAME = r"\\.\pipe\WakeX_Hardware_Helper_IPC"
AUTH_KEY_DIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "WakeX")
AUTH_KEY_PATH = os.path.join(AUTH_KEY_DIR, "helper_auth.key")

# Environment flag to force in-process fake hardware backend (for testing / simulated LAN)
USE_FAKE_HARDWARE = os.environ.get("WAKEX_TEST_FAKE_HARDWARE", "0") == "1"


class FakeHardwareBackend:
    """In-memory mock of ASUS & privileged hardware controls for unit testing."""
    def __init__(self):
        self.operating_mode = "performance"
        self.battery_charge_limit = 80
        self.keyboard_brightness = 2
        self.keyboard_rgb_mode = "static"
        self.fn_lock = True
        self.dgpu_mode = "standard"
        self.cpu_fan_rpm = 2400
        self.gpu_fan_rpm = 2200
        self.cpu_temp = 58
        self.gpu_temp = 47
        self.gpu_sleeping = False

    def dispatch(self, cmd: str, params: Dict[str, Any]) -> Dict[str, Any]:
        cmd = cmd.upper()
        if cmd == "PING":
            return {"status": "ok", "message": "PONG (Fake Backend)", "elevated": True}

        elif cmd == "GET_STATUS":
            return {
                "status": "ok",
                "operating_mode": self.operating_mode,
                "battery_charge_limit": self.battery_charge_limit,
                "keyboard_brightness": self.keyboard_brightness,
                "fn_lock": self.fn_lock,
                "dgpu_mode": self.dgpu_mode,
                "cpu_fan_rpm": self.cpu_fan_rpm,
                "gpu_fan_rpm": self.gpu_fan_rpm,
                "cpu_temp": self.cpu_temp,
                "gpu_temp": self.gpu_temp,
                "gpu_sleeping": self.gpu_sleeping
            }

        elif cmd == "SET_OPERATING_MODE":
            mode = str(params.get("mode", "")).lower()
            if mode not in ("windows", "silent", "performance", "turbo"):
                return {"status": "error", "error_code": "INVALID_MODE", "message": f"Unsupported mode: {mode}"}
            self.operating_mode = mode
            if mode == "silent":
                self.cpu_fan_rpm = 1800
                self.gpu_fan_rpm = 0
            elif mode == "turbo":
                self.cpu_fan_rpm = 4200
                self.gpu_fan_rpm = 4000
            else:
                self.cpu_fan_rpm = 2400
                self.gpu_fan_rpm = 2200
            return {"status": "ok", "operating_mode": self.operating_mode}

        elif cmd == "SET_BATTERY_LIMIT":
            try:
                limit = int(params.get("limit", 80))
            except (ValueError, TypeError):
                return {"status": "error", "error_code": "INVALID_LIMIT", "message": "Limit must be an integer"}
            if limit not in (50, 60, 70, 80, 85, 90, 95, 100):
                return {"status": "error", "error_code": "LIMIT_OUT_OF_RANGE", "message": "Limit must be between 50 and 100"}
            self.battery_charge_limit = limit
            return {"status": "ok", "battery_charge_limit": self.battery_charge_limit}

        elif cmd == "SET_KEYBOARD_BRIGHTNESS":
            level = int(params.get("level", 2))
            if level not in (0, 1, 2, 3):
                return {"status": "error", "error_code": "INVALID_BRIGHTNESS", "message": "Level must be 0, 1, 2, or 3"}
            self.keyboard_brightness = level
            return {"status": "ok", "keyboard_brightness": self.keyboard_brightness}

        elif cmd == "SET_FN_LOCK":
            self.fn_lock = bool(params.get("enabled", True))
            return {"status": "ok", "fn_lock": self.fn_lock}

        elif cmd == "SET_DGPU_MODE":
            mode = str(params.get("mode", "")).lower()
            if mode not in ("eco", "standard", "optimized"):
                return {"status": "error", "error_code": "INVALID_GPU_MODE", "message": f"Unsupported GPU mode: {mode}"}
            self.dgpu_mode = mode
            self.gpu_sleeping = (mode == "eco")
            return {"status": "ok", "dgpu_mode": self.dgpu_mode, "reboot_required": False}

        elif cmd == "GET_FAN_RPM":
            return {"status": "ok", "cpu_fan_rpm": self.cpu_fan_rpm, "gpu_fan_rpm": self.gpu_fan_rpm}

        return {"status": "error", "error_code": "UNKNOWN_COMMAND", "message": f"Unrecognized helper command: {cmd}"}


_fake_backend = FakeHardwareBackend()


def get_helper_auth_token() -> str:
    """Reads or creates the secret local IPC auth token."""
    if os.path.exists(AUTH_KEY_PATH):
        try:
            with open(AUTH_KEY_PATH, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    # Fallback to local config directory for testing
    fallback = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "helper_auth.key")
    if os.path.exists(fallback):
        try:
            with open(fallback, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    return ""


def send_hardware_command(command: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Sends a strictly typed, allowlisted command to the Hardware Helper.
    If the helper is not running or fake mode is enabled, routes appropriately.
    """
    params = params or {}

    if USE_FAKE_HARDWARE or os.environ.get("WAKEX_TEST_FAKE_HARDWARE") == "1":
        return _fake_backend.dispatch(command, params)

    if sys.platform != "win32":
        return {
            "status": "error",
            "error_code": "PLATFORM_NOT_SUPPORTED",
            "message": "ASUS Hardware Helper is only available on Windows."
        }

    # Attempt Windows Named Pipe IPC
    try:
        import win32file
        import win32pipe
        import pywintypes

        token = get_helper_auth_token()
        payload = json.dumps({
            "auth_token": token,
            "command": command,
            "params": params
        }).encode("utf-8")

        # Connect to pipe with a short 1.5s timeout
        handle = win32file.CreateFile(
            PIPE_NAME,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            0,
            None
        )

        win32file.WriteFile(handle, payload)
        result, data = win32file.ReadFile(handle, 65536)
        win32file.CloseHandle(handle)

        resp = json.loads(data.decode("utf-8"))
        return resp

    except pywintypes.error as pe:
        # 2 = FILE_NOT_FOUND (pipe does not exist / service not running)
        return {
            "status": "error",
            "error_code": "HELPER_NOT_INSTALLED",
            "message": "WakeX Hardware Helper is not installed or running. Click 'Enable Hardware Controls' to set up."
        }
    except Exception as e:
        logger.warning(f"Hardware Helper IPC error: {e}")
        return {
            "status": "error",
            "error_code": "HELPER_IPC_ERROR",
            "message": f"Hardware Helper error: {str(e)}"
        }


def is_helper_connected() -> bool:
    """Checks whether the Hardware Helper is alive and answering."""
    if USE_FAKE_HARDWARE or os.environ.get("WAKEX_TEST_FAKE_HARDWARE") == "1":
        return True
    res = send_hardware_command("PING")
    return res.get("status") == "ok"
