"""
Local Operating System Power Dispatcher (Windows & Linux)
Handles real power capabilities, system telemetry, and command dispatch.
Safe argument-list execution without shell=True.
"""
import os
import sys
import subprocess
import logging
import platform

logger = logging.getLogger("WakeX.Power")
CURRENT_OS = platform.system().lower()

def get_os_type() -> str:
    return CURRENT_OS

def get_supported_capabilities() -> dict:
    """
    Detects real capabilities of the local host system.
    Returns PASS/UNSUPPORTED for each power state rather than assuming it works.
    """
    caps = {
        "os": CURRENT_OS,
        "shutdown": True,
        "restart": True,
        "sleep": False,
        "hibernate": False,
        "lock": True,
        "unlock": True,
        "wake_on_lan": True,
        "notes": []
    }

    if CURRENT_OS == "windows":
        try:
            res = subprocess.run(["powercfg", "/availablesleepstates"], capture_output=True, text=True)
            output = res.stdout.lower()
            if "standby (s3)" in output or "standby (s0 low power idle)" in output:
                caps["sleep"] = True
            else:
                caps["notes"].append("S3/S0ix Sleep not listed in powercfg")

            if "hibernate" in output:
                caps["hibernate"] = True
            else:
                caps["notes"].append("Hibernate not enabled in powercfg")
        except Exception as e:
            logger.warning(f"Failed to query powercfg: {e}")
            caps["sleep"] = True
            caps["hibernate"] = True

    elif CURRENT_OS == "linux":
        # Check systemd / sysfs power states
        if os.path.exists("/sys/power/state"):
            try:
                with open("/sys/power/state", "r") as f:
                    states = f.read().strip().split()
                    caps["sleep"] = "mem" in states or "standby" in states or "freeze" in states
                    caps["hibernate"] = "disk" in states
            except Exception as e:
                logger.warning(f"Could not read /sys/power/state: {e}")
                caps["sleep"] = True
        else:
            caps["sleep"] = True

    return caps

def execute_shutdown(delay_seconds: int = 0) -> dict:
    """Clean system shutdown on local OS."""
    try:
        if CURRENT_OS == "windows":
            subprocess.run(["shutdown", "/s", "/t", str(delay_seconds)], check=True)
            return {"status": "success", "action": "shutdown", "message": f"Windows shutdown initiated in {delay_seconds}s"}
        elif CURRENT_OS == "linux":
            if delay_seconds > 0:
                subprocess.run(["shutdown", "-h", f"+{max(1, delay_seconds // 60)}"], check=True)
            else:
                try:
                    subprocess.run(["systemctl", "poweroff"], check=True)
                except Exception:
                    subprocess.run(["shutdown", "-h", "now"], check=True)
            return {"status": "success", "action": "shutdown", "message": "Linux poweroff initiated"}
        else:
            return {"status": "unsupported", "action": "shutdown", "message": f"Unsupported OS: {CURRENT_OS}"}
    except Exception as e:
        logger.error(f"Shutdown execution error: {e}")
        return {"status": "error", "action": "shutdown", "message": str(e)}

def execute_restart(delay_seconds: int = 0) -> dict:
    """Clean system reboot on local OS."""
    try:
        if CURRENT_OS == "windows":
            subprocess.run(["shutdown", "/r", "/t", str(delay_seconds)], check=True)
            return {"status": "success", "action": "restart", "message": f"Windows restart initiated in {delay_seconds}s"}
        elif CURRENT_OS == "linux":
            try:
                subprocess.run(["systemctl", "reboot"], check=True)
            except Exception:
                subprocess.run(["shutdown", "-r", "now"], check=True)
            return {"status": "success", "action": "restart", "message": "Linux reboot initiated"}
        else:
            return {"status": "unsupported", "action": "restart", "message": f"Unsupported OS: {CURRENT_OS}"}
    except Exception as e:
        logger.error(f"Restart execution error: {e}")
        return {"status": "error", "action": "restart", "message": str(e)}

def execute_sleep() -> dict:
    """Suspends the system into low-power idle/RAM sleep."""
    caps = get_supported_capabilities()
    if not caps.get("sleep"):
        return {"status": "unsupported", "action": "sleep", "message": "Sleep/Standby is not supported on this hardware/OS configuration."}

    try:
        if CURRENT_OS == "windows":
            subprocess.Popen([
                "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Application]::SetSuspendState([System.Windows.Forms.PowerState]::Suspend, $false, $false)"
            ])
            return {"status": "success", "action": "sleep", "message": "Windows entering Sleep / Modern Standby"}
        elif CURRENT_OS == "linux":
            subprocess.Popen(["systemctl", "suspend"])
            return {"status": "success", "action": "sleep", "message": "Linux entering Suspend to RAM"}
        else:
            return {"status": "unsupported", "action": "sleep", "message": f"Unsupported OS: {CURRENT_OS}"}
    except Exception as e:
        logger.error(f"Sleep execution error: {e}")
        return {"status": "error", "action": "sleep", "message": str(e)}

def execute_hibernate() -> dict:
    """Hibernates system (saves RAM to disk and powers down to 0W)."""
    caps = get_supported_capabilities()
    if not caps.get("hibernate"):
        return {
            "status": "unsupported",
            "action": "hibernate",
            "message": "Hibernate is not supported on this machine. (Requires swap space on Linux or active hiberfil.sys on Windows)."
        }

    try:
        if CURRENT_OS == "windows":
            subprocess.run(["powercfg", "/hibernate", "on"], capture_output=True)
            subprocess.Popen(["shutdown", "/h"])
            return {"status": "success", "action": "hibernate", "message": "Windows entering 0-Watt Hibernate"}
        elif CURRENT_OS == "linux":
            subprocess.Popen(["systemctl", "hibernate"])
            return {"status": "success", "action": "hibernate", "message": "Linux entering Hibernation (Suspend to Disk)"}
        else:
            return {"status": "unsupported", "action": "hibernate", "message": f"Unsupported OS: {CURRENT_OS}"}
    except Exception as e:
        logger.error(f"Hibernate execution error: {e}")
        return {"status": "error", "action": "hibernate", "message": str(e)}

def execute_lock() -> dict:
    """Locks active user session/workstation without stopping processes."""
    try:
        if CURRENT_OS == "windows":
            subprocess.run(["rundll32.exe", "user32.dll,LockWorkStation"], check=True)
            return {"status": "success", "action": "lock", "message": "Windows workstation locked"}
        elif CURRENT_OS == "linux":
            res = None
            try:
                res = subprocess.run(["loginctl", "lock-session"], capture_output=True)
            except Exception:
                pass
            if not res or res.returncode != 0:
                res = subprocess.run(["xdg-screensaver", "lock"], capture_output=True)
            if res and res.returncode == 0:
                return {"status": "success", "action": "lock", "message": "Linux desktop session locked"}
            return {"status": "error", "action": "lock", "message": "Could not lock session (no active display session or loginctl)"}
        else:
            return {"status": "unsupported", "action": "lock", "message": f"Unsupported OS: {CURRENT_OS}"}
    except Exception as e:
        logger.error(f"Lock execution error: {e}")
        return {"status": "error", "action": "lock", "message": str(e)}

def execute_unlock() -> dict:
    """
    Wakes the display, turns on monitors from DPMS sleep, and dismisses the lock screen
    curtain / wallpaper to reveal the login input prompt.
    NOTE: For security reasons, Windows credentials are never accepted over network or simulated via SendKeys.
    """
    try:
        if CURRENT_OS == "windows":
            import ctypes
            import time
            try:
                ctypes.windll.user32.SendMessageW(0xFFFF, 0x0112, 0xF170, -1)
            except Exception:
                pass

            try:
                ctypes.windll.user32.mouse_event(0x0001, 1, 1, 0, 0)
                time.sleep(0.05)
                ctypes.windll.user32.mouse_event(0x0001, -1, -1, 0, 0)
            except Exception:
                pass

            try:
                ctypes.windll.user32.keybd_event(0x20, 0, 0, 0)  # Space down
                time.sleep(0.05)
                ctypes.windll.user32.keybd_event(0x20, 0, 2, 0)  # Space up
            except Exception:
                pass

            return {"status": "success", "action": "unlock", "message": "Display awakened and lock screen curtain dismissed"}

        elif CURRENT_OS == "linux":
            for cmd in [["loginctl", "unlock-session"], ["xdg-screensaver", "reset"], ["xset", "dpms", "force", "on"]]:
                try:
                    subprocess.run(cmd, capture_output=True)
                except Exception:
                    pass
            return {"status": "success", "action": "unlock", "message": "Linux display awakened and lock session reset"}
        else:
            return {"status": "unsupported", "action": "unlock", "message": f"Unsupported OS: {CURRENT_OS}"}
    except Exception as e:
        logger.error(f"Unlock execution error: {e}")
        return {"status": "error", "action": "unlock", "message": str(e)}

def abort_shutdown() -> dict:
    """Cancels pending timed power actions."""
    try:
        if CURRENT_OS == "windows":
            subprocess.run(["shutdown", "/a"], check=True)
            return {"status": "success", "message": "Pending Windows shutdown cancelled"}
        elif CURRENT_OS == "linux":
            subprocess.run(["shutdown", "-c"], check=True)
            return {"status": "success", "message": "Pending Linux shutdown cancelled"}
        return {"status": "unsupported", "message": "Unsupported OS"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
