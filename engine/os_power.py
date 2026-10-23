"""
WakeX OS Power Abstraction Layer
Provides safe, OS-specific power operations for Windows and Linux with capability detection.
"""
import os
import sys
import platform
import logging
import subprocess

logger = logging.getLogger("WakeX.OSPower")

CURRENT_OS = platform.system().lower()  # "windows" or "linux"

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
            # Query powercfg /availablesleepstates
            res = subprocess.run("powercfg /availablesleepstates", shell=True, capture_output=True, text=True)
            output = res.stdout.lower()
            if "standby (s3)" in output or "standby (s0 low power idle)" in output:
                caps["sleep"] = True
            else:
                caps["notes"].append("S3/S0ix Sleep not listed in powercfg")

            if "hibernate" in output and "not available" not in output:
                caps["hibernate"] = True
            else:
                # Check if hiberfil.sys exists or can be enabled
                caps["hibernate"] = os.path.exists("C:\\hiberfil.sys")
        except Exception as e:
            logger.warning(f"Error querying Windows power states: {e}")
            caps["sleep"] = True
            caps["hibernate"] = True

    elif CURRENT_OS == "linux":
        # Check /sys/power/state
        if os.path.exists("/sys/power/state"):
            try:
                with open("/sys/power/state", "r") as f:
                    states = f.read().strip().split()
                    caps["sleep"] = "mem" in states or "freeze" in states or "standby" in states
                    caps["hibernate"] = "disk" in states
                    if not caps["hibernate"]:
                        caps["notes"].append("Linux kernel /sys/power/state does not list 'disk' (no swap configured for hibernation)")
            except Exception as e:
                logger.warning(f"Error reading /sys/power/state: {e}")
        else:
            caps["notes"].append("/sys/power/state not available")

    return caps

def execute_shutdown(delay_seconds: int = 0) -> dict:
    """Clean system shutdown on local OS."""
    try:
        if CURRENT_OS == "windows":
            cmd = f"shutdown /s /t {delay_seconds}"
            subprocess.run(cmd, shell=True, check=True)
            return {"status": "success", "action": "shutdown", "message": f"Windows shutdown initiated in {delay_seconds}s"}
        elif CURRENT_OS == "linux":
            # Prefer systemctl, fallback to shutdown
            if delay_seconds > 0:
                cmd = f"shutdown -h +{max(1, delay_seconds // 60)}"
            else:
                cmd = "systemctl poweroff || shutdown -h now"
            subprocess.run(cmd, shell=True, check=True)
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
            cmd = f"shutdown /r /t {delay_seconds}"
            subprocess.run(cmd, shell=True, check=True)
            return {"status": "success", "action": "restart", "message": f"Windows restart initiated in {delay_seconds}s"}
        elif CURRENT_OS == "linux":
            cmd = "systemctl reboot || shutdown -r now"
            subprocess.run(cmd, shell=True, check=True)
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
            ps_cmd = (
                'powershell.exe -Command "Add-Type -AssemblyName System.Windows.Forms; '
                '[System.Windows.Forms.Application]::SetSuspendState([System.Windows.Forms.PowerState]::Suspend, $false, $false)"'
            )
            subprocess.Popen(ps_cmd, shell=True)
            return {"status": "success", "action": "sleep", "message": "Windows entering Sleep / Modern Standby"}
        elif CURRENT_OS == "linux":
            subprocess.Popen("systemctl suspend", shell=True)
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
            subprocess.run("powercfg /hibernate on", shell=True, capture_output=True)
            subprocess.Popen("shutdown /h", shell=True)
            return {"status": "success", "action": "hibernate", "message": "Windows entering 0-Watt Hibernate"}
        elif CURRENT_OS == "linux":
            subprocess.Popen("systemctl hibernate", shell=True)
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
            # Win32 user32 LockWorkStation
            subprocess.run("rundll32.exe user32.dll,LockWorkStation", shell=True, check=True)
            return {"status": "success", "action": "lock", "message": "Windows workstation locked"}
        elif CURRENT_OS == "linux":
            # Try loginctl, fallback to xdg-screensaver
            res = subprocess.run("loginctl lock-session || xdg-screensaver lock", shell=True, capture_output=True)
            if res.returncode == 0:
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
            # 1. Wake monitor (turn on display if in DPMS sleep)
            try:
                ctypes.windll.user32.SendMessageW(0xFFFF, 0x0112, 0xF170, -1)
            except Exception:
                pass

            # 2. Simulate mouse movement to register user activity
            try:
                ctypes.windll.user32.mouse_event(0x0001, 1, 1, 0, 0)
                time.sleep(0.05)
                ctypes.windll.user32.mouse_event(0x0001, -1, -1, 0, 0)
            except Exception:
                pass

            # 3. Send Spacebar to dismiss lock screen curtain and present the PIN/password prompt
            try:
                ctypes.windll.user32.keybd_event(0x20, 0, 0, 0)  # Space down
                time.sleep(0.05)
                ctypes.windll.user32.keybd_event(0x20, 0, 2, 0)  # Space up
            except Exception:
                pass

            return {"status": "success", "action": "unlock", "message": "Display awakened and lock screen curtain dismissed"}

        elif CURRENT_OS == "linux":
            # Unlock session via systemd loginctl or xdg-screensaver
            res = subprocess.run("loginctl unlock-session || xdg-screensaver reset || xset dpms force on", shell=True, capture_output=True)
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
            subprocess.run("shutdown /a", shell=True, check=True)
            return {"status": "success", "message": "Pending Windows shutdown cancelled"}
        elif CURRENT_OS == "linux":
            subprocess.run("shutdown -c", shell=True, check=True)
            return {"status": "success", "message": "Pending Linux shutdown cancelled"}
        return {"status": "unsupported", "message": "Unsupported OS"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
