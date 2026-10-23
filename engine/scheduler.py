"""
AetherCommand Hardware Wake Scheduler
Schedules motherboard RTC wake timers using Windows Task Scheduler and kernel waitable timers.
"""
import os
import sys
import json
import logging
import datetime
import subprocess
from engine.storage import safe_read_json, atomic_write_json

logger = logging.getLogger("AetherCommand.Scheduler")

TASK_NAME = "WakeX_ScheduledWake"
if getattr(sys, 'frozen', False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

SETTINGS_PATH = os.path.join(APP_DIR, "config", "settings.json")

def enable_windows_wake_timers():
    """
    Enables 'Allow wake timers' in Windows active power scheme for both AC and Battery.
    This prevents Windows power management from ignoring hardware wake events.
    """
    try:
        # Enable RTC wake timers on AC
        subprocess.run(
            "powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP RTCWAKING 1",
            shell=True, capture_output=True
        )
        # Enable RTC wake timers on DC (battery)
        subprocess.run(
            "powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_SLEEP RTCWAKING 1",
            shell=True, capture_output=True
        )
        # Apply active scheme
        subprocess.run("powercfg /SETACTIVE SCHEME_CURRENT", shell=True, capture_output=True)
        return True
    except Exception as e:
        logger.warning(f"Could not set powercfg wake timers: {e}")
        return False

def configure_wake_schedule(time_str: str, days: list[str], enabled: bool = True) -> dict:
    """
    Configures a persistent Windows scheduled task with <WakeToRun> flag.
    - time_str: e.g. "08:50" (24-hour format)
    - days: list of 3-letter day codes ["Mon", "Tue", "Wed", "Thu", "Fri"]
    """
    enable_windows_wake_timers()
    
    if not enabled:
        # Delete task if disabled
        subprocess.run(f'schtasks /delete /tn "{TASK_NAME}" /f', shell=True, capture_output=True)
        return {"status": "success", "message": "Wake schedule disabled."}

    # Map day codes to PowerShell day names
    day_map = {
        "Mon": "Monday", "Tue": "Tuesday", "Wed": "Wednesday",
        "Thu": "Thursday", "Fri": "Friday", "Sat": "Saturday", "Sun": "Sunday"
    }
    valid_days = [day_map[d] for d in days if d in day_map]
    if not valid_days:
        valid_days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]

    days_ps = ",".join([f"'{d}'" for d in valid_days])

    # PowerShell command to create/update scheduled task with WakeToRun
    ps_cmd = f"""
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo AetherCommand Woke PC"
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek {days_ps} -At "{time_str}"
    $settings = New-ScheduledTaskSettingsSet -WakeToRun -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName "{TASK_NAME}" -Action $action -Trigger $trigger -Settings $settings -Force
    """

    try:
        res = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True)
        if res.returncode == 0:
            # Update settings.json
            _update_settings_file(time_str, days, enabled)
            return {
                "status": "success",
                "message": f"Hardware wake scheduled for {time_str} on {', '.join(days)}."
            }
        else:
            logger.error(f"Error registering task: {res.stderr}")
            return {"status": "error", "message": res.stderr}
    except Exception as e:
        logger.error(f"Failed to schedule wake: {e}")
        return {"status": "error", "message": str(e)}

def get_wake_status() -> dict:
    """Reads current schedule from settings and checks task scheduler."""
    data = safe_read_json(SETTINGS_PATH, default={})
    if isinstance(data, dict):
        return data.get("wake_schedule", {
            "enabled": False,
            "time": "08:50",
            "days": ["Mon", "Tue", "Wed", "Thu", "Fri"]
        })
    return {"enabled": False, "time": "08:50", "days": []}

def _update_settings_file(time_str: str, days: list[str], enabled: bool):
    try:
        data = safe_read_json(SETTINGS_PATH, default={})
        if not isinstance(data, dict):
            data = {}
        data["wake_schedule"] = {
            "enabled": enabled,
            "time": time_str,
            "days": days
        }
        atomic_write_json(SETTINGS_PATH, data)
    except Exception as e:
        logger.error(f"Failed updating settings: {e}")
