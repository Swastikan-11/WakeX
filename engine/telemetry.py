"""
AetherCommand Telemetry & Diagnostics
Monitors CPU, Memory, Battery/AC power, Uptime, and Screen Captures.
"""
import io
import time
import psutil
import logging
from PIL import ImageGrab

logger = logging.getLogger("AetherCommand.Telemetry")

BOOT_TIME = psutil.boot_time()

def get_system_telemetry() -> dict:
    """Collects real-time hardware status metrics."""
    try:
        cpu_percent = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        
        # Battery telemetry
        battery = psutil.sensors_battery()
        if battery:
            battery_percent = round(battery.percent, 1)
            power_plugged = battery.power_plugged
            secs_left = battery.secsleft if battery.secsleft != psutil.POWER_TIME_UNLIMITED else -1
        else:
            # Desktop or driver unsupported
            battery_percent = 100.0
            power_plugged = True
            secs_left = -1

        # Calculate uptime
        uptime_seconds = int(time.time() - BOOT_TIME)
        hours, remainder = divmod(uptime_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        uptime_str = f"{hours}h {minutes}m {seconds}s"

        return {
            "status": "online",
            "cpu_percent": cpu_percent,
            "memory_percent": mem.percent,
            "memory_used_gb": round(mem.used / (1024 ** 3), 2),
            "memory_total_gb": round(mem.total / (1024 ** 3), 2),
            "battery_percent": battery_percent,
            "power_plugged": power_plugged,
            "battery_secs_left": secs_left,
            "uptime": uptime_str,
            "timestamp": time.time()
        }
    except Exception as e:
        logger.error(f"Error gathering telemetry: {e}")
        return {
            "status": "error",
            "error": str(e),
            "timestamp": time.time()
        }

def capture_screen_jpeg(quality: int = 65, max_width: int = 1280) -> bytes:
    """
    Captures the primary monitor screen and returns JPEG bytes.
    Optimized for low-bandwidth mobile viewing.
    """
    try:
        screenshot = ImageGrab.grab()
        # Downscale if larger than max_width to keep mobile loading instant
        if screenshot.width > max_width:
            ratio = max_width / float(screenshot.width)
            new_height = int(float(screenshot.height) * ratio)
            screenshot = screenshot.resize((max_width, new_height))
            
        # Convert RGBA to RGB if needed
        if screenshot.mode != "RGB":
            screenshot = screenshot.convert("RGB")
            
        buffer = io.BytesIO()
        screenshot.save(buffer, format="JPEG", quality=quality, optimize=True)
        return buffer.getvalue()
    except Exception as e:
        logger.error(f"Error capturing screen: {e}")
        # Return a simple fallback 1x1 image or raise
        raise e
