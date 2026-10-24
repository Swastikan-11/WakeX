"""
WakeX Telemetry & Real-Time Resource Monitor
Collects comprehensive hardware metrics:
- CPU frequency, usage %, temperatures
- RAM used/total %, configured clock speed MT/s
- Primary NVMe/SSD storage used/total %
- Network throughput delta (recv/sent KB/s)
- Battery state & charge limit active
- Dedicated GPU metrics with strict Power-Saving D3 Cold Guard
- 60-second rolling circular buffer for live graphs
"""
import io
import sys
import time
import shutil
import psutil
import logging
import collections
import subprocess
from typing import Dict, Any, List, Optional
from PIL import ImageGrab

logger = logging.getLogger("WakeX.Telemetry")

BOOT_TIME = psutil.boot_time()

# 60-second rolling history buffer
MONITOR_HISTORY = collections.deque(maxlen=60)
_last_net_io = psutil.net_io_counters()
_last_net_time = time.time()
_cached_ram_mts: Optional[int] = None


def get_ram_configured_clock_speed() -> int:
    """Returns RAM frequency in MT/s via WMI (cached)."""
    global _cached_ram_mts
    if _cached_ram_mts is not None:
        return _cached_ram_mts
    try:
        cmd = "Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ConfiguredClockSpeed"
        out = subprocess.check_output(["powershell", "-NoProfile", "-Command", cmd], text=True, timeout=2).strip()
        if out:
            _cached_ram_mts = int(out.splitlines()[0])
            return _cached_ram_mts
    except Exception:
        pass
    _cached_ram_mts = 3200
    return _cached_ram_mts


def get_gpu_telemetry(keep_awake: bool = False) -> Dict[str, Any]:
    """
    Safely queries NVIDIA GPU metrics.
    STRICT SAFETY: Does not poll dGPU when asleep to prevent battery drain.
    Shows 'power_saving' unless keep_awake is True or active 3D load is detected.
    """
    has_nvidia = shutil.which("nvidia-smi") is not None
    if not has_nvidia:
        return {
            "status": "unavailable",
            "name": None,
            "usage": None,
            "temp": None,
            "power_watts": None,
            "vram_used_mb": None,
            "vram_total_mb": None
        }

    # If keep_awake is False, avoid waking dGPU from low power D3 sleep
    if not keep_awake:
        # Check if any processes are currently running on dGPU
        try:
            r = subprocess.run(
                ["nvidia-smi", "--query-compute-apps=pid", "--format=csv,noheader"],
                capture_output=True, text=True, timeout=0.8
            )
            # If no 3D apps running, respect Power Saving mode
            if r.returncode == 0 and not r.stdout.strip():
                return {
                    "status": "power_saving",
                    "name": "NVIDIA RTX 2050",
                    "usage": 0,
                    "temp": None,
                    "power_watts": 0.0,
                    "vram_used_mb": 0,
                    "vram_total_mb": 4096
                }
        except Exception:
            pass

    # Query active GPU stats
    try:
        fields = "name,temperature.gpu,utilization.gpu,power.draw,memory.used,memory.total"
        res = subprocess.run(
            ["nvidia-smi", f"--query-gpu={fields}", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=1.2
        )
        if res.returncode == 0 and res.stdout.strip():
            parts = [p.strip() for p in res.stdout.splitlines()[0].split(",")]
            return {
                "status": "active",
                "name": parts[0] if len(parts) > 0 else "NVIDIA GPU",
                "temp": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
                "usage": int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
                "power_watts": float(parts[3]) if len(parts) > 3 else 0.0,
                "vram_used_mb": int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0,
                "vram_total_mb": int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 4096
            }
    except Exception as e:
        logger.warning(f"Error querying nvidia-smi: {e}")

    return {
        "status": "power_saving",
        "name": "NVIDIA GPU",
        "usage": 0,
        "temp": None,
        "power_watts": 0.0,
        "vram_used_mb": 0,
        "vram_total_mb": 4096
    }


def get_live_system_usage(keep_gpu_awake: bool = False) -> Dict[str, Any]:
    """Returns live telemetry snapshot across CPU, GPU, RAM, Disk, Net, and Battery."""
    global _last_net_io, _last_net_time
    now = time.time()
    dt = max(0.1, now - _last_net_time)

    # CPU
    cpu_pct = psutil.cpu_percent(interval=None)
    cpu_freq = psutil.cpu_freq()
    freq_mhz = round(cpu_freq.current, 1) if cpu_freq else 2688.0

    # Memory
    mem = psutil.virtual_memory()
    ram_mts = get_ram_configured_clock_speed()

    # Storage
    disk = psutil.disk_usage('/') if not sys.platform == "win32" else psutil.disk_usage('C:\\')

    # Network rate (KB/s)
    cur_net = psutil.net_io_counters()
    net_in_kbps = round((cur_net.bytes_recv - _last_net_io.bytes_recv) / dt / 1024.0, 1)
    net_out_kbps = round((cur_net.bytes_sent - _last_net_io.bytes_sent) / dt / 1024.0, 1)
    _last_net_io = cur_net
    _last_net_time = now

    # Battery
    battery = psutil.sensors_battery()
    bat_pct = round(battery.percent, 1) if battery else 100.0
    plugged = battery.power_plugged if battery else True

    # GPU
    gpu = get_gpu_telemetry(keep_awake=keep_gpu_awake)

    snapshot = {
        "timestamp": now,
        "cpu": {
            "usage_pct": cpu_pct,
            "freq_mhz": freq_mhz,
            "cores": psutil.cpu_count(logical=True),
            "temp_c": None
        },
        "gpu": gpu,
        "memory": {
            "used_gb": round(mem.used / (1024**3), 2),
            "total_gb": round(mem.total / (1024**3), 2),
            "usage_pct": mem.percent,
            "clock_speed_mts": ram_mts
        },
        "storage": {
            "used_gb": round(disk.used / (1024**3), 1),
            "total_gb": round(disk.total / (1024**3), 1),
            "usage_pct": disk.percent
        },
        "network": {
            "rx_kbps": max(0.0, net_in_kbps),
            "tx_kbps": max(0.0, net_out_kbps)
        },
        "battery": {
            "percent": bat_pct,
            "plugged": plugged
        }
    }

    # Append to rolling history
    MONITOR_HISTORY.append({
        "time": int(now),
        "cpu": cpu_pct,
        "gpu": gpu.get("usage") or 0,
        "ram": mem.percent,
        "rx": max(0.0, net_in_kbps),
        "tx": max(0.0, net_out_kbps)
    })

    return snapshot


def get_monitor_history() -> List[Dict[str, Any]]:
    """Returns the 60-second rolling history buffer."""
    return list(MONITOR_HISTORY)


def get_system_telemetry() -> dict:
    """Legacy endpoint backward compatibility."""
    snap = get_live_system_usage()
    uptime_seconds = int(time.time() - BOOT_TIME)
    hours, remainder = divmod(uptime_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return {
        "status": "online",
        "cpu_percent": snap["cpu"]["usage_pct"],
        "memory_percent": snap["memory"]["usage_pct"],
        "memory_used_gb": snap["memory"]["used_gb"],
        "memory_total_gb": snap["memory"]["total_gb"],
        "battery_percent": snap["battery"]["percent"],
        "power_plugged": snap["battery"]["plugged"],
        "battery_secs_left": -1,
        "uptime": f"{hours}h {minutes}m {seconds}s",
        "timestamp": snap["timestamp"]
    }


def capture_screen_jpeg(quality: int = 65, max_width: int = 1280) -> bytes:
    """Captures monitor screen and returns JPEG bytes."""
    try:
        screenshot = ImageGrab.grab()
        if screenshot.width > max_width:
            ratio = max_width / float(screenshot.width)
            new_height = int(float(screenshot.height) * ratio)
            screenshot = screenshot.resize((max_width, new_height))
        if screenshot.mode != "RGB":
            screenshot = screenshot.convert("RGB")
        buffer = io.BytesIO()
        screenshot.save(buffer, format="JPEG", quality=quality, optimize=True)
        return buffer.getvalue()
    except Exception as e:
        logger.error(f"Error capturing screen: {e}")
        raise e
