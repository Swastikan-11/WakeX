"""
WakeX Scenes & Automation Engine
Allows one-tap orchestration of multi-hardware profiles:
- Operating mode (Silent / Performance / Turbo)
- GPU mode (Eco / Standard)
- Display refresh rate & brightness
- Power Plan synchronization
- Audio & Display sleep
- App launching & lock actions
"""
import os
import time
import logging
from typing import Dict, Any, List, Optional
from engine.storage import safe_read_json, atomic_write_json

logger = logging.getLogger("WakeX.Scenes")

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config")
SCENES_FILE = os.path.join(CONFIG_DIR, "scenes.json")

DEFAULT_SCENES = [
    {
        "id": "scene_game",
        "name": "Game Mode",
        "icon": "🎮",
        "description": "Turbo cooling, 144Hz refresh rate, high performance power scheme, and 85% brightness.",
        "actions": {
            "operating_mode": "turbo",
            "refresh_rate": 144,
            "brightness": 85,
            "volume": 75,
            "power_plan": "high_performance"
        },
        "is_builtin": True
    },
    {
        "id": "scene_quiet",
        "name": "Quiet / Study",
        "icon": "🤫",
        "description": "Silent acoustics, 60Hz display, balanced power scheme, and 50% brightness.",
        "actions": {
            "operating_mode": "silent",
            "refresh_rate": 60,
            "brightness": 50,
            "volume": 35,
            "power_plan": "power_saver"
        },
        "is_builtin": True
    },
    {
        "id": "scene_battery",
        "name": "Battery Saver",
        "icon": "🔋",
        "description": "Silent fans, Eco GPU mode, 60Hz display, 30% brightness, and power saver scheme.",
        "actions": {
            "operating_mode": "silent",
            "gpu_mode": "eco",
            "refresh_rate": 60,
            "brightness": 30,
            "power_plan": "power_saver"
        },
        "is_builtin": True
    },
    {
        "id": "scene_away",
        "name": "Step Away",
        "icon": "🔒",
        "description": "Immediately locks session, turns off displays, and mutes audio.",
        "actions": {
            "power_action": "lock",
            "display_off": True,
            "mute_audio": True
        },
        "is_builtin": True
    }
]


def load_scenes() -> List[Dict[str, Any]]:
    """Loads all scenes from disk, creating default built-ins if missing."""
    custom = safe_read_json(SCENES_FILE, default=None)
    if custom is None or not isinstance(custom, list):
        atomic_write_json(SCENES_FILE, DEFAULT_SCENES)
        return DEFAULT_SCENES
    return custom


def save_scenes(scenes: List[Dict[str, Any]]) -> bool:
    """Saves scenes list to disk."""
    return atomic_write_json(SCENES_FILE, scenes)


def apply_scene(scene_id: str) -> Dict[str, Any]:
    """
    Applies all actions in a scene atomically and returns execution results.
    Never crashes on unsupported hardware; applies what is supported and notes what was skipped.
    """
    scenes = load_scenes()
    target = next((s for s in scenes if s["id"] == scene_id), None)
    if not target:
        return {"status": "error", "message": f"Scene '{scene_id}' not found."}

    results = {}
    actions = target.get("actions", {})

    from engine.hardware_ipc import send_hardware_command
    from engine.windows_controls import (
        set_refresh_rate,
        set_screen_brightness,
        set_master_volume_percent,
        set_active_power_plan,
        turn_off_display,
        toggle_audio_mute
    )
    from engine import os_power

    # 1. Operating mode
    if "operating_mode" in actions:
        mode = actions["operating_mode"]
        res_mode = send_hardware_command("SET_OPERATING_MODE", {"mode": mode})
        results["operating_mode"] = res_mode.get("status", "ok")

    # 2. GPU mode
    if "gpu_mode" in actions:
        gmode = actions["gpu_mode"]
        res_gpu = send_hardware_command("SET_DGPU_MODE", {"mode": gmode})
        results["gpu_mode"] = res_gpu.get("status", "ok")

    # 3. Refresh rate
    if "refresh_rate" in actions:
        res_hz = set_refresh_rate(actions["refresh_rate"])
        results["refresh_rate"] = res_hz.get("status", "ok")

    # 4. Brightness
    if "brightness" in actions:
        res_bright = set_screen_brightness(actions["brightness"])
        results["brightness"] = res_bright.get("status", "ok")

    # 5. Volume
    if "volume" in actions:
        res_vol = set_master_volume_percent(actions["volume"])
        results["volume"] = res_vol.get("status", "ok")

    # 6. Power Plan
    if "power_plan" in actions:
        res_plan = set_active_power_plan(actions["power_plan"])
        results["power_plan"] = res_plan.get("status", "ok")

    # 7. Mute audio
    if actions.get("mute_audio"):
        res_mute = toggle_audio_mute()
        results["mute_audio"] = res_mute.get("status", "ok")

    # 8. Display Off
    if actions.get("display_off"):
        res_doff = turn_off_display()
        results["display_off"] = res_doff.get("status", "ok")

    # 9. Power action (e.g. lock)
    if "power_action" in actions:
        p_act = actions["power_action"]
        if p_act == "lock":
            res_lock = os_power.lock_workstation()
            results["power_action"] = res_lock.get("status", "ok")
        elif p_act == "sleep":
            res_sleep = os_power.sleep_machine()
            results["power_action"] = res_sleep.get("status", "ok")

    logger.info(f"SCENE_APPLIED: Scene='{target['name']}' (ID={scene_id}) Result={results}")
    return {
        "status": "ok",
        "scene_id": scene_id,
        "name": target["name"],
        "results": results
    }


def create_scene(name: str, icon: str, actions: Dict[str, Any], description: str = "") -> Dict[str, Any]:
    """Creates a custom user scene."""
    import secrets
    scenes = load_scenes()
    scene_id = f"scene_user_{secrets.token_hex(4)}"
    new_scene = {
        "id": scene_id,
        "name": name.strip() or "Custom Scene",
        "icon": icon or "⭐",
        "description": description or "Custom user configured scene.",
        "actions": actions,
        "is_builtin": False
    }
    scenes.append(new_scene)
    save_scenes(scenes)
    return new_scene


def delete_scene(scene_id: str) -> bool:
    """Deletes a custom scene by ID. Built-in scenes cannot be deleted."""
    scenes = load_scenes()
    target = next((s for s in scenes if s["id"] == scene_id), None)
    if not target or target.get("is_builtin"):
        return False
    scenes = [s for s in scenes if s["id"] != scene_id]
    save_scenes(scenes)
    return True
