"""
AetherCommand Workspace & Application Orchestrator
Enumerate Start Menu apps, launch desktop software & URLs, and manage scheduled workspaces.
"""
import os
import sys
import json
import time
import logging
import datetime
import webbrowser
import subprocess
from typing import List, Dict, Any, Optional
from engine.storage import safe_read_json, atomic_write_json

logger = logging.getLogger("AetherCommand.Workspace")

if getattr(sys, 'frozen', False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

CONFIG_PATH = os.path.join(APP_DIR, "config", "workspaces.json")

# In-memory cache for installed Start Menu applications
_INSTALLED_APPS_CACHE: List[Dict[str, str]] = []
_CACHE_TIMESTAMP: float = 0.0
CACHE_TTL_SECONDS: float = 300.0  # 5 minutes cache

def get_installed_apps(force_refresh: bool = False) -> List[Dict[str, str]]:
    """
    Scans the system for installed applications.
    On Windows: Uses PowerShell `Get-StartApps` to retrieve all Start Menu apps & AppIDs.
    On Linux: Scans /usr/share/applications and ~/.local/share/applications for .desktop entries.
    """
    global _INSTALLED_APPS_CACHE, _CACHE_TIMESTAMP
    now = time.time()
    if not force_refresh and _INSTALLED_APPS_CACHE and (now - _CACHE_TIMESTAMP < CACHE_TTL_SECONDS):
        return _INSTALLED_APPS_CACHE

    apps: List[Dict[str, str]] = []

    if sys.platform == "win32":
        try:
            # PowerShell Get-StartApps returns both packaged UWP apps and Win32 Start Menu shortcuts
            ps_cmd = "Get-StartApps | Select-Object Name, AppID | ConvertTo-Json -Compress"
            res = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                encoding="utf-8",
                timeout=12
            )
            if res.returncode == 0 and res.stdout.strip():
                raw = json.loads(res.stdout)
                if isinstance(raw, dict):
                    raw = [raw]
                
                seen_names = set()
                for item in raw:
                    name = str(item.get("Name", "")).strip()
                    app_id = str(item.get("AppID", "")).strip()
                    if name and app_id:
                        # Clean up duplicate names or system entries
                        key = (name.lower(), app_id.lower())
                        if key not in seen_names:
                            seen_names.add(key)
                            apps.append({
                                "name": name,
                                "app_id": app_id
                            })
        except Exception as e:
            logger.error(f"Failed scanning Windows StartApps: {e}")

    else:
        # Linux fallback: scan .desktop files in standard XDG application directories
        search_dirs = [
            "/usr/share/applications",
            "/usr/local/share/applications",
            os.path.expanduser("~/.local/share/applications")
        ]
        seen_names = set()
        for sdir in search_dirs:
            if not os.path.exists(sdir):
                continue
            for root, _, files in os.walk(sdir):
                for file in files:
                    if file.endswith(".desktop"):
                        filepath = os.path.join(root, file)
                        try:
                            name = None
                            exec_cmd = None
                            with open(filepath, "r", encoding="utf-8", errors="ignore") as df:
                                for line in df:
                                    line = line.strip()
                                    if line.startswith("Name=") and not name:
                                        name = line.split("=", 1)[1].strip()
                                    elif line.startswith("Exec=") and not exec_cmd:
                                        exec_cmd = line.split("=", 1)[1].strip()
                                    if name and exec_cmd:
                                        break
                            if name and name not in seen_names:
                                seen_names.add(name)
                                apps.append({
                                    "name": name,
                                    "app_id": file[:-8] if file.endswith(".desktop") else name
                                })
                        except Exception:
                            continue

    # Sort apps alphabetically by Name
    apps.sort(key=lambda x: x["name"].lower())
    _INSTALLED_APPS_CACHE = apps
    _CACHE_TIMESTAMP = now
    logger.info(f"Loaded {len(apps)} installed Start Menu applications.")
    return apps

def launch_single_app(app_id_or_path: str) -> bool:
    """
    Launches an application by AppID, executable path, or URI.
    Works universally across Windows (Win32 & UWP) and Linux.
    """
    if not app_id_or_path or not app_id_or_path.strip():
        return False
        
    target = app_id_or_path.strip()

    import urllib.parse
    # 1. If it's a URL/Web address
    if target.startswith("http://") or target.startswith("https://"):
        try:
            parsed = urllib.parse.urlsplit(target)
            if parsed.scheme in ("http", "https"):
                webbrowser.open(target)
                return True
        except Exception as e:
            logger.error(f"Failed opening URL {target}: {e}")
            return False

    # Block dangerous shell injection characters in AppIDs / targets
    dangerous_chars = ["&", "|", ";", "$", "`", "<", ">", "\n", "\r"]
    if any(ch in target for ch in dangerous_chars):
        logger.warning(f"Blocked launch of suspicious target containing shell metacharacters: '{target}'")
        return False

    if sys.platform == "win32":
        # 1. If target is an existing executable file path
        if os.path.exists(target) and os.path.isfile(target):
            try:
                os.startfile(target)
                return True
            except Exception as e:
                logger.warning(f"os.startfile failed for '{target}': {e}, trying subprocess without shell")
                try:
                    subprocess.Popen([target])
                    return True
                except Exception as ex:
                    logger.error(f"Failed launching binary '{target}': {ex}")

        # 2. If target is a Start Menu AppID (UWP package, AppFolder link, or special GUID)
        try:
            appsfolder_target = f"shell:AppsFolder\\{target}"
            os.startfile(appsfolder_target)
            return True
        except Exception as e1:
            logger.debug(f"os.startfile shell:AppsFolder failed for '{target}': {e1}. Trying powershell Start-Process.")
            try:
                ps_cmd = "Start-Process"
                res = subprocess.run(
                    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd, f"shell:AppsFolder\\{target}"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if res.returncode == 0:
                    return True
            except Exception as e2:
                logger.debug(f"PowerShell Start-Process failed: {e2}")

        # 3. Fallback: try executing directly as safe single-binary command
        try:
            subprocess.Popen([target])
            return True
        except Exception as e3:
            logger.error(f"All launch attempts failed for '{target}': {e3}")
            return False

    else:
        # Linux launch
        try:
            # Try gtk-launch first if it's a desktop app id
            res = subprocess.run(["gtk-launch", target], capture_output=True, timeout=5)
            if res.returncode == 0:
                return True
        except Exception:
            pass
        try:
            import shlex
            cmd = shlex.split(target) if isinstance(target, str) else [target]
            subprocess.Popen(cmd)
            return True
        except Exception as e:
            logger.error(f"Linux launch error for '{target}': {e}")
            return False

def load_workspaces() -> Dict[str, Any]:
    """Reads all configured workspace profiles with crash resilience."""
    data = safe_read_json(CONFIG_PATH, default={"active_profile": "work_shift", "profiles": []})
    return data if isinstance(data, dict) else {"active_profile": "work_shift", "profiles": []}

def save_workspaces(data: Dict[str, Any]) -> bool:
    """Saves updated workspace profiles atomically."""
    return atomic_write_json(CONFIG_PATH, data)

def save_or_update_profile(profile_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Creates or updates a single workspace profile.
    Generates a unique ID if not provided.
    """
    data = load_workspaces()
    profiles = data.get("profiles", [])

    p_id = profile_data.get("id")
    if not p_id:
        # Generate slug from name
        name = profile_data.get("name", "workspace").strip().lower()
        slug = "".join(c if c.isalnum() else "_" for c in name).strip("_")
        p_id = f"{slug}_{int(time.time())}"
        profile_data["id"] = p_id

    # Format applications: list of {name, app_id}
    apps = profile_data.get("applications", [])
    clean_apps = []
    for item in apps:
        if isinstance(item, dict):
            clean_apps.append({
                "name": item.get("name", item.get("app_id", "App")),
                "app_id": item.get("app_id", "")
            })
        elif isinstance(item, str) and item.strip():
            clean_apps.append({
                "name": os.path.basename(item) if ("\\" in item or "/" in item) else item,
                "app_id": item.strip()
            })
    profile_data["applications"] = clean_apps

    # Format URLs: list of strings
    raw_urls = profile_data.get("urls", [])
    clean_urls = []
    for u in raw_urls:
        if isinstance(u, str) and u.strip():
            target_u = u.strip()
            if not target_u.startswith("http://") and not target_u.startswith("https://"):
                target_u = "https://" + target_u
            clean_urls.append(target_u)
    profile_data["urls"] = clean_urls

    # Format Schedule: {enabled: bool, time: "HH:MM", days: [...]}
    sched = profile_data.get("schedule", {})
    if not isinstance(sched, dict):
        sched = {"enabled": False, "time": "09:00", "days": ["Mon", "Tue", "Wed", "Thu", "Fri"]}
    profile_data["schedule"] = {
        "enabled": bool(sched.get("enabled", False)),
        "time": str(sched.get("time", "09:00")).strip(),
        "days": list(sched.get("days", ["Mon", "Tue", "Wed", "Thu", "Fri"]))
    }

    # Find and update or append
    idx = next((i for i, p in enumerate(profiles) if p.get("id") == p_id), -1)
    if idx >= 0:
        # Preserve last_scheduled_run if existing
        if "last_scheduled_run" in profiles[idx] and "last_scheduled_run" not in profile_data:
            profile_data["last_scheduled_run"] = profiles[idx]["last_scheduled_run"]
        profiles[idx] = profile_data
    else:
        profiles.append(profile_data)

    data["profiles"] = profiles
    save_workspaces(data)
    return profile_data

def delete_profile(profile_id: str) -> bool:
    """Deletes a workspace profile by ID."""
    data = load_workspaces()
    profiles = data.get("profiles", [])
    original_len = len(profiles)
    profiles = [p for p in profiles if p.get("id") != profile_id]
    if len(profiles) == original_len:
        return False
    data["profiles"] = profiles
    if data.get("active_profile") == profile_id and profiles:
        data["active_profile"] = profiles[0].get("id", "")
    return save_workspaces(data)

def launch_workspace(profile_id: str) -> Dict[str, Any]:
    """
    Executes a workspace:
    1. Opens configured URLs in the default browser.
    2. Launches configured desktop software & Start Menu applications.
    """
    data = load_workspaces()
    profile = next((p for p in data.get("profiles", []) if p.get("id") == profile_id), None)
    
    if not profile:
        return {"status": "error", "message": f"Profile '{profile_id}' not found."}

    launched_urls: List[str] = []
    launched_apps: List[str] = []
    errors: List[str] = []

    # 1. Launch Browser & URLs
    urls = profile.get("urls", [])
    for idx, url in enumerate(urls):
        try:
            webbrowser.open(url, new=(1 if idx == 0 else 2))
            launched_urls.append(url)
        except Exception as ex:
            errors.append(f"Failed opening URL {url}: {ex}")

    # 2. Launch Desktop Applications
    apps = profile.get("applications", [])
    for app in apps:
        app_id = ""
        app_display = ""
        if isinstance(app, dict):
            app_id = app.get("app_id", "")
            app_display = app.get("name", app_id)
        elif isinstance(app, str):
            app_id = app.strip()
            app_display = os.path.basename(app_id) if ("\\" in app_id or "/" in app_id) else app_id

        if not app_id:
            continue

        success = launch_single_app(app_id)
        if success:
            launched_apps.append(app_display)
        else:
            errors.append(f"Could not launch: {app_display}")

    # Update active profile
    data["active_profile"] = profile_id
    save_workspaces(data)

    return {
        "status": "success",
        "profile_name": profile.get("name", profile_id),
        "launched_urls": launched_urls,
        "launched_apps": launched_apps,
        "errors": errors
    }

def check_and_run_scheduled_workspaces() -> List[Dict[str, Any]]:
    """
    Evaluates current time against configured workspace schedules.
    If a workspace's schedule matches current HH:MM and day of the week,
    and has not already run within this minute, triggers `launch_workspace`.
    """
    now = datetime.datetime.now()
    cur_time = now.strftime("%H:%M")
    cur_day = now.strftime("%a")  # 'Mon', 'Tue', 'Wed', etc.
    cur_stamp = now.strftime("%Y-%m-%d %H:%M")

    data = load_workspaces()
    profiles = data.get("profiles", [])
    executed: List[Dict[str, Any]] = []
    updated = False

    for profile in profiles:
        sched = profile.get("schedule", {})
        if not sched.get("enabled"):
            continue

        sched_time = sched.get("time", "").strip()
        sched_days = sched.get("days", [])

        # Match time (HH:MM) and weekday
        if sched_time == cur_time and cur_day in sched_days:
            # Check if already triggered this minute
            if profile.get("last_scheduled_run") != cur_stamp:
                logger.info(f"Triggering scheduled workspace '{profile.get('name')}' at {cur_stamp}")
                profile["last_scheduled_run"] = cur_stamp
                updated = True
                
                # Launch workspace
                result = launch_workspace(profile["id"])
                executed.append(result)

    if updated:
        save_workspaces(data)

    return executed
