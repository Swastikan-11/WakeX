"""
WakeX Multi-Device Management & Target-Isolated Power Routing
Enforces absolute device isolation: commands for Device B never execute on Host Device A.
"""
import os
import sys
import json
import socket
import logging
import time
import secrets
import hashlib
import hmac
import urllib.request
import urllib.error
from engine import os_power
from engine.storage import safe_read_json, atomic_write_json

logger = logging.getLogger("WakeX.Devices")

if getattr(sys, 'frozen', False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

CONFIG_PATH = os.path.join(APP_DIR, "config", "devices.json")

def get_host_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def load_devices() -> list:
    """Loads all paired devices with resilient fallback to backup."""
    if not os.path.exists(CONFIG_PATH):
        # Default device is this host machine
        cur_ip = get_host_ip()
        default_devices = [
            {
                "id": "dev_host_primary",
                "name": "ASUS TUF Gaming F15",
                "type": "laptop",
                "ip": cur_ip if cur_ip != "127.0.0.1" else "192.168.1.104",
                "mac": "00-11-22-33-44-55",
                "port": 8000,
                "is_current": True,
                "status": "online",
                "auth_token": ""
            }
        ]
        save_devices(default_devices)
        return default_devices

    try:
        devs = safe_read_json(CONFIG_PATH, default=[])
        if not isinstance(devs, list):
            devs = []
        cur_ip = get_host_ip()
        modified = False
        for d in devs:
            if d.get("is_current") and cur_ip != "127.0.0.1" and d.get("ip") != cur_ip:
                d["ip"] = cur_ip
                modified = True
        if modified:
            save_devices(devs)
        return devs
    except Exception as e:
        logger.error(f"Error loading devices: {e}")
        return []

def save_devices(devices: list) -> bool:
    """Saves device list atomically with crash protection."""
    return atomic_write_json(CONFIG_PATH, devices)

def add_device(name: str, ip: str, mac: str, port: int = 8001, dev_type: str = "pc", auth_token: str = "") -> dict:
    """Pairs a new device with optional auth token for agent communication."""
    devices = load_devices()
    dev_id = f"dev_{int(len(devices) + 1)}_{name.lower().replace(' ', '_')[:10]}"
    
    clean_mac = mac.replace(":", "-").replace(".", "-").upper().strip()
    new_device = {
        "id": dev_id,
        "name": name.strip(),
        "type": dev_type,
        "ip": ip.strip(),
        "mac": clean_mac,
        "port": port,
        "is_current": False,
        "status": "unknown",
        "auth_token": auth_token.strip()
    }
    devices.append(new_device)
    save_devices(devices)
    return {"status": "success", "device": new_device}

def rename_device(device_id: str, new_name: str) -> dict:
    """Renames an existing paired device."""
    devices = load_devices()
    found = False
    for dev in devices:
        if dev["id"] == device_id:
            dev["name"] = new_name.strip()
            found = True
            break
    
    if found:
        save_devices(devices)
        return {"status": "success", "message": f"Device renamed to '{new_name}'"}
    return {"status": "error", "message": "Device not found"}

def update_device(device_id: str, name: str, ip: str, mac: str, port: int, auth_token: str = "") -> dict:
    """Updates device details."""
    devices = load_devices()
    clean_mac = mac.replace(":", "-").replace(".", "-").upper().strip()
    for dev in devices:
        if dev["id"] == device_id:
            dev["name"] = name.strip()
            dev["ip"] = ip.strip()
            dev["mac"] = clean_mac
            dev["port"] = port
            if auth_token:
                dev["auth_token"] = auth_token.strip()
            save_devices(devices)
            return {"status": "success", "message": "Device updated successfully"}
    return {"status": "error", "message": "Device not found"}

def delete_device(device_id: str) -> dict:
    """Unpairs / deletes a device."""
    devices = load_devices()
    target = next((d for d in devices if d["id"] == device_id), None)
    if not target:
        return {"status": "error", "message": "Device not found"}
    if target.get("is_current"):
        return {"status": "error", "message": "Cannot delete the host computer"}

    updated = [d for d in devices if d["id"] != device_id]
    save_devices(updated)
    return {"status": "success", "message": "Device removed"}

def get_subnet_broadcast() -> str:
    """Calculates active /24 subnet broadcast address from local host IP."""
    ip = get_host_ip()
    if ip and ip != "127.0.0.1":
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.255"
    return "192.168.1.255"

def send_wake_on_lan(mac_address, broadcast_ip: str = "255.255.255.255", port: int = 9) -> dict:
    """Constructs and broadcasts Wake-on-LAN Magic Packets to single or multiple MACs across broadcast domains."""
    mac_list = [mac_address] if isinstance(mac_address, str) else list(mac_address)
    sent_macs = []
    
    # Broadcast targets: global broadcast and local subnet broadcasts
    dynamic_sub = get_subnet_broadcast()
    broadcast_targets = list(dict.fromkeys(["255.255.255.255", dynamic_sub, "192.168.1.255", "192.168.1.255", broadcast_ip]))

    for mac in mac_list:
        if not mac or not isinstance(mac, str):
            continue
        clean_mac = mac.replace(":", "").replace("-", "").replace(".", "").upper().strip()
        if len(clean_mac) != 12:
            continue
        try:
            mac_bytes = bytes.fromhex(clean_mac)
            magic_packet = b'\xff' * 6 + mac_bytes * 16

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                for b_ip in broadcast_targets:
                    for p in [9, 7, 0]:
                        try:
                            sock.sendto(magic_packet, (b_ip, p))
                        except Exception:
                            pass
            sent_macs.append(clean_mac)
            logger.info(f"Broadcasted Wake-on-LAN Magic Packet to {clean_mac} across {broadcast_targets}")
        except Exception as e:
            logger.error(f"Failed sending WoL to {mac}: {e}")

    if sent_macs:
        return {
            "status": "success",
            "message": f"⚡ Turn On / Wake signal sent to MAC(s): {', '.join(sent_macs)} across subnets {broadcast_targets} on ports 9, 7, and 0!",
            "macs_sent": sent_macs,
            "broadcast_targets": broadcast_targets,
            "ports": [9, 7, 0]
        }
    return {
        "status": "error",
        "code": "INVALID_MAC",
        "message": f"No valid 12-character MAC address found in: '{mac_address}'. Please register your network card MAC address."
    }


def check_device_online(ip: str, port: int = 8000, timeout: float = 0.5) -> bool:
    """Checks if a device is online via TCP connection or ping."""
    if not ip or not any(c.isdigit() for c in ip):
        return False
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        # Fallback to single quick ping
        try:
            if os_power.get_os_type() == "windows":
                res = subprocess.run(["ping", "-n", "1", "-w", "400", ip], capture_output=True)
            else:
                res = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True)
            return res.returncode == 0
        except Exception:
            return False

# ================= CRITICAL MULTI-DEVICE TARGET ROUTING =================

def dispatch_power_command(target_device_id: str, action: str, delay_seconds: int = 0) -> dict:
    """
    Guarantees target isolation:
    - If target_device_id is the Host: executes on Host OS.
    - If target_device_id is a Remote Device: forwards to Remote Device Agent.
      The Host OS is NEVER touched.
    """
    devices = load_devices()
    target = next((d for d in devices if d["id"] == target_device_id), None)
    if not target:
        return {
            "status": "error",
            "code": "DEVICE_NOT_FOUND",
            "message": f"Target device '{target_device_id}' does not exist."
        }

    # Case 1: Target IS the local Host machine
    if target.get("is_current"):
        logger.info(f"Target '{target_device_id}' is the local Host. Executing '{action}' locally.")
        if action == "shutdown":
            return os_power.execute_shutdown(delay_seconds)
        elif action == "restart":
            return os_power.execute_restart(delay_seconds)
        elif action == "sleep":
            return os_power.execute_sleep()
        elif action == "hibernate":
            return os_power.execute_hibernate()
        elif action == "lock":
            return os_power.execute_lock()
        elif action == "unlock":
            return os_power.execute_unlock()
        elif action == "abort":
            return os_power.abort_shutdown()
        else:
            return {"status": "error", "message": f"Unknown action '{action}'"}


    # Case 2: Target is a REMOTE machine (Device B, C, etc.)
    # SAFETY RULE: The Host machine MUST NEVER execute local power commands!
    ip = target.get("ip")
    port = target.get("port", 8001)
    token = target.get("auth_token", "")

    if not ip or not any(c.isdigit() for c in ip):
        return {
            "status": "error",
            "code": "INVALID_IP",
            "message": f"Target device '{target['name']}' has an invalid IP address ('{ip}'). Remote command aborted. Host was not modified."
        }

    logger.info(f"Target '{target_device_id}' is REMOTE ({ip}:{port}). Dispatching command to remote agent...")

    agent_url = f"http://{ip}:{port}/api/agent/power"
    payload_str = json.dumps({
        "action": action,
        "target_device_id": target_device_id
    })
    payload = payload_str.encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "X-WakeX-Device-Token": token
    }

    if token:
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        body_sha256 = hashlib.sha256(payload).hexdigest()
        sign_string = f"POST:/api/agent/power:{timestamp}:{nonce}:{body_sha256}"
        signature = hmac.new(token.encode("utf-8"), sign_string.encode("utf-8"), hashlib.sha256).hexdigest()
        headers["X-WakeX-Timestamp"] = timestamp
        headers["X-WakeX-Nonce"] = nonce
        headers["X-WakeX-Signature"] = signature

    req = urllib.request.Request(
        agent_url,
        data=payload,
        headers=headers,
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=3.5) as response:
            res_body = json.loads(response.read().decode("utf-8"))
            return {
                "status": "success",
                "target_device": target["name"],
                "target_device_id": target_device_id,
                "remote_response": res_body
            }
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        return {
            "status": "error",
            "code": f"HTTP_{e.code}",
            "message": f"Remote agent on '{target['name']}' error: {err_msg}"
        }
    except Exception as e:
        logger.warning(f"Could not reach remote agent on {ip}:{port}: {e}")
        return {
            "status": "error",
            "code": "DEVICE_UNREACHABLE",
            "message": f"Remote device '{target['name']}' ({ip}:{port}) is offline or WakeX Agent is not running on it. Host system was NOT modified."
        }
