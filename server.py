"""
WakeX Server
FastAPI Web and REST API Server running locally on the PC.
Features Zero-Cloud Cryptographic Client Pairing, HMAC-SHA256 Request Verification,
Target-Isolated Multi-Device Power, UDP LAN Auto-Discovery, and Hardware WoL.
"""
import os
import sys
import hmac
import time
import json
import secrets
import hashlib
import asyncio
import logging
from contextlib import asynccontextmanager
from typing import List, Optional, Any, Dict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Response, Header, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from engine import telemetry, power, workspace, scheduler, devices, os_power, security, readiness
from engine.discovery import discovery_service
from engine.bot_assistant import bot_instance

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] WakeX.Server: %(message)s")
logger = logging.getLogger("WakeX.Server")

if getattr(sys, 'frozen', False):
    APP_DIR = os.path.dirname(sys.executable)
    BUNDLE_DIR = getattr(sys, '_MEIPASS', APP_DIR)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
    BUNDLE_DIR = APP_DIR

STATIC_DIR = os.path.join(APP_DIR, "static") if os.path.isdir(os.path.join(APP_DIR, "static")) else os.path.join(BUNDLE_DIR, "static")
SETTINGS_FILE = os.path.join(APP_DIR, "config", "settings.json")
APK_PATH = os.path.join(APP_DIR, "WakeX.apk") if os.path.exists(os.path.join(APP_DIR, "WakeX.apk")) else os.path.join(BUNDLE_DIR, "WakeX.apk")


# --- Lifespan Context Manager (Modern FastAPI Lifecycle) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start UDP LAN Discovery Service & Background Scheduler
    discovery_service.start()
    scheduler_task = asyncio.create_task(run_workspace_scheduler())
    logger.info("WakeX Hub initialized: LAN Discovery and Scheduler active.")
    try:
        yield
    finally:
        # Shutdown: Clean up background services
        scheduler_task.cancel()
        discovery_service.stop()
        logger.info("WakeX Hub stopped.")


async def run_workspace_scheduler():
    logger.info("24/7 Workspace auto-launch scheduler daemon active.")
    while True:
        try:
            executed = workspace.check_and_run_scheduled_workspaces()
            if executed:
                for ex in executed:
                    logger.info(f"Automatically launched scheduled workspace: {ex.get('profile_name')}")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Workspace scheduler check error: {e}")
        await asyncio.sleep(20)


app = FastAPI(title="WakeX Hub", version="3.0.0", lifespan=lifespan)


# --- Models ---
class PowerActionRequest(BaseModel):
    action: str  # 'shutdown', 'restart', 'sleep', 'hibernate', 'lock', 'unlock', 'abort'
    target_device_id: Optional[str] = None
    delay_seconds: Optional[int] = 0

class ClientPairRequest(BaseModel):
    pairing_code: Optional[str] = ""
    client_name: Optional[str] = "Mobile Device"
    client_id: Optional[str] = None

class PairExchangeRequest(BaseModel):
    client_id: str
    client_name: Optional[str] = "Mobile Device"
    client_public_key: str
    client_nonce: str

class PairAuthenticateRequest(BaseModel):
    session_id: str
    pairing_code: str
    client_proof: str

class BotMessageRequest(BaseModel):
    message: str

class ScheduleRequest(BaseModel):
    enabled: bool
    time: str
    days: List[str]

class PairDeviceRequest(BaseModel):
    name: str
    ip: str
    mac: str
    port: Optional[int] = 8001
    dev_type: Optional[str] = "pc"
    auth_token: Optional[str] = ""

class RenameDeviceRequest(BaseModel):
    new_name: str

class UpdateDeviceRequest(BaseModel):
    name: str
    ip: str
    mac: str
    port: int
    auth_token: Optional[str] = ""

class WorkspaceProfileRequest(BaseModel):
    id: Optional[str] = None
    name: str
    icon: Optional[str] = "briefcase"
    description: Optional[str] = ""
    browser: Optional[str] = "default"
    urls: List[str] = Field(default_factory=list)
    applications: List[Any] = Field(default_factory=list)
    schedule: Optional[Dict[str, Any]] = None


# --- Authentication & Pairing Endpoints ---

@app.get("/api/auth/status")
async def auth_status(request: Request):
    """Reports authentication and pairing status."""
    paired = security.get_paired_clients()
    client_ip = request.client.host if request.client else "unknown"
    is_local = client_ip in ("127.0.0.1", "::1", "localhost")
    return {
        "status": "ready",
        "is_local": is_local,
        "paired_clients_count": len(paired),
        "pairing_required": len(paired) > 0 and not is_local
    }


@app.get("/api/auth/local-token")
async def get_local_token(request: Request):
    """Issues ephemeral local session token strictly to host machine browser (127.0.0.1)."""
    client_ip = request.client.host if request.client else "unknown"
    if client_ip not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(status_code=403, detail="Local tokens only issued to host machine.")
    return {"token": security.LOCAL_SESSION_TOKEN}


@app.post("/api/auth/pairing-code")
async def create_pairing_code(_: dict = Depends(security.verify_authenticated_request)):
    """Generates a secure 6-digit one-time pairing code for pairing a new phone."""
    code = security.generate_pairing_code()
    return {
        "pairing_code": code,
        "validity_seconds": security.PAIRING_CODE_VALIDITY,
        "message": f"Enter code {code} in your WakeX phone app within 5 minutes."
    }


@app.post("/api/auth/pair/exchange")
async def pair_exchange_endpoint(req: PairExchangeRequest, request: Request):
    """
    Step 1: Ephemeral X25519 Diffie-Hellman Key Exchange.
    Establishes ECDH shared secret and derives client secret via HKDF without transmitting it.
    """
    client_ip = request.client.host if request.client else "unknown"
    security.check_rate_limit(client_ip)
    res = security.start_pairing_exchange(
        client_id=req.client_id,
        client_name=req.client_name or "Mobile Device",
        client_public_key_hex=req.client_public_key,
        client_nonce=req.client_nonce
    )
    return res


@app.post("/api/auth/pair/authenticate")
async def pair_authenticate_endpoint(req: PairAuthenticateRequest, request: Request):
    """
    Step 2: Mutual PIN authentication of the handshake transcript.
    Authenticates handshake, confirms derived secret, and enforces per-PIN rate limits.
    """
    client_ip = request.client.host if request.client else "unknown"
    success, data, err = security.authenticate_pairing_session(
        session_id=req.session_id,
        pairing_code=req.pairing_code,
        client_proof=req.client_proof,
        client_ip=client_ip
    )
    if not success:
        status_code = 429 if "revoked" in err or "locked out" in err else 401
        raise HTTPException(status_code=status_code, detail=err)
    return data


@app.post("/api/auth/pair")
async def pair_client_device(req: ClientPairRequest, request: Request):
    """Legacy pairing endpoint - informs client to use X25519 handshake."""
    raise HTTPException(
        status_code=400,
        detail="WakeX v2.4+ requires ephemeral X25519 key exchange (/api/auth/pair/exchange). Please update client."
    )


@app.get("/api/auth/paired-clients")
async def list_paired_clients(_: dict = Depends(security.verify_authenticated_request)):
    """Lists paired devices (names and IDs only, never secrets)."""
    paired = security.get_paired_clients()
    sanitized = []
    for cid, info in paired.items():
        sanitized.append({
            "client_id": cid,
            "name": info.get("name", "Unknown"),
            "created_at": info.get("created_at"),
            "last_seen": info.get("last_seen")
        })
    return sanitized


@app.delete("/api/auth/paired-clients/{client_id}")
async def revoke_paired_client(client_id: str, _: dict = Depends(security.verify_authenticated_request)):
    """Revokes access for a paired client."""
    success = security.unpair_client(client_id)
    if not success:
        raise HTTPException(status_code=404, detail="Client not found.")
    return {"status": "success", "message": f"Client '{client_id}' access revoked."}

@app.post("/api/auth/reset")
async def reset_auth_endpoint(_: dict = Depends(security.verify_authenticated_request)):
    """Resets all paired clients and security session caches."""
    security.reset_all_auth_state()
    return {"status": "reset", "message": "All paired devices, active sessions, and security caches have been reset."}


# --- Telemetry, Screen & Capabilities Endpoints ---

@app.get("/api/system/capabilities")
async def get_system_capabilities():
    """Reports actual OS power capabilities for the host machine."""
    return os_power.get_supported_capabilities()


@app.get("/api/system/readiness")
async def get_system_readiness():
    """Reports hardware Wake-on-LAN and WoWLAN readiness diagnostics."""
    return readiness.get_wol_readiness()


@app.post("/api/system/test-wol")
async def test_wol_packet(_: dict = Depends(security.verify_authenticated_request)):
    """Emits test Wake-on-LAN Magic Packets across all adapters and returns diagnostic delivery report."""
    devs = devices.load_devices()
    host_dev = next((d for d in devs if d.get("is_current")), None) or {}
    mac = host_dev.get("mac") or "00-11-22-33-44-55"
    eth_mac = host_dev.get("ethernet_mac") or mac
    wifi_mac = host_dev.get("wifi_mac") or mac
    all_macs = [m for m in [mac, eth_mac, wifi_mac] if m]
    unique_macs = list(dict.fromkeys(all_macs))
    res = devices.send_wake_on_lan(unique_macs)
    res["tested_macs"] = unique_macs
    res["primary_cold_wake_mac"] = f"{eth_mac} (Ethernet - 0W Cold Boot)"
    res["standby_wake_mac"] = f"{wifi_mac} (Wi-Fi - Sleep / Modern Standby S0ix)"
    return res


@app.get("/api/telemetry")
async def get_telemetry():
    return telemetry.get_system_telemetry()


@app.get("/api/screen")
async def get_screen(_: dict = Depends(security.verify_authenticated_request)):
    try:
        img_bytes = telemetry.capture_screen_jpeg(quality=70, max_width=1280)
        return Response(content=img_bytes, media_type="image/jpeg")
    except Exception as e:
        logger.error(f"Failed to capture screen: {e}")
        raise HTTPException(status_code=500, detail="Screen capture unavailable")


# --- CRITICAL MULTI-DEVICE POWER CONTROLS (TARGET ISOLATION + HMAC AUTH) ---

@app.post("/api/devices/{device_id}/power")
async def execute_device_power(
    device_id: str,
    req: PowerActionRequest,
    request: Request,
    auth_context: dict = Depends(security.verify_authenticated_request)
):
    """
    CRITICAL MULTI-DEVICE SAFETY:
    Executes a power command STRICTLY on target 'device_id'.
    - If device_id is a remote PC (Device B), Host Device A NEVER executes local power commands!
    - Enforces HMAC cryptographic verification and idempotency caching.
    """
    act = req.action.lower()
    if act == "cancel_shutdown":
        act = "abort"
    if act not in ["shutdown", "restart", "sleep", "hibernate", "lock", "unlock", "abort"]:
        raise HTTPException(status_code=400, detail=f"Unsupported power action '{act}'")

    # Granular permission check
    user_perm = auth_context.get("permission", "control").lower()
    user_val = security.PERMISSION_HIERARCHY.get(user_perm, 2)
    if act in ["shutdown", "restart", "hibernate"]:
        if user_val < security.PERMISSION_HIERARCHY["full"]:
            security.audit_logger.warning(
                f"Permission denied: Client '{auth_context.get('client_id')}' with '{user_perm}' privilege "
                f"attempted destructive power action '{act}'"
            )
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions: Action '{act}' requires 'full' privilege, but client has '{user_perm}'."
            )
    else:
        if user_val < security.PERMISSION_HIERARCHY["control"]:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions: Action '{act}' requires 'control' privilege, but client has '{user_perm}'."
            )

    # Idempotency check using request nonce
    nonce = request.headers.get("X-WakeX-Nonce") or f"{device_id}_{act}_{int(time.time() // 5)}"
    idempotent_key = f"{auth_context.get('client_id')}:{nonce}"
    cached = security.check_and_record_idempotency(idempotent_key)
    if cached:
        return cached

    res = devices.dispatch_power_command(device_id, act, req.delay_seconds or 0)
    if res.get("status") == "error":
        raise HTTPException(status_code=400, detail=res.get("message"))

    security.store_idempotent_result(idempotent_key, res)
    security.audit_logger.info(
        f"POWER_EXEC: Client={auth_context.get('client_id')} Target={device_id} Action={act} Status=OK"
    )
    return res


@app.post("/api/power")
async def execute_legacy_power(
    req: PowerActionRequest,
    request: Request,
    auth_context: dict = Depends(security.verify_authenticated_request)
):
    """
    Legacy power route: requires explicit target_device_id or falls back safely to host with auth.
    """
    target_id = req.target_device_id
    if not target_id:
        devs = devices.load_devices()
        host_dev = next((d for d in devs if d.get("is_current")), None) or {}
        target_id = host_dev["id"] if host_dev else "dev_host_primary"

    return await execute_device_power(target_id, req, request, auth_context)


# --- Multi-Device Management & Turn On (WoL) Endpoints ---

@app.get("/api/devices")
async def list_devices():
    devs = devices.load_devices()
    host_caps = os_power.get_supported_capabilities()
    for d in devs:
        if d.get("is_current"):
            d["status"] = "online"
            d["capabilities"] = host_caps
        else:
            is_up = devices.check_device_online(d.get("ip", ""), d.get("port", 8001), timeout=0.3)
            d["status"] = "online" if is_up else "offline"
            d["capabilities"] = {
                "os": d.get("type", "pc"),
                "shutdown": True,
                "restart": True,
                "sleep": True,
                "hibernate": True,
                "lock": True,
                "unlock": True,
                "wake_on_lan": bool(d.get("mac"))
            }
    return devs


@app.post("/api/devices/pair")
async def pair_secondary_pc(req: PairDeviceRequest, _: dict = Depends(security.verify_authenticated_request)):
    return devices.add_device(req.name, req.ip, req.mac, req.port or 8001, req.dev_type or "pc", req.auth_token or "")


@app.post("/api/devices/{device_id}/rename")
async def rename_device_endpoint(device_id: str, req: RenameDeviceRequest, _: dict = Depends(security.verify_authenticated_request)):
    res = devices.rename_device(device_id, req.new_name)
    if res.get("status") == "error":
        raise HTTPException(status_code=404, detail=res.get("message"))
    return res


@app.post("/api/devices/{device_id}/update")
async def update_device_endpoint(device_id: str, req: UpdateDeviceRequest, _: dict = Depends(security.verify_authenticated_request)):
    res = devices.update_device(device_id, req.name, req.ip, req.mac, req.port, req.auth_token or "")
    if res.get("status") == "error":
        raise HTTPException(status_code=404, detail=res.get("message"))
    return res


@app.delete("/api/devices/{device_id}")
async def delete_device_endpoint(device_id: str, _: dict = Depends(security.verify_authenticated_request)):
    res = devices.delete_device(device_id)
    if res.get("status") == "error":
        raise HTTPException(status_code=400, detail=res.get("message"))
    return res


@app.post("/api/devices/{device_id}/wake")
async def wake_device(device_id: str, _: dict = Depends(security.verify_authenticated_request)):
    devs = devices.load_devices()
    dev = next((d for d in devs if d["id"] == device_id), None)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")

    macs = []
    if dev.get("mac"): macs.append(dev.get("mac"))
    if dev.get("wifi_mac") and dev.get("wifi_mac") not in macs: macs.append(dev.get("wifi_mac"))
    if dev.get("ethernet_mac") and dev.get("ethernet_mac") not in macs: macs.append(dev.get("ethernet_mac"))

    if not macs:
        raise HTTPException(status_code=400, detail="Device has no MAC address configured")

    res = devices.send_wake_on_lan(macs)
    return res


# --- Installed Apps & Workspace Endpoints ---

@app.get("/api/apps/installed")
async def get_installed_apps(refresh: bool = False):
    """Enumerates all applications installed in the Windows Start Menu or Linux desktop."""
    return {"apps": workspace.get_installed_apps(force_refresh=refresh)}


@app.get("/api/workspaces")
async def get_workspaces():
    return workspace.load_workspaces()


@app.post("/api/workspaces/profile")
async def save_workspace_profile(req: WorkspaceProfileRequest, _: dict = Depends(security.verify_authenticated_request)):
    """Creates or updates a customized workspace profile with apps, URLs, and schedule."""
    data = req.model_dump() if hasattr(req, "model_dump") else req.dict()
    saved = workspace.save_or_update_profile(data)
    return {"status": "success", "profile": saved}


@app.delete("/api/workspaces/{profile_id}")
async def delete_workspace_profile(profile_id: str, _: dict = Depends(security.verify_authenticated_request)):
    """Deletes a workspace profile by ID."""
    success = workspace.delete_profile(profile_id)
    if not success:
        raise HTTPException(status_code=404, detail="Workspace profile not found")
    return {"status": "success", "message": f"Profile '{profile_id}' deleted."}


@app.post("/api/workspaces/launch/{profile_id}")
async def launch_workspace_profile(profile_id: str, _: dict = Depends(security.verify_authenticated_request)):
    res = workspace.launch_workspace(profile_id)
    if res.get("status") == "error":
        raise HTTPException(status_code=404, detail=res.get("message"))
    return res


@app.post("/api/workspaces/save")
async def save_workspaces_config(data: dict, _: dict = Depends(security.verify_authenticated_request)):
    success = workspace.save_workspaces(data)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to save workspaces")
    return {"status": "success", "message": "Workspaces updated successfully"}


# --- Schedule Endpoints ---

@app.get("/api/schedule")
async def get_schedule():
    return scheduler.get_wake_status()


@app.post("/api/schedule")
async def update_schedule(req: ScheduleRequest, _: dict = Depends(security.verify_authenticated_request)):
    return scheduler.configure_wake_schedule(req.time, req.days, req.enabled)


# --- In-App Bot Endpoints ---

@app.get("/api/bot/history")
async def get_bot_history():
    return {"history": bot_instance.history}


@app.post("/api/bot/chat")
async def bot_chat(req: BotMessageRequest, _: dict = Depends(security.verify_authenticated_request)):
    return bot_instance.process_message(req.message)


# --- Direct APK Download Endpoint ---

@app.get("/download/wakex.apk")
async def download_apk():
    if os.path.exists(APK_PATH):
        return FileResponse(
            APK_PATH,
            media_type="application/vnd.android.package-archive",
            filename="WakeX.apk"
        )
    raise HTTPException(status_code=404, detail="WakeX.apk is still generating. Please check back in a moment.")


# --- Health Check Endpoint (24/7 Monitoring) ---

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "app": "WakeX Hub",
        "uptime": telemetry.get_system_telemetry().get("uptime", "unknown"),
        "os": os_power.get_os_type()
    }


# --- WebSocket for Real-Time Telemetry ---

@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = telemetry.get_system_telemetry()
            await websocket.send_json(data)
            await asyncio.sleep(2.0)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")


# Mount static files (PWA dashboard)
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def serve_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "WakeX Hub Backend is running. Static files missing."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)


@app.get("/api/capabilities")
async def get_capabilities_endpoint(_: dict = Depends(security.require_permission("view"))):
    """Dynamic system capabilities registry for Command Center controls."""
    from engine.capabilities import get_system_capabilities
    return get_system_capabilities()


@app.put("/api/auth/paired-clients/{client_id}/permission")
async def update_client_permission_endpoint(
    client_id: str,
    payload: dict,
    _: dict = Depends(security.require_permission("full"))
):
    """Allows admin/full client to configure granular permission for a device."""
    perm = payload.get("permission", "control")
    success = security.update_client_permission(client_id, perm)
    if not success:
        raise HTTPException(status_code=400, detail="Invalid client ID or permission level.")
    return {"status": "ok", "client_id": client_id, "permission": perm}
