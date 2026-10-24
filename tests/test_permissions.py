import time
import uuid
import pytest
from starlette.testclient import TestClient
from server import app
from engine import security, devices

client = TestClient(app)


def generate_auth_headers(client_id: str, secret: str, method: str, path: str, body: bytes = b"") -> dict:
    ts = str(time.time())
    nonce = uuid.uuid4().hex
    sig = security.compute_request_signature(
        secret=secret,
        method=method,
        path=path,
        timestamp=ts,
        nonce=nonce,
        body_bytes=body
    )
    return {
        "x-wakex-client-id": client_id,
        "x-wakex-timestamp": ts,
        "x-wakex-nonce": nonce,
        "x-wakex-signature": sig,
        "content-type": "application/json"
    }


def test_permission_hierarchy_enforcement(monkeypatch):
    monkeypatch.setattr(devices, "dispatch_power_command", lambda d, a, delay=0: {"status": "ok", "action": a})

    # Setup test clients with different permission levels
    security.reset_all_auth_state()

    view_client = security.register_paired_client("Viewer Phone", "client_viewer", permission="view")
    ctrl_client = security.register_paired_client("Controller Phone", "client_ctrl", permission="control")
    full_client = security.register_paired_client("Admin Phone", "client_full", permission="full")

    # 1. Test View Client
    # Should succeed on read endpoint
    headers_view = generate_auth_headers("client_viewer", view_client["client_secret"], "GET", "/api/system/capabilities")
    resp = client.get("/api/system/capabilities", headers=headers_view)
    assert resp.status_code == 200

    # Should FAIL with 403 on power action
    body = b'{"action": "sleep"}'
    headers_power_view = generate_auth_headers("client_viewer", view_client["client_secret"], "POST", "/api/devices/host_pc/power", body=body)
    resp = client.post("/api/devices/host_pc/power", headers=headers_power_view, content=body)
    assert resp.status_code == 403
    assert "Insufficient permissions" in resp.json()["detail"]

    # 2. Test Control Client
    # Should succeed on display wake / lock
    body_lock = b'{"action": "lock"}'
    headers_lock_ctrl = generate_auth_headers("client_ctrl", ctrl_client["client_secret"], "POST", "/api/devices/host_pc/power", body=body_lock)
    resp = client.post("/api/devices/host_pc/power", headers=headers_lock_ctrl, content=body_lock)
    assert resp.status_code == 200

    # Should FAIL on destructive shutdown
    body_shut = b'{"action": "shutdown"}'
    headers_shut_ctrl = generate_auth_headers("client_ctrl", ctrl_client["client_secret"], "POST", "/api/devices/host_pc/power", body=body_shut)
    resp = client.post("/api/devices/host_pc/power", headers=headers_shut_ctrl, content=body_shut)
    assert resp.status_code == 403
    assert "Insufficient permissions" in resp.json()["detail"]

    # 3. Test Full Client
    # Should be permitted on destructive actions (e.g. shutdown / cancel)
    body_cancel = b'{"action": "cancel_shutdown"}'
    headers_cancel_full = generate_auth_headers("client_full", full_client["client_secret"], "POST", "/api/devices/host_pc/power", body=body_cancel)
    resp = client.post("/api/devices/host_pc/power", headers=headers_cancel_full, content=body_cancel)
    assert resp.status_code == 200

    # 4. Permission update endpoint
    success = security.update_client_permission("client_viewer", "full")
    assert success is True
    # Now viewer has full and can cancel shutdown
    headers_now_full = generate_auth_headers("client_viewer", view_client["client_secret"], "POST", "/api/devices/host_pc/power", body=body_cancel)
    resp = client.post("/api/devices/host_pc/power", headers=headers_now_full, content=body_cancel)
    assert resp.status_code == 200
