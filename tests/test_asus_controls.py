import os
import time
import uuid
import pytest
from starlette.testclient import TestClient
from server import app
from engine import security

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


def test_asus_operating_mode_endpoints():
    os.environ["WAKEX_TEST_FAKE_HARDWARE"] = "1"
    security.reset_all_auth_state()

    ctrl_client = security.register_paired_client("Controller", "client_ctrl", permission="control")
    view_client = security.register_paired_client("Viewer", "client_view", permission="view")

    # 1. View client can read status
    headers_view = generate_auth_headers("client_view", view_client["client_secret"], "GET", "/api/asus/status")
    resp = client.get("/api/asus/status", headers=headers_view)
    assert resp.status_code == 200
    assert "operating_mode" in resp.json()

    # 2. View client cannot change mode
    body = b'{"mode": "turbo"}'
    headers_view_post = generate_auth_headers("client_view", view_client["client_secret"], "POST", "/api/asus/operating-mode", body=body)
    resp = client.post("/api/asus/operating-mode", headers=headers_view_post, content=body)
    assert resp.status_code == 403

    # 3. Control client can set mode
    headers_ctrl = generate_auth_headers("client_ctrl", ctrl_client["client_secret"], "POST", "/api/asus/operating-mode", body=body)
    resp = client.post("/api/asus/operating-mode", headers=headers_ctrl, content=body)
    assert resp.status_code == 200
    assert resp.json()["operating_mode"] == "turbo"

    # 4. Invalid mode rejected
    body_bad = b'{"mode": "nitro_super_boost"}'
    headers_bad = generate_auth_headers("client_ctrl", ctrl_client["client_secret"], "POST", "/api/asus/operating-mode", body=body_bad)
    resp = client.post("/api/asus/operating-mode", headers=headers_bad, content=body_bad)
    assert resp.status_code == 400


def test_asus_battery_limit_endpoints():
    os.environ["WAKEX_TEST_FAKE_HARDWARE"] = "1"
    ctrl_client = security.register_paired_client("Controller", "client_ctrl", permission="control")
    full_client = security.register_paired_client("Admin", "client_full", permission="full")

    # Control client cannot change battery limit (requires 'full')
    body = b'{"limit": 80}'
    headers_ctrl = generate_auth_headers("client_ctrl", ctrl_client["client_secret"], "POST", "/api/asus/battery-limit", body=body)
    resp = client.post("/api/asus/battery-limit", headers=headers_ctrl, content=body)
    assert resp.status_code == 403

    # Full client can set limit
    headers_full = generate_auth_headers("client_full", full_client["client_secret"], "POST", "/api/asus/battery-limit", body=body)
    resp = client.post("/api/asus/battery-limit", headers=headers_full, content=body)
    assert resp.status_code == 200
    assert resp.json()["battery_charge_limit"] == 80


def test_asus_gpu_mode_endpoints():
    os.environ["WAKEX_TEST_FAKE_HARDWARE"] = "1"
    full_client = security.register_paired_client("Admin", "client_full", permission="full")

    body = b'{"mode": "eco"}'
    headers = generate_auth_headers("client_full", full_client["client_secret"], "POST", "/api/asus/gpu-mode", body=body)
    resp = client.post("/api/asus/gpu-mode", headers=headers, content=body)
    assert resp.status_code == 200
    assert resp.json()["dgpu_mode"] == "eco"
    assert resp.json()["reboot_required"] is True
