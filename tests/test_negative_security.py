import os
import time
import uuid
import pytest
from starlette.testclient import TestClient
from server import app
from engine import security

client = TestClient(app)


def generate_auth_headers(client_id: str, secret: str, method: str, path: str, body: bytes = b"", timestamp: str = None, nonce: str = None) -> dict:
    ts = timestamp or str(time.time())
    n = nonce or uuid.uuid4().hex
    sig = security.compute_request_signature(
        secret=secret,
        method=method,
        path=path,
        timestamp=ts,
        nonce=n,
        body_bytes=body
    )
    return {
        "x-wakex-client-id": client_id,
        "x-wakex-timestamp": ts,
        "x-wakex-nonce": n,
        "x-wakex-signature": sig,
        "content-type": "application/json"
    }


def test_unsigned_hardware_request_rejected():
    # Calling hardware endpoint with zero security headers
    resp = client.post("/api/asus/operating-mode", json={"mode": "turbo"})
    assert resp.status_code == 401
    assert "Missing cryptographic client headers" in resp.json()["detail"]


def test_replayed_nonce_hardware_request_rejected():
    os.environ["WAKEX_TEST_FAKE_HARDWARE"] = "1"
    security.reset_all_auth_state()
    user = security.register_paired_client("Tester", "client_replay", permission="full")

    body = b'{"mode": "silent"}'
    fixed_nonce = "fixed_test_nonce_12345"
    fixed_ts = str(time.time())

    headers = generate_auth_headers("client_replay", user["client_secret"], "POST", "/api/asus/operating-mode", body=body, timestamp=fixed_ts, nonce=fixed_nonce)

    # First request succeeds
    r1 = client.post("/api/asus/operating-mode", headers=headers, content=body)
    assert r1.status_code == 200

    # Exact replay of same nonce rejected
    r2 = client.post("/api/asus/operating-mode", headers=headers, content=body)
    assert r2.status_code == 403
    assert "Duplicate request nonce" in r2.json()["detail"]


def test_clock_skew_timestamp_rejected():
    security.reset_all_auth_state()
    user = security.register_paired_client("Tester", "client_skew", permission="full")

    body = b'{"mode": "turbo"}'
    old_ts = str(time.time() - 300) # 5 minutes in past

    headers = generate_auth_headers("client_skew", user["client_secret"], "POST", "/api/asus/operating-mode", body=body, timestamp=old_ts)
    resp = client.post("/api/asus/operating-mode", headers=headers, content=body)
    assert resp.status_code == 403
    assert "Request expired or clock skewed" in resp.json()["detail"]


def test_wrong_permission_rejected():
    security.reset_all_auth_state()
    # View-only client
    viewer = security.register_paired_client("Viewer", "client_view_only", permission="view")

    body = b'{"limit": 80}'
    headers = generate_auth_headers("client_view_only", viewer["client_secret"], "POST", "/api/asus/battery-limit", body=body)
    resp = client.post("/api/asus/battery-limit", headers=headers, content=body)
    assert resp.status_code == 403
    assert "Insufficient permissions" in resp.json()["detail"]


def test_malformed_and_out_of_range_parameters():
    os.environ["WAKEX_TEST_FAKE_HARDWARE"] = "1"
    security.reset_all_auth_state()
    admin = security.register_paired_client("Admin", "client_admin", permission="full")

    # 1. Out of range battery limit
    body_limit = b'{"limit": 250}'
    headers_lim = generate_auth_headers("client_admin", admin["client_secret"], "POST", "/api/asus/battery-limit", body=body_limit)
    resp = client.post("/api/asus/battery-limit", headers=headers_lim, content=body_limit)
    assert resp.status_code == 400

    # 2. Unknown operating mode
    body_mode = b'{"mode": "nuclear_fusion_boost"}'
    headers_mode = generate_auth_headers("client_admin", admin["client_secret"], "POST", "/api/asus/operating-mode", body=body_mode)
    resp = client.post("/api/asus/operating-mode", headers=headers_mode, content=body_mode)
    assert resp.status_code == 400
