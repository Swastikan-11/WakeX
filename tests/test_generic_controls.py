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


def test_live_telemetry_endpoint():
    security.reset_all_auth_state()
    user = security.register_paired_client("Tester", "client_test", permission="control")

    headers = generate_auth_headers("client_test", user["client_secret"], "GET", "/api/telemetry/live")
    resp = client.get("/api/telemetry/live", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "cpu" in data
    assert "usage_pct" in data["cpu"]
    assert "freq_mhz" in data["cpu"]
    assert "memory" in data
    assert "used_gb" in data["memory"]
    assert "gpu" in data
    # GPU asleep safety: status should be power_saving, active, or unavailable
    assert data["gpu"]["status"] in ("power_saving", "active", "unavailable")


def test_monitor_history_endpoint():
    user = security.register_paired_client("Tester", "client_test", permission="view")
    headers = generate_auth_headers("client_test", user["client_secret"], "GET", "/api/monitor/history")
    resp = client.get("/api/monitor/history", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "history" in data
    assert isinstance(data["history"], list)


def test_media_control_endpoint():
    user = security.register_paired_client("Tester", "client_test", permission="control")
    body = b'{"action": "play_pause"}'
    headers = generate_auth_headers("client_test", user["client_secret"], "POST", "/api/system/media", body=body)
    resp = client.post("/api/system/media", headers=headers, content=body)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_audio_endpoints():
    user = security.register_paired_client("Tester", "client_test", permission="control")

    # Get audio
    headers_get = generate_auth_headers("client_test", user["client_secret"], "GET", "/api/system/audio")
    resp = client.get("/api/system/audio", headers=headers_get)
    assert resp.status_code == 200
    assert "volume" in resp.json()

    # Set volume
    body = b'{"volume": 70}'
    headers_vol = generate_auth_headers("client_test", user["client_secret"], "POST", "/api/system/audio/volume", body=body)
    resp = client.post("/api/system/audio/volume", headers=headers_vol, content=body)
    assert resp.status_code == 200
    assert resp.json()["volume"] == 70


def test_power_plan_endpoint():
    user = security.register_paired_client("Tester", "client_test", permission="view")
    headers = generate_auth_headers("client_test", user["client_secret"], "GET", "/api/system/power-plan")
    resp = client.get("/api/system/power-plan", headers=headers)
    assert resp.status_code == 200
    assert "plan" in resp.json()
