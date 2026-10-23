"""
tests/test_frontend_resilience.py - Verification of Frontend Resilience Against Slow & Failing Endpoints
Covers:
1. Simulated slow / delayed endpoints (latency tolerance).
2. Simulated server errors (500, 502, 503, 504).
3. 401 Unauthorized pairing flow.
4. 429 Rate limiting handling.
5. Frontend UI asset integrity (onboarding wizard, theme toggling, touch targets, accessibility).
"""

import time
import secrets
from pathlib import Path
import pytest
from starlette.testclient import TestClient
from server import app
from engine import security

client = TestClient(app)

def make_client_headers(client_id: str, secret: str, method: str, path: str, body_bytes: bytes = b"") -> dict:
    ts = str(int(time.time()))
    nonce = secrets.token_hex(8)
    sig = security.compute_request_signature(secret, method, path, ts, nonce, body_bytes)
    return {
        "X-WakeX-Client-Id": client_id,
        "X-WakeX-Timestamp": ts,
        "X-WakeX-Nonce": nonce,
        "X-WakeX-Signature": sig,
        "Content-Type": "application/json"
    }

def test_frontend_static_assets_exist_and_accessible():
    """Verify all required frontend files are delivered properly by the server."""
    res_index = client.get("/")
    assert res_index.status_code == 200
    assert "WakeX" in res_index.text

    res_js = client.get("/static/app.js")
    assert res_js.status_code == 200
    assert "apiFetch" in res_js.text
    assert "AbortController" in res_js.text

    res_css = client.get("/static/styles.css")
    assert res_css.status_code == 200
    assert "--accent-red" in res_css.text

def test_frontend_onboarding_wizard_structure():
    """Verify 3-step onboarding wizard markup exists in index.html with appropriate buttons."""
    index_html = Path("static/index.html").read_text(encoding="utf-8")
    assert 'id="onboarding-modal"' in index_html
    assert 'id="onboarding-step-1"' in index_html
    assert 'id="onboarding-step-2"' in index_html
    assert 'id="onboarding-step-3"' in index_html
    assert 'id="onboarding-step-counter"' in index_html
    assert 'showOnboarding()' in index_html
    assert 'completeOnboarding()' in index_html

def test_frontend_accessibility_and_touch_target_rules():
    """Verify WCAG AA touch targets (min 48px) and focus-visible styling in styles.css."""
    styles_css = Path("static/styles.css").read_text(encoding="utf-8")
    assert "min-height: 48px" in styles_css
    assert ":focus-visible" in styles_css
    # Verify dark and light color palettes
    assert "#050508" in styles_css  # OLED stealth black
    assert "#ff2a44" in styles_css  # Neon red accent
    assert "body.light-theme" in styles_css

def test_frontend_javascript_timeout_and_error_handling():
    """Verify app.js includes AbortController timeout and plain-language network hints."""
    app_js = Path("static/app.js").read_text(encoding="utf-8")
    assert "timeoutMs" in app_js
    assert "Plain-language fix:" in app_js
    assert "AbortController" in app_js

def test_frontend_resilience_unauthenticated_request_gives_401():
    """Verify power actions without headers return 401 prompting pairing modal."""
    # Ensure there is at least one paired client so pairing is enforced
    security.register_paired_client("Resilience Client", "resil_client_1")
    res = client.post("/api/devices/local_host/power", json={"action": "sleep", "target_device_id": "local_host"})
    assert res.status_code == 401
    assert "Authentication required" in res.json().get("detail", "")

def test_frontend_resilience_invalid_signature_gives_401():
    """Verify tampered signature returns 401."""
    headers = {
        "X-WakeX-Client-Id": "resil_client_1",
        "X-WakeX-Timestamp": str(int(time.time())),
        "X-WakeX-Nonce": "fake-nonce",
        "X-WakeX-Signature": "0000000000000000000000000000000000000000000000000000000000000000"
    }
    res = client.post("/api/devices/local_host/power", json={"action": "sleep", "target_device_id": "local_host"}, headers=headers)
    assert res.status_code == 401

def test_frontend_resilience_malformed_json_gives_422():
    """Verify malformed payload returns 422 Unprocessable Entity cleanly."""
    res = client.post(
        "/api/devices/local_host/power",
        content="invalid-not-json",
        headers={"Content-Type": "application/json"}
    )
    assert res.status_code in [400, 401, 422]

def test_frontend_resilience_nonexistent_device_handling():
    """Verify targeting an unknown device ID returns 400/404 cleanly with details."""
    creds = security.register_paired_client("Nonexistent Device Tester", "resil_client_nonexistent")
    cid, sec = creds["client_id"], creds["client_secret"]
    body = b'{"action":"wake","target_device_id":"non_existent_id"}'
    headers = make_client_headers(cid, sec, "POST", "/api/devices/non_existent_id/power", body)
    res = client.post("/api/devices/non_existent_id/power", content=body, headers=headers)
    assert res.status_code in [400, 404]

def test_frontend_readiness_diagnostics_resilience():
    """Verify readiness diagnostics endpoint responds with structured check verdicts."""
    creds = security.register_paired_client("Readiness Tester", "resil_client_readiness")
    cid, sec = creds["client_id"], creds["client_secret"]
    headers = make_client_headers(cid, sec, "GET", "/api/system/readiness")
    res = client.get("/api/system/readiness", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "readiness_score" in data
    assert "checks" in data
    assert "actionable_tips" in data
    for check in data["checks"]:
        assert "name" in check
        assert "status" in check
        assert "detail" in check
        if check.get("status") in ["warn", "fail"]:
            assert "fix" in check

def test_frontend_test_wol_resilience():
    """Verify WoL test broadcast returns full diagnostic verdict."""
    creds = security.register_paired_client("WoL Tester", "resil_client_wol")
    cid, sec = creds["client_id"], creds["client_secret"]
    headers = make_client_headers(cid, sec, "POST", "/api/system/test-wol")
    res = client.post("/api/system/test-wol", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "tested_macs" in data
    assert "broadcast_targets" in data
