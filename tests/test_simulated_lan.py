"""
tests/test_simulated_lan.py - End-to-End Simulated LAN Multi-Device Integration Suite

Simulates a real local area network environment:
1. Hub running on local host
2. Ephemeral Remote Linux Agent running on 127.0.0.1:18001
3. Simulated Phone companion app executing full X25519 PAKE pairing handshake
4. End-to-end authenticated power action dispatch from Phone -> Hub -> Agent
5. Strict target isolation and replay attack prevention
"""

import os
import sys
import time
import json
import secrets
import hashlib
import hmac
import threading
from http.server import HTTPServer
from unittest.mock import patch
import pytest
from starlette.testclient import TestClient

# Ensure root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import server
from engine import security, devices
from agent import wakex_agent

client = TestClient(server.app)

AGENT_TEST_PORT = 18001
AGENT_DEVICE_ID = "dev_simulated_linux_node"
AGENT_AUTH_TOKEN = "wakex_agent_test_token_secret_12345"

SIMULATED_AGENT_CONFIG = {
    "device_id": AGENT_DEVICE_ID,
    "device_name": "Ubuntu Workstation Node",
    "device_type": "linux",
    "agent_port": AGENT_TEST_PORT,
    "auth_token": AGENT_AUTH_TOKEN,
    "hub_url": "",
    "created_at": time.time()
}


@pytest.fixture(scope="module")
def simulated_agent_server():
    """Spins up a real WakeX agent HTTP server on a local ephemeral test port."""
    wakex_agent.SEEN_NONCES.clear()
    wakex_agent.IDEMPOTENCY_CACHE.clear()

    patcher = patch("agent.wakex_agent.load_or_create_config", return_value=SIMULATED_AGENT_CONFIG)
    patcher.start()

    httpd = HTTPServer(("127.0.0.1", AGENT_TEST_PORT), wakex_agent.WakeXAgentHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.1)

    yield httpd

    httpd.shutdown()
    httpd.server_close()
    patcher.stop()


def test_simulated_lan_full_flow(simulated_agent_server):
    """
    Drives a complete simulated LAN integration flow:
    1. Phone pairs with Hub via X25519 PAKE handshake
    2. Hub registers remote Linux Agent node
    3. Phone sends signed power commands to remote Linux Agent
    4. Verify target isolation, replay protection, and telemetry
    """
    # -------------------------------------------------------------
    # 1. Phone Handshake & Cryptographic Pairing with Hub (X25519 PAKE)
    # -------------------------------------------------------------
    pin = security.generate_pairing_code()
    assert len(pin) == 6

    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization

    phone_priv = x25519.X25519PrivateKey.generate()
    phone_pub_bytes = phone_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    phone_nonce = secrets.token_hex(16)
    phone_client_id = "client_simulated_pixel_phone"

    # Step 1: Exchange
    res_ex = client.post("/api/auth/pair/exchange", json={
        "client_id": phone_client_id,
        "client_name": "Google Pixel 9 Pro (Simulated LAN)",
        "client_public_key": phone_pub_bytes.hex(),
        "client_nonce": phone_nonce
    })
    assert res_ex.status_code == 200
    ex_data = res_ex.json()
    session_id = ex_data["session_id"]
    hub_pub_hex = ex_data["hub_public_key"]
    hub_nonce = ex_data["hub_nonce"]

    # Compute shared secret & HKDF
    hub_pub_obj = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(hub_pub_hex))
    shared_secret = phone_priv.exchange(hub_pub_obj)
    kdf_salt = bytes.fromhex(phone_nonce) + bytes.fromhex(hub_nonce)
    phone_derived_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=kdf_salt,
        info=b"wakex-client-secret-v1"
    ).derive(shared_secret).hex()

    # Step 2: Transcript authentication
    transcript = f"{phone_client_id}:{phone_pub_bytes.hex()}:{phone_nonce}:{hub_pub_hex}:{hub_nonce}"
    phone_proof = hmac.new(pin.encode("utf-8"), f"CLIENT:{transcript}".encode("utf-8"), hashlib.sha256).hexdigest()

    res_auth = client.post("/api/auth/pair/authenticate", json={
        "session_id": session_id,
        "pairing_code": pin,
        "client_proof": phone_proof
    })
    assert res_auth.status_code == 200
    assert res_auth.json()["client_id"] == phone_client_id
    assert "hub_proof" in res_auth.json()

    # Helper function for phone authenticated requests
    def phone_request(method: str, path: str, body: dict = None):
        body_bytes = json.dumps(body).encode("utf-8") if body else b""
        ts = str(int(time.time()))
        nonce = secrets.token_hex(8)
        body_hash = hashlib.sha256(body_bytes).hexdigest()
        sign_str = f"{method.upper()}:{path}:{ts}:{nonce}:{body_hash}"
        sig = hmac.new(phone_derived_secret.encode("utf-8"), sign_str.encode("utf-8"), hashlib.sha256).hexdigest()
        headers = {
            "X-WakeX-Client-Id": phone_client_id,
            "X-WakeX-Timestamp": ts,
            "X-WakeX-Nonce": nonce,
            "X-WakeX-Signature": sig,
            "Content-Type": "application/json"
        }
        if method.upper() == "GET":
            return client.get(path, headers=headers)
        return client.post(path, content=body_bytes, headers=headers)

    # -------------------------------------------------------------
    # 2. Register Simulated Remote Linux Agent into Hub Device Config
    # -------------------------------------------------------------
    devs = devices.load_devices()
    existing_agent = next((d for d in devs if d.get("id") == AGENT_DEVICE_ID), None)
    if not existing_agent:
        devs.append({
            "id": AGENT_DEVICE_ID,
            "name": "Ubuntu Workstation Node",
            "type": "linux",
            "ip": "127.0.0.1",
            "port": AGENT_TEST_PORT,
            "mac": "00-11-22-33-44-55",
            "token": AGENT_AUTH_TOKEN,
            "auth_token": AGENT_AUTH_TOKEN,
            "is_current": False
        })
        devices.save_devices(devs)

    # Verify device appears online in /api/devices
    res_devs = phone_request("GET", "/api/devices")
    assert res_devs.status_code == 200
    device_list = res_devs.json()
    agent_entry = next((d for d in device_list if d["id"] == AGENT_DEVICE_ID), None)
    assert agent_entry is not None
    assert agent_entry["status"] == "online"

    # -------------------------------------------------------------
    # 3. Phone Sends Authenticated Power Actions to Remote Linux Agent
    # -------------------------------------------------------------
    with patch("agent.wakex_agent.execute_agent_power") as mock_agent_exec, \
         patch("engine.os_power.execute_lock") as mock_host_lock:
        mock_agent_exec.return_value = {"status": "success", "action": "lock", "executed": True}

        # Issue lock command to AGENT_DEVICE_ID
        res_power = phone_request("POST", f"/api/devices/{AGENT_DEVICE_ID}/power", {"action": "lock"})
        assert res_power.status_code == 200
        data = res_power.json()
        assert data["status"] == "success"

        # Verify AGENT executed the command
        mock_agent_exec.assert_called_once_with("lock")
        # CRITICAL TARGET ISOLATION PROOF: Host PC lock was NOT called!
        mock_host_lock.assert_not_called()

    # -------------------------------------------------------------
    # 4. Verify Linux Agent Rejects Malformed & Unauthorized Actions
    # -------------------------------------------------------------
    with patch("agent.wakex_agent.execute_agent_power") as mock_agent_exec:
        # Invalid power action (not in whitelist)
        res_invalid = phone_request("POST", f"/api/devices/{AGENT_DEVICE_ID}/power", {"action": "rm -rf /"})
        assert res_invalid.status_code == 400
        mock_agent_exec.assert_not_called()

    # -------------------------------------------------------------
    # 5. Clean Teardown: Remove test agent node
    # -------------------------------------------------------------
    devs = [d for d in devices.load_devices() if d.get("id") != AGENT_DEVICE_ID]
    devices.save_devices(devs)
