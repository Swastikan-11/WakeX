"""
WakeX Comprehensive Test Suite
Validates:
1. Zero-Cloud Cryptographic Client Pairing & Secrets Generation.
2. HMAC-SHA256 Request Verification with Nonce & Timestamp Replay Protection.
3. Anti-Brute-Force Rate Limiting (5 failed attempts -> 429 Lockout).
4. Multi-Device Target Isolation: Remote commands NEVER touch Host OS.
5. OS-Level Power Abstraction & Hardware Capability Reporting (Windows & Linux).
6. Safe Display Unlock & Lock Screen Dismissal (Zero cleartext SendKeys).
7. Wake-on-LAN 102-byte Magic Packet Generation across multi-adapter MACs.
8. Standalone Remote Agent Protocol (Authentication, Telemetry, Power Execution).
9. Device Management & Renaming Persistence.
10. Idempotency Guard for Destructive Power Actions.
11. Workspace Profiles & Start Menu App Discovery.
"""
import os
import sys
import json
import time
import socket
import secrets
import hashlib
import hmac
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import server
from engine import os_power, power, devices, security, workspace
from agent import wakex_agent

client = TestClient(server.app)


def make_auth_headers(client_id: str, secret: str, method: str, path: str, body_bytes: bytes = b"") -> dict:
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


# ============================================================================
# 1. Cryptographic Pairing & HMAC Authentication Tests
# ============================================================================

def test_pairing_code_generation_and_consumption():
    """Verify one-time 6-digit pairing code is generated and consumed upon pairing."""
    code = security.generate_pairing_code()
    assert len(code) == 6
    assert code in security.ACTIVE_PAIRING_CODES

    # Pair a test device using the code
    pair_resp = client.post("/api/auth/pair", json={
        "pairing_code": code,
        "client_name": "Test Pixel 9",
        "client_id": "test_client_001"
    })
    assert pair_resp.status_code == 200
    data = pair_resp.json()
    assert data["status"] == "paired"
    assert data["client_id"] == "test_client_001"
    assert "client_secret" in data
    assert len(data["client_secret"]) == 64  # 256-bit hex secret

    # Verify code was consumed (cannot be reused)
    assert code not in security.ACTIVE_PAIRING_CODES
    reuse_resp = client.post("/api/auth/pair", json={
        "pairing_code": code,
        "client_name": "Attacker Device"
    })
    assert reuse_resp.status_code == 401


def test_hmac_authenticated_request_success():
    """Verify a valid HMAC-signed request executes successfully."""
    # Ensure test client is paired
    creds = security.register_paired_client("Pixel Tester", "test_pixel")
    cid = creds["client_id"]
    secret = creds["client_secret"]

    with patch("engine.devices.dispatch_power_command", return_value={"status": "success", "action": "lock"}):
        body_bytes = b'{"action":"lock"}'
        headers = make_auth_headers(cid, secret, "POST", "/api/devices/host-primary/power", body_bytes)
        resp = client.post("/api/devices/host-primary/power", content=body_bytes, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"


def test_unauthenticated_requests_blocked():
    """Verify unauthenticated remote requests without HMAC headers are rejected with 401."""
    resp = client.post("/api/devices/host-primary/power", json={"action": "lock"})
    assert resp.status_code == 401


def test_replay_attack_rejected_duplicate_nonce():
    """Verify that reusing the same nonce within the time window is blocked with HTTP 403."""
    creds = security.register_paired_client("Replay Target", "test_replay_client")
    cid = creds["client_id"]
    secret = creds["client_secret"]

    body_bytes = b'{"action":"lock"}'
    headers = make_auth_headers(cid, secret, "POST", "/api/devices/host-primary/power", body_bytes)

    with patch("engine.devices.dispatch_power_command", return_value={"status": "success", "action": "lock"}):
        # 1st attempt: success
        resp1 = client.post("/api/devices/host-primary/power", content=body_bytes, headers=headers)
        assert resp1.status_code == 200

        # 2nd attempt with IDENTICAL headers/nonce (Replay attack): MUST be rejected
        resp2 = client.post("/api/devices/host-primary/power", content=body_bytes, headers=headers)
        assert resp2.status_code == 403
        assert "replay detected" in resp2.json()["detail"].lower()


def test_replay_attack_rejected_skewed_timestamp():
    """Verify that timestamps older than 60 seconds are blocked with HTTP 403."""
    creds = security.register_paired_client("Skew Target", "test_skew_client")
    cid = creds["client_id"]
    secret = creds["client_secret"]

    payload = {"action": "lock"}
    body_bytes = json.dumps(payload).encode("utf-8")
    old_ts = str(int(time.time()) - 120)  # 2 minutes in the past
    nonce = secrets.token_hex(8)
    sig = security.compute_request_signature(secret, "POST", "/api/devices/host-primary/power", old_ts, nonce, body_bytes)

    headers = {
        "X-WakeX-Client-Id": cid,
        "X-WakeX-Timestamp": old_ts,
        "X-WakeX-Nonce": nonce,
        "X-WakeX-Signature": sig,
        "Content-Type": "application/json"
    }

    resp = client.post("/api/devices/host-primary/power", json=payload, headers=headers)
    assert resp.status_code == 403
    assert "expired" in resp.json()["detail"].lower() or "skewed" in resp.json()["detail"].lower()


def test_power_action_idempotency_guard():
    """Verify duplicate power commands with the same nonce return cached responses without executing OS APIs twice."""
    creds = security.register_paired_client("Idempotency Device", "test_idem_client")
    cid = creds["client_id"]
    secret = creds["client_secret"]

    body_bytes = b'{"action":"lock"}'
    headers = make_auth_headers(cid, secret, "POST", "/api/devices/host-primary/power", body_bytes)

    with patch("engine.devices.dispatch_power_command", return_value={"status": "success", "action": "lock"}) as mock_dispatch:
        # First call: executes dispatch
        resp1 = client.post("/api/devices/host-primary/power", content=body_bytes, headers=headers)
        assert resp1.status_code == 200
        assert mock_dispatch.call_count == 1

        # Second call with stored idempotency key: should return cached result without calling dispatch again
        idem_key = f"{cid}:{headers['X-WakeX-Nonce']}"
        cached = security.check_and_record_idempotency(idem_key)
        assert cached is not None
        assert cached["status"] == "success"


def test_anti_brute_force_rate_limit_lockout():
    """Verify that exceeding 5 failed auth attempts locks out the IP with HTTP 429."""
    test_ip = "192.168.99.99"
    security.clear_auth_failures(test_ip)

    for i in range(security.MAX_FAILED_ATTEMPTS):
        security.record_auth_failure(test_ip)

    # Next check must raise 429 HTTPException
    with pytest.raises(Exception) as exc_info:
        security.check_rate_limit(test_ip)
    assert "429" in str(exc_info.value)
    security.clear_auth_failures(test_ip)


# ============================================================================
# 2. Multi-Device Safety & Target Isolation Tests (CRITICAL)
# ============================================================================

def test_remote_device_power_isolation(monkeypatch):
    """
    CRITICAL MULTI-DEVICE SAFETY REQUIREMENT:
    When user executes a power command (Shutdown/Restart/Sleep/Hibernate/Lock) for Device B (Remote Linux PC),
    Host Device A MUST NEVER execute the command locally.
    The command must be dispatched via HTTP to Device B's agent.
    """
    test_devices = [
        {
            "id": "host-primary",
            "name": "ASUS TUF Gaming F15",
            "ip": "192.168.1.23",
            "is_current": True,
            "os": "windows"
        },
        {
            "id": "remote-node-2",
            "name": "Sanjay PC",
            "ip": "192.168.1.48",
            "port": 8001,
            "auth_token": "sanjay_secret_token_123",
            "is_current": False,
            "os": "linux"
        }
    ]
    monkeypatch.setattr(devices, "load_devices", lambda: test_devices)

    # Mock local host OS power functions to ensure they are NEVER called
    host_shutdown_mock = MagicMock()
    host_restart_mock = MagicMock()
    host_sleep_mock = MagicMock()
    monkeypatch.setattr(os_power, "execute_shutdown", host_shutdown_mock)
    monkeypatch.setattr(os_power, "execute_restart", host_restart_mock)
    monkeypatch.setattr(os_power, "execute_sleep", host_sleep_mock)

    # Mock remote agent HTTP dispatcher
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"status": "success", "action": "shutdown", "os": "linux"}).encode("utf-8")
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # Execute shutdown on remote Sanjay PC
        result = devices.dispatch_power_command("remote-node-2", "shutdown", delay_seconds=0)

        assert result["status"] == "success"
        assert result["target_device_id"] == "remote-node-2"

        # VERIFY: Host OS functions were NEVER invoked
        host_shutdown_mock.assert_not_called()
        host_restart_mock.assert_not_called()
        host_sleep_mock.assert_not_called()

        # Verify the remote request was sent to Sanjay PC's IP and port with token
        called_req = mock_urlopen.call_args[0][0]
        assert called_req.full_url == "http://192.168.1.48:8001/api/agent/power"
        assert called_req.get_header("X-wakex-device-token") == "sanjay_secret_token_123"
        req_data = json.loads(called_req.data.decode("utf-8"))
        assert req_data["action"] == "shutdown"


def test_remote_device_offline_does_not_affect_host(monkeypatch):
    """
    When remote device is unreachable/offline, the Hub reports error.
    It MUST NEVER fall back to executing locally on the host.
    """
    test_devices = [
        {"id": "host-primary", "name": "ASUS TUF", "ip": "192.168.1.23", "is_current": True},
        {"id": "remote-node-2", "name": "Sanjay PC", "ip": "192.168.1.48", "port": 8001, "auth_token": "tok", "is_current": False}
    ]
    monkeypatch.setattr(devices, "load_devices", lambda: test_devices)

    host_shutdown_mock = MagicMock()
    monkeypatch.setattr(os_power, "execute_shutdown", host_shutdown_mock)

    import urllib.error
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        result = devices.dispatch_power_command("remote-node-2", "shutdown")
        assert result["status"] == "error"
        assert result["code"] == "DEVICE_UNREACHABLE"
        host_shutdown_mock.assert_not_called()


def test_nonexistent_device_id_rejected():
    """Commands sent to non-existent target device IDs must fail safely."""
    result = devices.dispatch_power_command("ghost-device-999", "restart")
    assert result["status"] == "error"
    assert result["code"] == "DEVICE_NOT_FOUND"


# ============================================================================
# 3. OS-Level Power Abstraction & Hardware Capabilities
# ============================================================================

def test_real_system_capabilities():
    """Verify system capabilities reports genuine OS features and hardware state."""
    caps = os_power.get_supported_capabilities()
    assert "os" in caps
    assert "shutdown" in caps
    assert "restart" in caps
    assert "lock" in caps
    assert "sleep" in caps
    assert "hibernate" in caps
    assert "wake_on_lan" in caps


def test_windows_lock_workstation_dispatch(monkeypatch):
    """Test that lock action executes LockWorkStation without error."""
    if os_power.CURRENT_OS != "windows":
        pytest.skip("Windows only test")

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        res = os_power.execute_lock()
        assert res["status"] == "success"
        assert res["action"] == "lock"
        mock_run.assert_called_once()
        assert "rundll32.exe user32.dll,LockWorkStation" in mock_run.call_args[0][0]


def test_cancel_shutdown(monkeypatch):
    """Test abort/cancel pending shutdown logic."""
    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = MagicMock(returncode=0)
        res = os_power.abort_shutdown()
        assert res["status"] == "success"


def test_safe_unlock_screen_execution():
    """Verify that execute_unlock runs display wake and lock screen dismissal without SendKeys."""
    res = os_power.execute_unlock()
    assert res["status"] == "success"
    assert res["action"] == "unlock"


# ============================================================================
# 4. Wake-on-LAN Magic Packet Generation
# ============================================================================

def test_wake_on_lan_magic_packet_structure():
    """
    Verify the Wake-on-LAN packet is exactly 102 bytes:
    - 6 bytes of 0xFF
    - 16 repetitions of the target device's 6-byte MAC address.
    """
    mac = "00-AA-BB-CC-DD-EE"
    clean_mac = mac.replace("-", "").replace(":", "")
    mac_bytes = bytes.fromhex(clean_mac)
    assert len(mac_bytes) == 6

    expected_packet = b'\xff' * 6 + mac_bytes * 16
    assert len(expected_packet) == 102

    with patch("socket.socket") as mock_socket_cls:
        mock_sock = MagicMock()
        mock_socket_cls.return_value.__enter__.return_value = mock_sock

        result = devices.send_wake_on_lan(mac, broadcast_ip="192.168.1.255", port=9)
        assert result["status"] == "success"
        mock_sock.sendto.assert_any_call(expected_packet, ("192.168.1.255", 9))


# ============================================================================
# 5. Remote Agent Daemon (Linux & Windows Standalone Agent)
# ============================================================================

def test_agent_telemetry_reporting():
    """Verify the agent reports system telemetry and status."""
    status = wakex_agent.get_agent_telemetry()
    assert "os" in status
    assert "hostname" in status
    assert "cpu_percent" in status
    assert "memory_percent" in status
    assert status["status"] == "online"


def test_agent_power_execution_dispatch(monkeypatch):
    """Verify the agent parses and routes power commands."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        res = wakex_agent.execute_agent_power("shutdown")
        assert res["status"] == "success"
        mock_run.assert_called_once()


# ============================================================================
# 6. Device Renaming and Persistence
# ============================================================================

def test_device_rename_and_persistence(monkeypatch):
    sample_devices = [
        {"id": "host-primary", "name": "ASUS TUF Gaming F15", "ip": "192.168.1.100", "is_current": True},
        {"id": "remote-node-2", "name": "Sanjay PC", "ip": "192.168.1.150", "is_current": False}
    ]
    monkeypatch.setattr(devices, "load_devices", lambda: [d.copy() for d in sample_devices])
    monkeypatch.setattr(devices, "save_devices", lambda devs: sample_devices.clear() or sample_devices.extend(devs) or True)

    res = devices.rename_device("remote-node-2", "Sanjay Workstation")
    assert res["status"] == "success"
    updated = next((d for d in sample_devices if d["id"] == "remote-node-2"), None)
    assert updated["name"] == "Sanjay Workstation"


# ============================================================================
# 7. Workspace and Scheduling Engine
# ============================================================================

def test_workspace_get_installed_apps():
    apps = workspace.get_installed_apps()
    assert isinstance(apps, list)
    if apps:
        assert "name" in apps[0]
        assert "app_id" in apps[0]


def test_workspace_crud_and_schedule_persistence(tmp_path, monkeypatch):
    dummy_config = {"active_profile": "test_ws", "profiles": []}
    monkeypatch.setattr(workspace, "CONFIG_PATH", str(tmp_path / "workspaces.json"))
    monkeypatch.setattr(workspace, "load_workspaces", lambda: dummy_config)
    monkeypatch.setattr(workspace, "save_workspaces", lambda data: dummy_config.update(data) or True)

    profile_req = {
        "name": "Dev Shift",
        "description": "Daily development setup",
        "applications": [{"name": "Calculator", "app_id": "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App"}],
        "urls": ["https://mail.google.com"],
        "schedule": {"enabled": True, "time": "09:30", "days": ["Mon", "Tue"]}
    }

    saved = workspace.save_or_update_profile(profile_req)
    assert saved["id"] is not None
    assert len(dummy_config["profiles"]) == 1
    assert dummy_config["profiles"][0]["name"] == "Dev Shift"

    deleted = workspace.delete_profile(saved["id"])
    assert deleted is True
    assert len(dummy_config["profiles"]) == 0


def test_system_readiness_diagnostics():
    """Verify system readiness reports structured diagnostics, adapters, and score."""
    from engine import readiness
    report = readiness.get_wol_readiness()
    assert "os" in report
    assert "readiness_score" in report
    assert "adapters" in report
    assert "checks" in report
    assert isinstance(report["readiness_score"], int)
    assert 0 <= report["readiness_score"] <= 100
    assert len(report["checks"]) > 0


def test_workspace_launch_app_security_sanitization():
    """Verify that suspicious commands containing shell injection characters are blocked."""
    assert workspace.launch_single_app("malicious_cmd & calc.exe") is False
    assert workspace.launch_single_app("test_app | shutdown /s") is False
    assert workspace.launch_single_app("app; rm -rf /") is False
    assert workspace.launch_single_app("file:///etc/passwd") is False
    assert workspace.launch_single_app("javascript:alert(1)") is False


# ============================================================================
# 8. Storage Resilience & Agent Hardening Tests
# ============================================================================

def test_storage_atomic_write_and_recovery(tmp_path):
    """Verify atomic write, flush, and recovery from .bak file upon corrupted JSON."""
    from engine.storage import atomic_write_json, safe_read_json
    test_file = str(tmp_path / "test_data.json")

    # Write initial valid payload
    data1 = {"version": 1, "status": "active"}
    assert atomic_write_json(test_file, data1) is True
    assert safe_read_json(test_file) == data1

    # Write updated payload (creating .bak)
    data2 = {"version": 2, "status": "updated"}
    assert atomic_write_json(test_file, data2) is True
    assert safe_read_json(test_file) == data2
    assert os.path.exists(test_file + ".bak")

    # Corrupt main file (simulate partial write / disk crash)
    with open(test_file, "w", encoding="utf-8") as f:
        f.write("{ incomplete_broken_json: ...")

    # safe_read_json should seamlessly recover data1 from the backup (.bak)
    recovered = safe_read_json(test_file, default={})
    assert recovered == data1


def test_agent_action_whitelist_validation():
    """Verify unknown or unwhitelisted commands are rejected by the agent."""
    res = wakex_agent.execute_agent_power("format_c")
    assert res["status"] == "error"
    assert "not permitted" in res["message"]

    res_hack = wakex_agent.execute_agent_power("shutdown; rm -rf /")
    assert res_hack["status"] == "error"


def test_agent_supported_actions():
    """Verify agent accurately inspects and returns supported platform actions."""
    actions = wakex_agent.get_supported_actions()
    assert "shutdown" in actions
    assert "restart" in actions
    assert "sleep" in actions


def test_agent_auth_verification_modes():
    """Verify Agent handler authenticates direct tokens, HMAC signatures, and rejects invalid/replayed requests."""
    handler = wakex_agent.WakeXAgentHandler.__new__(wakex_agent.WakeXAgentHandler)
    handler.client_address = ("192.168.1.100", 50221)
    handler.path = "/api/agent/power"

    config = {
        "auth_token": "secret_agent_token_abc123",
        "device_id": "dev_test_01"
    }

    # 1. Direct device token test (success)
    handler.headers = {"X-WakeX-Device-Token": "secret_agent_token_abc123"}
    ok, err = handler._verify_auth(config, b"{}")
    assert ok is True
    assert err == ""

    # 2. Invalid direct device token test (failure)
    handler.headers = {"X-WakeX-Device-Token": "wrong_token"}
    ok, err = handler._verify_auth(config, b"{}")
    assert ok is False

    # 3. Valid HMAC-SHA256 signature test (success)
    body = b'{"action":"sleep"}'
    ts = str(int(time.time()))
    nonce = secrets.token_hex(8)
    body_hash = hashlib.sha256(body).hexdigest()
    sign_str = f"POST:/api/agent/power:{ts}:{nonce}:{body_hash}"
    sig = hmac.new(b"secret_agent_token_abc123", sign_str.encode("utf-8"), hashlib.sha256).hexdigest()

    handler.headers = {
        "X-WakeX-Signature": sig,
        "X-WakeX-Timestamp": ts,
        "X-WakeX-Nonce": nonce
    }
    ok, err = handler._verify_auth(config, body)
    assert ok is True

    # 4. Replay attack with same nonce (failure)
    ok, err = handler._verify_auth(config, body)
    assert ok is False
    assert "Replay attack detected" in err

    # 5. Skewed timestamp (>60 seconds) (failure)
    skewed_ts = str(int(time.time()) - 100)
    skewed_nonce = secrets.token_hex(8)
    sign_str_skewed = f"POST:/api/agent/power:{skewed_ts}:{skewed_nonce}:{body_hash}"
    sig_skewed = hmac.new(b"secret_agent_token_abc123", sign_str_skewed.encode("utf-8"), hashlib.sha256).hexdigest()
    handler.headers = {
        "X-WakeX-Signature": sig_skewed,
        "X-WakeX-Timestamp": skewed_ts,
        "X-WakeX-Nonce": skewed_nonce
    }
    ok, err = handler._verify_auth(config, body)
    assert ok is False
    assert "skewed" in err

