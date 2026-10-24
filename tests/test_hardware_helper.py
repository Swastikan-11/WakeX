import os
import pytest
from engine.hardware_ipc import send_hardware_command, is_helper_connected, _fake_backend
from engine.capabilities import get_system_capabilities, detect_software_conflicts


def test_fake_hardware_backend_operating_modes():
    os.environ["WAKEX_TEST_FAKE_HARDWARE"] = "1"
    assert is_helper_connected() is True

    # Check ping
    ping = send_hardware_command("PING")
    assert ping["status"] == "ok"

    # Test setting operating mode
    res = send_hardware_command("SET_OPERATING_MODE", {"mode": "turbo"})
    assert res["status"] == "ok"
    assert res["operating_mode"] == "turbo"
    assert _fake_backend.cpu_fan_rpm == 4200

    res = send_hardware_command("SET_OPERATING_MODE", {"mode": "silent"})
    assert res["status"] == "ok"
    assert res["operating_mode"] == "silent"
    assert _fake_backend.cpu_fan_rpm == 1800

    # Reject invalid mode
    res = send_hardware_command("SET_OPERATING_MODE", {"mode": "extreme_overclock"})
    assert res["status"] == "error"
    assert res["error_code"] == "INVALID_MODE"


def test_fake_hardware_backend_battery_limit():
    os.environ["WAKEX_TEST_FAKE_HARDWARE"] = "1"

    # Allowed limit
    res = send_hardware_command("SET_BATTERY_LIMIT", {"limit": 80})
    assert res["status"] == "ok"
    assert res["battery_charge_limit"] == 80

    res = send_hardware_command("SET_BATTERY_LIMIT", {"limit": 60})
    assert res["status"] == "ok"
    assert res["battery_charge_limit"] == 60

    # Rejected limit out of safe range
    res = send_hardware_command("SET_BATTERY_LIMIT", {"limit": 30})
    assert res["status"] == "error"
    assert res["error_code"] == "LIMIT_OUT_OF_RANGE"


def test_fake_hardware_backend_dgpu_modes():
    os.environ["WAKEX_TEST_FAKE_HARDWARE"] = "1"

    # Eco mode puts dGPU to sleep
    res = send_hardware_command("SET_DGPU_MODE", {"mode": "eco"})
    assert res["status"] == "ok"
    assert res["dgpu_mode"] == "eco"
    assert _fake_backend.gpu_sleeping is True

    # Standard mode wakes dGPU
    res = send_hardware_command("SET_DGPU_MODE", {"mode": "standard"})
    assert res["status"] == "ok"
    assert res["dgpu_mode"] == "standard"
    assert _fake_backend.gpu_sleeping is False


def test_capabilities_registry_structure():
    caps = get_system_capabilities(force_refresh=True)
    assert "os" in caps
    assert "supported_operating_modes" in caps
    assert "supported_refresh_rates" in caps
    assert isinstance(caps["supported_refresh_rates"], list)
    assert "conflicts" in caps
    assert "armoury_crate_detected" in caps["conflicts"]
    assert "ghelper_detected" in caps["conflicts"]
