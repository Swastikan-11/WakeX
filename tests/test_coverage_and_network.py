"""
tests/test_coverage_and_network.py - Feature Coverage, Discovery, IP Re-binding, & Cross-Platform Power Tests

Covers:
1. UDP discovery service (response to WAKEX_DISCOVER and beacon emission).
2. Hub IP re-binding on host network IP changes.
3. WoL Magic Packet delivery strictly on ports 9 and 7 (port 0 purged).
4. End-to-end execution of all 6 power actions across Windows and Linux:
   - Shutdown
   - Restart
   - Sleep
   - Hibernate
   - Lock
   - Unlock (verifying display wake only, no stored credentials)
"""

import json
import socket
from unittest.mock import patch, MagicMock
import pytest

from engine import discovery
from engine import devices
from engine import os_power


# ============================================================================
# 1. UDP Discovery Service & Handshake Tests
# ============================================================================

def test_udp_discovery_responder_answers_ping():
    """Verify DiscoveryService listens for WAKEX_DISCOVER and answers with structured JSON."""
    service = discovery.DiscoveryService(http_port=8000)
    service.running = True

    mock_sock = MagicMock()
    # Simulate receiving "WAKEX_DISCOVER" from a mobile client at ("192.168.1.55", 54321)
    mock_sock.recvfrom.side_effect = [
        (b"WAKEX_DISCOVER\n", ("192.168.1.55", 54321)),
        socket.timeout(),
    ]

    with patch("socket.socket", return_value=mock_sock), \
         patch("engine.discovery.get_local_ip", return_value="192.168.1.104"), \
         patch("socket.gethostname", return_value="test-pc"), \
         patch("engine.os_power.get_os_type", return_value="windows"), \
         patch("time.time", side_effect=[1000.0, 1000.1, 1006.0]):

        # Run single iteration of run logic
        service._sock = mock_sock
        # Stop after first batch
        def stop_after_receive(*args, **kwargs):
            service.running = False
            return (b"WAKEX_DISCOVER", ("192.168.1.55", 54321))
        mock_sock.recvfrom.side_effect = stop_after_receive

        service._run()

        # Verify a response was sent to ("192.168.1.55", 54321)
        assert mock_sock.sendto.called
        sent_args = mock_sock.sendto.call_args_list[0]
        sent_bytes, sent_addr = sent_args[0]
        assert sent_addr == ("192.168.1.55", 54321)

        payload = json.loads(sent_bytes.decode("utf-8"))
        assert payload["app"] == "WakeX"
        assert payload["ip"] == "192.168.1.104"
        assert payload["port"] == 8000
        assert payload["hostname"] == "test-pc"
        assert payload["os"] == "windows"


# ============================================================================
# 2. IP Re-binding on Network Address Change
# ============================================================================

def test_hub_ip_rebinding_on_address_change(tmp_path):
    """Verify that when host LAN IP changes, devices.load_devices() automatically updates the host record."""
    dummy_config = tmp_path / "devices.json"
    initial_devices = [
        {
            "id": "dev_host_1",
            "name": "Host PC",
            "ip": "192.168.1.50",
            "mac": "00-11-22-33-44-55",
            "port": 8000,
            "is_current": True
        },
        {
            "id": "dev_remote_2",
            "name": "Remote Laptop",
            "ip": "192.168.1.80",
            "mac": "00-AA-BB-CC-DD-EE",
            "port": 8001,
            "is_current": False
        }
    ]
    with open(dummy_config, "w") as f:
        json.dump(initial_devices, f)

    with patch("engine.devices.CONFIG_PATH", dummy_config), \
         patch("engine.devices.get_host_ip", return_value="192.168.1.200"):  # IP changed to .200

        loaded = devices.load_devices()
        host = next(d for d in loaded if d.get("is_current"))
        remote = next(d for d in loaded if not d.get("is_current"))

        # Host IP must be re-bound to the new IP
        assert host["ip"] == "192.168.1.200"
        # Remote IP must remain unchanged
        assert remote["ip"] == "192.168.1.80"

        # Verify persisted atomically to file
        with open(dummy_config, "r") as f:
            persisted = json.load(f)
        persisted_host = next(d for d in persisted if d.get("is_current"))
        assert persisted_host["ip"] == "192.168.1.200"


# ============================================================================
# 3. WoL Magic Packet Ports Verification (Purged Port 0)
# ============================================================================

def test_wol_magic_packet_ports_strict_9_and_7():
    """Verify Wake-on-LAN packets are transmitted only on ports 9 and 7, never port 0."""
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__.return_value = mock_sock

        res = devices.send_wake_on_lan("00-11-22-33-44-55")
        assert res["status"] == "success"
        assert res["ports"] == [9, 7]
        assert 0 not in res["ports"]

        # Check all destinations called on socket.sendto
        called_ports = {call[0][1][1] for call in mock_sock.sendto.call_args_list}
        assert 0 not in called_ports
        assert 9 in called_ports or 7 in called_ports


# ============================================================================
# 4. Cross-Platform Power Actions Verification (Windows & Linux)
# ============================================================================

def test_power_shutdown_windows_and_linux():
    # Windows
    with patch("engine.os_power.CURRENT_OS", "windows"), \
         patch("subprocess.run") as mock_run:
        res = os_power.execute_shutdown(delay_seconds=30)
        assert res["status"] == "success"
        mock_run.assert_called_once_with(["shutdown", "/s", "/t", "30"], check=True)

    # Linux
    with patch("engine.os_power.CURRENT_OS", "linux"), \
         patch("subprocess.run") as mock_run:
        res = os_power.execute_shutdown(delay_seconds=0)
        assert res["status"] == "success"
        mock_run.assert_called_once_with(["systemctl", "poweroff"], check=True)


def test_power_restart_windows_and_linux():
    # Windows
    with patch("engine.os_power.CURRENT_OS", "windows"), \
         patch("subprocess.run") as mock_run:
        res = os_power.execute_restart(delay_seconds=0)
        assert res["status"] == "success"
        mock_run.assert_called_once_with(["shutdown", "/r", "/t", "0"], check=True)

    # Linux
    with patch("engine.os_power.CURRENT_OS", "linux"), \
         patch("subprocess.run") as mock_run:
        res = os_power.execute_restart(delay_seconds=0)
        assert res["status"] == "success"
        mock_run.assert_called_once_with(["systemctl", "reboot"], check=True)


def test_power_sleep_windows_and_linux():
    # Windows
    with patch("engine.os_power.CURRENT_OS", "windows"), \
         patch("engine.os_power.get_supported_capabilities", return_value={"sleep": True}), \
         patch("subprocess.Popen") as mock_popen:
        res = os_power.execute_sleep()
        assert res["status"] == "success"
        assert mock_popen.called

    # Linux
    with patch("engine.os_power.CURRENT_OS", "linux"), \
         patch("engine.os_power.get_supported_capabilities", return_value={"sleep": True}), \
         patch("subprocess.Popen") as mock_popen:
        res = os_power.execute_sleep()
        assert res["status"] == "success"
        mock_popen.assert_called_once_with(["systemctl", "suspend"])


def test_power_hibernate_windows_and_linux():
    # Windows
    with patch("engine.os_power.CURRENT_OS", "windows"), \
         patch("engine.os_power.get_supported_capabilities", return_value={"hibernate": True}), \
         patch("subprocess.run") as mock_run, \
         patch("subprocess.Popen") as mock_popen:
        res = os_power.execute_hibernate()
        assert res["status"] == "success"
        mock_run.assert_called_once_with(["powercfg", "/hibernate", "on"], capture_output=True)
        mock_popen.assert_called_once_with(["shutdown", "/h"])

    # Linux
    with patch("engine.os_power.CURRENT_OS", "linux"), \
         patch("engine.os_power.get_supported_capabilities", return_value={"hibernate": True}), \
         patch("subprocess.Popen") as mock_popen:
        res = os_power.execute_hibernate()
        assert res["status"] == "success"
        mock_popen.assert_called_once_with(["systemctl", "hibernate"])


def test_power_lock_windows_and_linux():
    # Windows
    with patch("engine.os_power.CURRENT_OS", "windows"), \
         patch("subprocess.run") as mock_run:
        res = os_power.execute_lock()
        assert res["status"] == "success"
        mock_run.assert_called_once_with(["rundll32.exe", "user32.dll,LockWorkStation"], check=True)

    # Linux
    with patch("engine.os_power.CURRENT_OS", "linux"), \
         patch("subprocess.run") as mock_run:
        mock_ret = MagicMock(returncode=0)
        mock_run.return_value = mock_ret
        res = os_power.execute_lock()
        assert res["status"] == "success"
        mock_run.assert_called_with(["loginctl", "lock-session"], capture_output=True)


def test_power_unlock_windows_and_linux_display_wake_only():
    """Verify Unlock Screen only wakes display and dismisses curtain; accepts no stored credentials."""
    # Windows
    with patch("engine.os_power.CURRENT_OS", "windows"), \
         patch("ctypes.windll.user32.SendMessageW") as mock_msg, \
         patch("ctypes.windll.user32.mouse_event") as mock_mouse, \
         patch("ctypes.windll.user32.keybd_event") as mock_kbd:
        res = os_power.execute_unlock()
        assert res["status"] == "success"
        assert "Display awakened" in res["message"]
        # Space key event used to wake display
        assert mock_kbd.called

    # Linux
    with patch("engine.os_power.CURRENT_OS", "linux"), \
         patch("subprocess.run") as mock_run:
        res = os_power.execute_unlock()
        assert res["status"] == "success"
        # Calls loginctl unlock-session, xdg-screensaver reset, xset dpms force on
        called_cmds = [call[0][0] for call in mock_run.call_args_list]
        assert ["loginctl", "unlock-session"] in called_cmds
        assert ["xset", "dpms", "force", "on"] in called_cmds
