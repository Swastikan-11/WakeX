"""
WakeX LAN Auto-Discovery Service
Runs a lightweight UDP broadcast and responder daemon on port 8002:
1. Responds to "WAKEX_DISCOVER" broadcast requests from mobile devices.
2. Periodically emits a local beacon announcing the Hub IP and service port.
Enables instant (~50ms) discovery on local Wi-Fi without slow subnet scans.
"""
import os
import sys
import json
import time
import socket
import logging
import threading
from engine import os_power

logger = logging.getLogger("WakeX.Discovery")

DISCOVERY_PORT = 8002
BEACON_INTERVAL_SECONDS = 5.0


def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


class DiscoveryService:
    def __init__(self, http_port: int = 8000):
        self.http_port = http_port
        self.running = False
        self._thread = None
        self._sock = None

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="WakeX-Discovery")
        self._thread.start()
        logger.info(f"Discovery responder started on UDP port {DISCOVERY_PORT}")

    def stop(self):
        self.running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def _run(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self._sock.bind(("", DISCOVERY_PORT))
            self._sock.settimeout(2.0)
        except Exception as e:
            logger.warning(f"Could not bind discovery socket on port {DISCOVERY_PORT}: {e}")
            return

        last_beacon = 0
        while self.running:
            now = time.time()
            local_ip = get_local_ip()

            # 1. Listen for incoming "WAKEX_DISCOVER" pings
            try:
                data, addr = self._sock.recvfrom(1024)
                msg = data.decode("utf-8", errors="ignore").strip()
                if "WAKEX_DISCOVER" in msg:
                    resp_payload = json.dumps({
                        "app": "WakeX",
                        "ip": local_ip,
                        "port": self.http_port,
                        "hostname": socket.gethostname(),
                        "os": os_power.get_os_type(),
                        "timestamp": int(now)
                    }).encode("utf-8")
                    self._sock.sendto(resp_payload, addr)
                    logger.debug(f"Discovery ping answered to {addr[0]}")
            except socket.timeout:
                pass
            except Exception as e:
                if self.running:
                    logger.debug(f"Discovery listen error: {e}")

            # 2. Emit periodic beacon to LAN broadcast
            if now - last_beacon >= BEACON_INTERVAL_SECONDS:
                last_beacon = now
                try:
                    beacon_data = json.dumps({
                        "app": "WakeX",
                        "ip": local_ip,
                        "port": self.http_port,
                        "hostname": socket.gethostname(),
                        "os": os_power.get_os_type()
                    }).encode("utf-8")
                    # Send to 255.255.255.255
                    self._sock.sendto(beacon_data, ("255.255.255.255", DISCOVERY_PORT))
                except Exception:
                    pass

        try:
            self._sock.close()
        except Exception:
            pass


discovery_service = DiscoveryService()
