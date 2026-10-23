"""
WakeX Lightweight Multi-Platform Remote Agent (Linux & Windows)
Runs as a background daemon on secondary computers to receive secure remote power commands.
Hardened with HMAC-SHA256 authentication, anti-replay, anti-brute-force lockout, and idempotency.
"""
import os
import sys
import json
import time
import secrets
import hashlib
import hmac
import logging
import platform
import argparse
import tempfile
import socket
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Tuple, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] WakeX.Agent: %(message)s")
logger = logging.getLogger("WakeX.Agent")

AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(AGENT_DIR, "agent_config.json")
CURRENT_OS = platform.system().lower()

# Security state
FAILED_ATTEMPTS: Dict[str, List[float]] = {}
LOCKOUTS: Dict[str, float] = {}
SEEN_NONCES: Dict[str, float] = {}
IDEMPOTENCY_CACHE: Dict[str, Tuple[float, dict]] = {}

MAX_AUTH_ATTEMPTS = 5
LOCKOUT_DURATION_SEC = 300  # 5 minutes
TIMESTAMP_TOLERANCE_SEC = 60
IDEMPOTENCY_TTL_SEC = 30
ALLOWED_ACTIONS = {"shutdown", "restart", "sleep", "hibernate", "lock", "unlock"}


def get_lan_ip() -> str:
    """Detects active primary LAN interface IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def atomic_write_json(file_path: str, data: Any) -> bool:
    """Atomically writes JSON configuration to prevent corruption."""
    abs_path = os.path.abspath(file_path)
    dir_name = os.path.dirname(abs_path)
    os.makedirs(dir_name, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix="tmp_agent_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, abs_path)
        return True
    except Exception as e:
        logger.error(f"Error saving agent config: {e}")
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        return False


def load_or_create_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading config: {e}")

    # Generate a cryptographically secure device identity and token
    new_token = secrets.token_hex(32)
    device_id = f"dev_{CURRENT_OS}_{secrets.token_hex(4)}"
    config = {
        "device_id": device_id,
        "device_name": platform.node() or f"{CURRENT_OS.capitalize()} PC",
        "device_type": CURRENT_OS,
        "agent_port": 8001,
        "auth_token": new_token,
        "hub_url": "",
        "created_at": time.time()
    }
    atomic_write_json(CONFIG_FILE, config)
    return config


def get_supported_actions() -> List[str]:
    """Inspects OS capabilities and returns list of supported power actions."""
    actions = ["shutdown", "restart"]
    if CURRENT_OS == "linux":
        actions.append("sleep")
        if os.path.exists("/sys/power/state"):
            try:
                with open("/sys/power/state", "r") as f:
                    if "disk" in f.read():
                        actions.append("hibernate")
            except Exception:
                pass
        actions.extend(["lock", "unlock"])
    elif CURRENT_OS == "windows":
        actions.extend(["sleep", "hibernate", "lock", "unlock"])
    return actions


def get_agent_telemetry() -> dict:
    cpu_percent = 0.0
    mem_percent = 0.0
    try:
        import psutil
        cpu_percent = psutil.cpu_percent(interval=None)
        mem_percent = psutil.virtual_memory().percent
    except ImportError:
        # Fallback reading /proc/loadavg or vmstat on Linux
        if CURRENT_OS == "linux" and os.path.exists("/proc/loadavg"):
            try:
                with open("/proc/loadavg", "r") as f:
                    cpu_percent = float(f.read().split()[0]) * 10
            except Exception:
                pass

    return {
        "status": "online",
        "os": CURRENT_OS,
        "hostname": platform.node(),
        "cpu_percent": round(cpu_percent, 1),
        "memory_percent": round(mem_percent, 1),
        "supported_actions": get_supported_actions(),
        "timestamp": time.time()
    }


def execute_agent_power(action: str) -> dict:
    action = action.lower().strip()
    if action not in ALLOWED_ACTIONS:
        return {"status": "error", "message": f"Action '{action}' is not permitted or unknown."}

    logger.info(f"Executing power action '{action}' on local {CURRENT_OS} agent...")

    if action == "shutdown":
        if CURRENT_OS == "linux":
            try:
                subprocess.run(["systemctl", "poweroff"], check=True)
            except Exception:
                subprocess.run(["shutdown", "-h", "now"], check=True)
            return {"status": "success", "message": "Linux poweroff initiated"}
        else:
            subprocess.run(["shutdown", "/s", "/t", "0"], check=True)
            return {"status": "success", "message": "Windows shutdown initiated"}

    elif action == "restart":
        if CURRENT_OS == "linux":
            try:
                subprocess.run(["systemctl", "reboot"], check=True)
            except Exception:
                subprocess.run(["shutdown", "-r", "now"], check=True)
            return {"status": "success", "message": "Linux reboot initiated"}
        else:
            subprocess.run(["shutdown", "/r", "/t", "0"], check=True)
            return {"status": "success", "message": "Windows restart initiated"}

    elif action == "sleep":
        if CURRENT_OS == "linux":
            subprocess.Popen(["systemctl", "suspend"])
            return {"status": "success", "message": "Linux suspend initiated"}
        else:
            subprocess.Popen([
                "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Application]::SetSuspendState([System.Windows.Forms.PowerState]::Suspend, $false, $false)"
            ])
            return {"status": "success", "message": "Windows sleep initiated"}

    elif action == "hibernate":
        if CURRENT_OS == "linux":
            if os.path.exists("/sys/power/state"):
                with open("/sys/power/state", "r") as f:
                    if "disk" not in f.read():
                        return {"status": "unsupported", "message": "Hibernation is not supported on this Linux kernel/swap configuration."}
            subprocess.Popen(["systemctl", "hibernate"])
            return {"status": "success", "message": "Linux hibernation initiated"}
        else:
            subprocess.Popen(["shutdown", "/h"])
            return {"status": "success", "message": "Windows hibernation initiated"}

    elif action == "lock":
        if CURRENT_OS == "linux":
            res = None
            try:
                res = subprocess.run(["loginctl", "lock-session"], capture_output=True)
            except Exception:
                pass
            if not res or res.returncode != 0:
                res = subprocess.run(["xdg-screensaver", "lock"], capture_output=True)
            if res and res.returncode == 0:
                return {"status": "success", "message": "Linux session locked"}
            return {"status": "error", "message": "Could not lock Linux session"}
        else:
            subprocess.run(["rundll32.exe", "user32.dll,LockWorkStation"], check=True)
            return {"status": "success", "message": "Windows workstation locked"}

    elif action == "unlock":
        if CURRENT_OS == "linux":
            for cmd in [["loginctl", "unlock-session"], ["xdg-screensaver", "reset"], ["xset", "dpms", "force", "on"]]:
                try:
                    subprocess.run(cmd, capture_output=True)
                except Exception:
                    pass
            return {"status": "success", "message": "Linux display awakened and session unlocked"}
        else:
            try:
                import ctypes
                ctypes.windll.user32.SendMessageW(0xFFFF, 0x0112, 0xF170, -1)
                ctypes.windll.user32.mouse_event(0x0001, 1, 1, 0, 0)
                time.sleep(0.05)
                ctypes.windll.user32.mouse_event(0x0001, -1, -1, 0, 0)
                ctypes.windll.user32.keybd_event(0x20, 0, 0, 0)
                time.sleep(0.05)
                ctypes.windll.user32.keybd_event(0x20, 0, 2, 0)
                return {"status": "success", "message": "Windows display awakened and lock screen dismissed"}
            except Exception as ex:
                return {"status": "error", "message": str(ex)}

    return {"status": "error", "message": f"Unknown action '{action}'"}


class WakeXAgentHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-WakeX-Signature, X-WakeX-Timestamp, X-WakeX-Nonce")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-WakeX-Signature, X-WakeX-Timestamp, X-WakeX-Nonce")
        self.end_headers()

    def _is_rate_limited(self, client_ip: str) -> bool:
        now = time.time()
        # Check active lockout
        if client_ip in LOCKOUTS:
            if now < LOCKOUTS[client_ip]:
                return True
            else:
                del LOCKOUTS[client_ip]
                FAILED_ATTEMPTS.pop(client_ip, None)
        return False

    def _record_auth_failure(self, client_ip: str):
        now = time.time()
        attempts = FAILED_ATTEMPTS.get(client_ip, [])
        attempts = [t for t in attempts if now - t < LOCKOUT_DURATION_SEC]
        attempts.append(now)
        FAILED_ATTEMPTS[client_ip] = attempts
        if len(attempts) >= MAX_AUTH_ATTEMPTS:
            LOCKOUTS[client_ip] = now + LOCKOUT_DURATION_SEC
            logger.warning(f"Client IP '{client_ip}' locked out for 5 minutes due to {len(attempts)} failed attempts.")

    def _verify_auth(self, config: dict, post_body_bytes: bytes, method: str = "POST") -> Tuple[bool, str]:
        """
        Enforces strict HMAC-SHA256 signature verification over every request.
        Raw token bypass (Mode B) has been completely removed for security.
        """
        client_ip = self.client_address[0]
        if self._is_rate_limited(client_ip):
            return False, "Rate limited. IP temporarily locked out."

        token = config.get("auth_token", "")
        if not token:
            return False, "Agent not configured with auth token."

        sig_header = self.headers.get("X-WakeX-Signature")
        ts_header = self.headers.get("X-WakeX-Timestamp")
        nonce_header = self.headers.get("X-WakeX-Nonce")

        if not sig_header or not ts_header or not nonce_header:
            self._record_auth_failure(client_ip)
            return False, "Authentication required: Missing cryptographic signature headers."

        now = time.time()
        try:
            req_ts = float(ts_header)
        except ValueError:
            self._record_auth_failure(client_ip)
            return False, "Invalid timestamp header"

        if abs(now - req_ts) > TIMESTAMP_TOLERANCE_SEC:
            self._record_auth_failure(client_ip)
            return False, "Request timestamp expired or skewed (>60s)"

        # Replay protection: check nonce
        for n, exp in list(SEEN_NONCES.items()):
            if now > exp:
                del SEEN_NONCES[n]

        if nonce_header in SEEN_NONCES:
            logger.warning(f"Replay attack detected with nonce '{nonce_header}' from {client_ip}")
            return False, "Replay attack detected: Nonce already used"

        SEEN_NONCES[nonce_header] = now + TIMESTAMP_TOLERANCE_SEC

        # Compute expected signature over METHOD:PATH:TIMESTAMP:NONCE:BODY_SHA256
        body_sha256 = hashlib.sha256(post_body_bytes).hexdigest()
        sign_string = f"{method.upper()}:{self.path}:{ts_header}:{nonce_header}:{body_sha256}"
        expected_sig = hmac.new(token.encode("utf-8"), sign_string.encode("utf-8"), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(sig_header.strip(), expected_sig):
            self._record_auth_failure(client_ip)
            return False, "Invalid cryptographic HMAC signature"

        # Auth successful, reset failures
        FAILED_ATTEMPTS.pop(client_ip, None)
        return True, ""

    def do_GET(self):
        config = load_or_create_config()
        if self.path in ("/api/agent/status", "/api/status"):
            auth_ok, auth_err = self._verify_auth(config, b"", method="GET")
            if not auth_ok:
                status_code = 429 if "locked out" in auth_err else 401
                self._send_json(status_code, {"status": "error", "message": auth_err})
                return
            telemetry = get_agent_telemetry()
            telemetry["device_id"] = config["device_id"]
            telemetry["device_name"] = config["device_name"]
            self._send_json(200, telemetry)
        elif self.path == "/api/agent/identity":
            # Returns public discovery metadata (non-destructive)
            self._send_json(200, {
                "device_id": config["device_id"],
                "device_name": config["device_name"],
                "device_type": config["device_type"],
                "agent_port": config["agent_port"],
                "os": CURRENT_OS,
                "supported_actions": get_supported_actions()
            })
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        config = load_or_create_config()
        content_len = int(self.headers.get("Content-Length", 0))
        post_body_bytes = self.rfile.read(content_len) if content_len > 0 else b""

        # Verify authentication
        auth_ok, auth_err = self._verify_auth(config, post_body_bytes, method="POST")
        if not auth_ok:
            status_code = 429 if "locked out" in auth_err else 401
            logger.warning(f"Auth failed from {self.client_address[0]}: {auth_err}")
            self._send_json(status_code, {"status": "error", "message": auth_err})
            return

        if self.path == "/api/agent/power":
            try:
                data = json.loads(post_body_bytes.decode("utf-8"))
            except Exception:
                self._send_json(400, {"status": "error", "message": "Invalid JSON payload"})
                return

            target_id = data.get("target_device_id")
            if target_id and target_id != config["device_id"]:
                logger.error(f"Target device mismatch: received '{target_id}', agent is '{config['device_id']}'")
                self._send_json(403, {
                    "status": "error",
                    "message": f"Target ID mismatch: this agent is '{config['device_id']}', received '{target_id}'"
                })
                return

            action = data.get("action", "").lower().strip()
            if action not in ALLOWED_ACTIONS:
                self._send_json(400, {
                    "status": "error",
                    "message": f"Action '{action}' is not supported. Allowed: {list(ALLOWED_ACTIONS)}"
                })
                return

            # Idempotency check: if nonce provided and already executed within 30s
            nonce = self.headers.get("X-WakeX-Nonce")
            if nonce and nonce in IDEMPOTENCY_CACHE:
                cached_time, cached_res = IDEMPOTENCY_CACHE[nonce]
                if time.time() - cached_time < IDEMPOTENCY_TTL_SEC:
                    logger.info(f"Serving idempotent cached response for nonce '{nonce}'")
                    self._send_json(200, cached_res)
                    return

            res = execute_agent_power(action)
            if nonce:
                IDEMPOTENCY_CACHE[nonce] = (time.time(), res)
            self._send_json(200, res)
        else:
            self._send_json(404, {"error": "Not Found"})

    def log_message(self, format, *args):
        logger.info(f"{self.client_address[0]} - {args[0]}")


def run_agent(host: str = "", port: int = 8001):
    config = load_or_create_config()
    bind_host = host if host else get_lan_ip()
    server_address = (bind_host, port)
    httpd = HTTPServer(server_address, WakeXAgentHandler)
    logger.info(f"WakeX Agent running on {server_address[0]}:{port} (OS: {CURRENT_OS})")
    logger.info(f"Device ID: {config['device_id']}")
    logger.info(f"Device Token: {config['auth_token']}")
    logger.info(f"Supported actions: {get_supported_actions()}")
    logger.info("Ready to accept authenticated remote power commands from WakeX Hub.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Agent stopped by user.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WakeX Multi-Platform Remote Agent")
    parser.add_argument("--host", type=str, default="", help="Host/IP interface to bind on (default: auto-detected LAN IP)")
    parser.add_argument("--port", type=int, default=8001, help="Port to listen on (default: 8001)")
    parser.add_argument("--pair", action="store_true", help="Print pairing details and token")
    args = parser.parse_args()

    cfg = load_or_create_config()
    if args.pair:
        print("\n" + "="*50)
        print("          WakeX Device Pairing Token")
        print("="*50)
        print(f"Device ID:    {cfg['device_id']}")
        print(f"Device Name:  {cfg['device_name']}")
        print(f"Device Token: {cfg['auth_token']}")
        print(f"Agent Port:   {cfg['agent_port']}")
        print(f"Supported:    {', '.join(get_supported_actions())}")
        print("="*50)
        print("Copy the Token above into WakeX Hub to securely pair this PC.\n")
        sys.exit(0)

    run_agent(args.host, args.port)
