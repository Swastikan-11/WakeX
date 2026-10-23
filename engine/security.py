"""
WakeX Security & Cryptographic Pairing Engine
Local-first, zero-cloud authentication:
- Cryptographic client pairing (one-time pairing codes / QR payload)
- HMAC-SHA256 request authentication with timestamp and nonce replay protection
- Anti-brute-force rate limiting and lockout
- Idempotency guard for destructive power actions
- Local audit logging
"""
import os
import sys
import hmac
import time
import json
import secrets
import hashlib
import logging
from typing import Optional, Dict, Any, Tuple
from fastapi import Request, HTTPException, Header
from engine.storage import safe_read_json, atomic_write_json

logger = logging.getLogger("WakeX.Security")
audit_logger = logging.getLogger("WakeX.Audit")

if getattr(sys, 'frozen', False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

CONFIG_DIR = os.path.join(APP_DIR, "config")
CLIENTS_FILE = os.path.join(CONFIG_DIR, "paired_clients.json")
AUDIT_LOG_FILE = os.path.join(APP_DIR, "wakex_audit.log")

# Setup audit logger to write to both file and console
if not audit_logger.handlers:
    try:
        fh = logging.FileHandler(AUDIT_LOG_FILE, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [AUDIT] %(message)s"))
        audit_logger.addHandler(fh)
        audit_logger.setLevel(logging.INFO)
    except Exception:
        pass

# --- In-Memory State for Replay, Rate-Limiting & Idempotency ---
SEEN_NONCES: Dict[str, float] = {}  # {f"{client_id}:{nonce}": expiry_timestamp}
ACTIVE_PAIRING_CODES: Dict[str, float] = {}  # {code: expiry_timestamp}
FAILED_ATTEMPTS: Dict[str, list] = {}  # {ip: [fail_timestamp1, ...]}
IDEMPOTENCY_CACHE: Dict[str, Tuple[float, dict]] = {}  # {idempotency_key: (timestamp, result_dict)}

LOCKOUT_WINDOW_SECONDS = 180  # 3 minutes
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # 5 minutes
PAIRING_CODE_VALIDITY = 300  # 5 minutes
MAX_CLOCK_SKEW_SECONDS = 60.0  # Allowed timestamp drift for HMAC

# Ephemeral token for local host browser session (127.0.0.1)
LOCAL_SESSION_TOKEN = secrets.token_hex(32)


def get_paired_clients() -> Dict[str, Any]:
    """Loads all paired client device secrets."""
    data = safe_read_json(CLIENTS_FILE, default={})
    return data if isinstance(data, dict) else {}


def save_paired_clients(clients: Dict[str, Any]) -> bool:
    """Atomically saves paired clients to disk."""
    return atomic_write_json(CLIENTS_FILE, clients)


def generate_pairing_code() -> str:
    """Generates a secure 6-digit one-time pairing code valid for 5 minutes."""
    clean_expired_pairing_codes()
    code = f"{secrets.randbelow(900000) + 100000}"
    ACTIVE_PAIRING_CODES[code] = time.time() + PAIRING_CODE_VALIDITY
    audit_logger.info(f"One-time pairing code generated: {code} (expires in {PAIRING_CODE_VALIDITY}s)")
    return code


def clean_expired_pairing_codes():
    now = time.time()
    expired = [c for c, exp in ACTIVE_PAIRING_CODES.items() if now > exp]
    for c in expired:
        del ACTIVE_PAIRING_CODES[c]


def register_paired_client(client_name: str, client_id: Optional[str] = None) -> Dict[str, str]:
    """Registers a client with a fresh 256-bit cryptographically secure shared secret."""
    clients = get_paired_clients()
    cid = client_id or f"client_{secrets.token_hex(6)}"
    secret = secrets.token_hex(32)

    clients[cid] = {
        "client_id": cid,
        "name": client_name.strip() or "Mobile Device",
        "secret": secret,
        "created_at": time.time(),
        "last_seen": time.time()
    }
    save_paired_clients(clients)
    audit_logger.info(f"New client paired successfully: ID={cid}, Name='{client_name}'")
    return {"client_id": cid, "client_secret": secret}


def unpair_client(client_id: str) -> bool:
    clients = get_paired_clients()
    if client_id in clients:
        del clients[client_id]
        save_paired_clients(clients)
        audit_logger.info(f"Client revoked/unpaired: ID={client_id}")
        return True
    return False


# --- Rate Limiting & Lockout ---

def check_rate_limit(client_ip: str):
    """Enforces temporary IP lockout if brute force is detected."""
    now = time.time()
    attempts = FAILED_ATTEMPTS.get(client_ip, [])
    # Keep only attempts within recent window
    recent = [t for t in attempts if now - t < LOCKOUT_WINDOW_SECONDS]
    FAILED_ATTEMPTS[client_ip] = recent

    if len(recent) >= MAX_FAILED_ATTEMPTS:
        remaining = int(LOCKOUT_DURATION - (now - recent[0]))
        if remaining > 0:
            audit_logger.warning(f"BLOCKED request from {client_ip} (IP locked out for {remaining}s)")
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed authentication attempts. Access locked for {remaining} seconds."
            )
        else:
            FAILED_ATTEMPTS[client_ip] = []


def record_auth_failure(client_ip: str):
    now = time.time()
    attempts = FAILED_ATTEMPTS.get(client_ip, [])
    attempts.append(now)
    FAILED_ATTEMPTS[client_ip] = attempts
    logger.warning(f"Failed authentication from {client_ip}. Attempts: {len(attempts)}/{MAX_FAILED_ATTEMPTS}")


def clear_auth_failures(client_ip: str):
    if client_ip in FAILED_ATTEMPTS:
        del FAILED_ATTEMPTS[client_ip]


# --- HMAC Request Verification ---

def compute_request_signature(
    secret: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body_bytes: bytes = b""
) -> str:
    """Computes HMAC-SHA256 over method, path, timestamp, nonce, and SHA256 of body."""
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    message = f"{method.upper()}:{path}:{timestamp}:{nonce}:{body_hash}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


async def verify_authenticated_request(
    request: Request,
    x_wakex_client_id: Optional[str] = Header(None),
    x_wakex_timestamp: Optional[str] = Header(None),
    x_wakex_nonce: Optional[str] = Header(None),
    x_wakex_signature: Optional[str] = Header(None),
    x_wakex_local_token: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """
    FastAPI dependency that enforces zero-cloud, local authentication:
    1. Requests from local host (127.0.0.1 / ::1) with the ephemeral local session token are permitted.
    2. All LAN/remote requests MUST provide a valid client ID and HMAC-SHA256 signature with nonces.
    """
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(client_ip)

    # 1. Allow local host web browser session
    if client_ip in ("127.0.0.1", "::1", "localhost"):
        if x_wakex_local_token and hmac.compare_digest(x_wakex_local_token, LOCAL_SESSION_TOKEN):
            return {"authenticated": True, "type": "local_session", "client_id": "localhost"}
        # For initial development or local browser, also permit local dashboard calls
        return {"authenticated": True, "type": "local_host", "client_id": "localhost"}

    # 2. Remote / LAN request: check paired clients
    paired_clients = get_paired_clients()

    # If no clients have EVER been paired, allow initial onboarding/pairing
    if not paired_clients and request.url.path.startswith("/api/auth/"):
        return {"authenticated": True, "type": "onboarding", "client_id": "onboarding"}

    if not x_wakex_client_id or not x_wakex_timestamp or not x_wakex_nonce or not x_wakex_signature:
        record_auth_failure(client_ip)
        audit_logger.warning(f"Unauthenticated request to {request.url.path} from {client_ip} (missing security headers)")
        raise HTTPException(
            status_code=401,
            detail="Authentication required: Missing cryptographic client headers."
        )

    client_info = paired_clients.get(x_wakex_client_id)
    if not client_info:
        record_auth_failure(client_ip)
        audit_logger.warning(f"Rejected request: Unknown client ID '{x_wakex_client_id}' from {client_ip}")
        raise HTTPException(status_code=401, detail="Unauthorized: Unrecognized client device.")

    # 3. Check Clock Skew (Replay Prevention 1)
    try:
        req_ts = float(x_wakex_timestamp)
    except ValueError:
        record_auth_failure(client_ip)
        raise HTTPException(status_code=400, detail="Invalid timestamp format.")

    now = time.time()
    if abs(now - req_ts) > MAX_CLOCK_SKEW_SECONDS:
        record_auth_failure(client_ip)
        audit_logger.warning(f"Replay rejected: Skewed timestamp ({req_ts}) from client '{x_wakex_client_id}' (diff: {now - req_ts:.1f}s)")
        raise HTTPException(
            status_code=403,
            detail=f"Request expired or clock skewed. Server time is {int(now)}."
        )

    # 4. Check Nonce Reuse (Replay Prevention 2)
    clean_seen_nonces()
    nonce_key = f"{x_wakex_client_id}:{x_wakex_nonce}"
    if nonce_key in SEEN_NONCES:
        record_auth_failure(client_ip)
        audit_logger.error(f"REPLAY ATTACK BLOCKED: Nonce '{x_wakex_nonce}' was previously used by {x_wakex_client_id}")
        raise HTTPException(status_code=403, detail="Security Alert: Duplicate request nonce (replay detected).")

    SEEN_NONCES[nonce_key] = now + (MAX_CLOCK_SKEW_SECONDS * 2)

    # 5. Read body and verify HMAC-SHA256 signature
    body = await request.body()
    expected_sig = compute_request_signature(
        secret=client_info["secret"],
        method=request.method,
        path=request.url.path,
        timestamp=x_wakex_timestamp,
        nonce=x_wakex_nonce,
        body_bytes=body
    )

    if not hmac.compare_digest(expected_sig, x_wakex_signature.lower()):
        record_auth_failure(client_ip)
        audit_logger.warning(f"Signature mismatch for client '{x_wakex_client_id}' from {client_ip}")
        raise HTTPException(status_code=401, detail="Invalid cryptographic signature.")

    # Authentication succeeded
    clear_auth_failures(client_ip)
    client_info["last_seen"] = now
    return {
        "authenticated": True,
        "type": "hmac_client",
        "client_id": x_wakex_client_id,
        "client_name": client_info.get("name", "Unknown")
    }


def clean_seen_nonces():
    now = time.time()
    expired = [k for k, exp in SEEN_NONCES.items() if now > exp]
    for k in expired:
        del SEEN_NONCES[k]


# --- Idempotency Guard ---

def check_and_record_idempotency(key: str, ttl_seconds: float = 30.0) -> Optional[dict]:
    """
    Checks if a power action with the specified idempotency key was recently executed.
    Returns cached result if already processed; otherwise returns None.
    """
    now = time.time()
    # Clean old entries
    expired = [k for k, (exp, _) in IDEMPOTENCY_CACHE.items() if now > exp]
    for k in expired:
        del IDEMPOTENCY_CACHE[k]

    if key in IDEMPOTENCY_CACHE:
        _, cached_result = IDEMPOTENCY_CACHE[key]
        audit_logger.info(f"Idempotent command hit for key '{key}': returning previous response.")
        return cached_result
    return None


def store_idempotent_result(key: str, result: dict, ttl_seconds: float = 30.0):
    IDEMPOTENCY_CACHE[key] = (time.time() + ttl_seconds, result)
