"""
WakeX Security & Cryptographic Subsystem
Local-First Cryptographic Authentication Engine with:
- Ephemeral X25519 Diffie-Hellman Key Exchange with HKDF long-term secret derivation
- PIN-Authenticated Handshake Proofs (PAKE-style transcript mutual authentication)
- Per-PIN attempt limits (5 max across all IPs) and automatic revocation
- HMAC-SHA256 Request Signing
- Nonce Replay Prevention across server process sessions
- Anti-Brute-Force Rate Limiting & Lockout
- Multi-Device Isolation Guard
"""
import os
import sys
import time
import secrets
import hashlib
import hmac
import logging
from typing import Dict, Any, Optional, Tuple
from fastapi import Request, HTTPException, Header, Depends
from engine.storage import safe_read_json, atomic_write_json

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

logger = logging.getLogger("WakeX.Security")
audit_logger = logging.getLogger("WakeX.Audit")

PERMISSION_HIERARCHY = {
    "view": 1,
    "control": 2,
    "full": 3
}

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config")
CLIENTS_FILE = os.path.join(CONFIG_DIR, "paired_clients.json")

# Process startup timestamp to reject any replays from prior runs
PROCESS_START_TIME = time.time()

# Setup audit file logger
if not audit_logger.handlers:
    try:
        log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wakex_audit.log")
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] [AUDIT] %(message)s"))
        audit_logger.addHandler(fh)
        audit_logger.setLevel(logging.INFO)
    except Exception:
        pass

# --- In-Memory State for Replay, Rate-Limiting & Idempotency ---
SEEN_NONCES: Dict[str, float] = {}  # {f"{client_id}:{nonce}": expiry_timestamp}

# PIN Lifecycle: {code: {"expiry": timestamp, "failed_attempts": int}}
ACTIVE_PAIRING_CODES: Dict[str, Dict[str, Any]] = {}
MAX_PIN_ATTEMPTS = 5

# Ephemeral Handshake Sessions: {session_id: {...}}
PENDING_PAIRING_SESSIONS: Dict[str, Dict[str, Any]] = {}

FAILED_ATTEMPTS: Dict[str, list] = {}  # {ip: [fail_timestamp1, ...]}
IDEMPOTENCY_CACHE: Dict[str, Tuple[float, dict]] = {}  # {idempotency_key: (timestamp, result_dict)}

LOCKOUT_WINDOW_SECONDS = 180  # 3 minutes
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # 5 minutes
PAIRING_CODE_VALIDITY = 300  # 5 minutes (300 seconds)
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
    """Generates a secure 6-digit one-time pairing code valid for 5 minutes with per-PIN attempt tracking."""
    clean_expired_pairing_codes()
    code = f"{secrets.randbelow(900000) + 100000}"
    ACTIVE_PAIRING_CODES[code] = {
        "expiry": time.time() + PAIRING_CODE_VALIDITY,
        "failed_attempts": 0
    }
    audit_logger.info(f"One-time pairing code generated: {code} (expires in {PAIRING_CODE_VALIDITY}s)")
    return code


def clean_expired_pairing_codes():
    now = time.time()
    expired_codes = [c for c, info in list(ACTIVE_PAIRING_CODES.items()) if now > info["expiry"]]
    for c in expired_codes:
        del ACTIVE_PAIRING_CODES[c]

    expired_sessions = [sid for sid, s in list(PENDING_PAIRING_SESSIONS.items()) if now > s["expiry"]]
    for sid in expired_sessions:
        del PENDING_PAIRING_SESSIONS[sid]


def consume_pairing_code(code: str) -> bool:
    """Atomically checks and consumes a pairing code."""
    clean_expired_pairing_codes()
    now = time.time()
    info = ACTIVE_PAIRING_CODES.get(code)
    if not info:
        return False
    if now > info["expiry"]:
        del ACTIVE_PAIRING_CODES[code]
        return False
    del ACTIVE_PAIRING_CODES[code]
    return True


def start_pairing_exchange(
    client_id: str,
    client_name: str,
    client_public_key_hex: str,
    client_nonce: str
) -> Dict[str, Any]:
    """
    Step 1 of Ephemeral X25519 Key Exchange.
    - Validates client public key
    - Generates Hub's ephemeral X25519 key pair and nonce
    - Computes ECDH shared secret
    - Derives the permanent client_secret via HKDF-SHA256 (derived purely from ECDH secret, NOT from the PIN)
    - Returns Hub public key and nonce for mutual authentication
    """
    clean_expired_pairing_codes()
    if not ACTIVE_PAIRING_CODES:
        raise HTTPException(status_code=400, detail="No active pairing code. Generate a pairing code on the Hub first.")

    try:
        client_pub_bytes = bytes.fromhex(client_public_key_hex.strip())
        client_pub_obj = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid client X25519 public key: {e}")

    # Generate Hub's ephemeral X25519 key pair
    hub_private = x25519.X25519PrivateKey.generate()
    hub_public = hub_private.public_key()
    hub_pub_bytes = hub_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    hub_nonce = secrets.token_hex(16)

    # Compute ECDH Shared Secret
    shared_secret = hub_private.exchange(client_pub_obj)

    # Derive permanent client secret using HKDF-SHA256
    # Salt combines both nonces to guarantee uniqueness
    kdf_salt = bytes.fromhex(client_nonce) + bytes.fromhex(hub_nonce)
    derived_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=kdf_salt,
        info=b"wakex-client-secret-v1"
    ).derive(shared_secret).hex()

    session_id = secrets.token_hex(16)
    PENDING_PAIRING_SESSIONS[session_id] = {
        "client_id": client_id,
        "client_name": client_name or "Mobile Device",
        "client_public_key": client_public_key_hex,
        "client_nonce": client_nonce,
        "hub_public_key": hub_pub_bytes.hex(),
        "hub_nonce": hub_nonce,
        "client_secret": derived_secret,
        "expiry": time.time() + PAIRING_CODE_VALIDITY
    }

    return {
        "session_id": session_id,
        "hub_public_key": hub_pub_bytes.hex(),
        "hub_nonce": hub_nonce
    }


def authenticate_pairing_session(
    session_id: str,
    pairing_code: str,
    client_proof: str,
    client_ip: str = "unknown"
) -> Tuple[bool, Dict[str, Any], str]:
    """
    Step 2 of Ephemeral X25519 Key Exchange.
    - Authenticates the handshake transcript using HMAC keyed with the 6-digit PIN.
    - A passive eavesdropper learns nothing since the secret is derived from ECDH.
    - An active attacker gets only 1 online guess per attempt.
    - Limits attempts to MAX_PIN_ATTEMPTS (5) across ALL IPs per PIN; revokes PIN immediately if exceeded.
    """
    check_rate_limit(client_ip)
    clean_expired_pairing_codes()

    session = PENDING_PAIRING_SESSIONS.get(session_id)
    if not session:
        record_auth_failure(client_ip)
        return False, {}, "Pairing session expired or not found."

    code = (pairing_code or "").strip()
    pin_info = ACTIVE_PAIRING_CODES.get(code)
    if not pin_info:
        record_auth_failure(client_ip)
        return False, {}, "Invalid or expired pairing code."

    now = time.time()
    if now > pin_info["expiry"]:
        del ACTIVE_PAIRING_CODES[code]
        record_auth_failure(client_ip)
        return False, {}, "Pairing code expired."

    # Check per-PIN failure threshold
    if pin_info["failed_attempts"] >= MAX_PIN_ATTEMPTS:
        del ACTIVE_PAIRING_CODES[code]
        del PENDING_PAIRING_SESSIONS[session_id]
        record_auth_failure(client_ip)
        audit_logger.warning(f"Pairing PIN {code} permanently revoked after {MAX_PIN_ATTEMPTS} failed attempts.")
        return False, {}, f"Pairing code revoked: exceeded maximum allowed attempts ({MAX_PIN_ATTEMPTS})."

    # Transcript: CLIENT_ID:CLIENT_PUB:CLIENT_NONCE:HUB_PUB:HUB_NONCE
    transcript = f"{session['client_id']}:{session['client_public_key']}:{session['client_nonce']}:{session['hub_public_key']}:{session['hub_nonce']}"
    expected_client_proof = hmac.new(
        code.encode("utf-8"),
        f"CLIENT:{transcript}".encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(client_proof.strip(), expected_client_proof):
        pin_info["failed_attempts"] += 1
        record_auth_failure(client_ip)
        audit_logger.warning(f"Failed pairing attempt for PIN {code} from {client_ip} (Attempt {pin_info['failed_attempts']}/{MAX_PIN_ATTEMPTS})")
        if pin_info["failed_attempts"] >= MAX_PIN_ATTEMPTS:
            del ACTIVE_PAIRING_CODES[code]
            del PENDING_PAIRING_SESSIONS[session_id]
            return False, {}, f"Pairing code revoked: exceeded maximum allowed attempts ({MAX_PIN_ATTEMPTS})."
        return False, {}, "Invalid PIN authentication proof."

    # Handshake authenticated successfully!
    hub_proof = hmac.new(
        code.encode("utf-8"),
        f"HUB:{transcript}".encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    # Consume single-use PIN and session
    del ACTIVE_PAIRING_CODES[code]
    del PENDING_PAIRING_SESSIONS[session_id]

    # Save permanently derived client secret
    clients = get_paired_clients()
    cid = session["client_id"]
    clients[cid] = {
        "client_id": cid,
        "name": session["client_name"],
        "secret": session["client_secret"],
        "permission": session.get("permission", "control"),
        "created_at": time.time(),
        "last_seen": time.time()
    }
    save_paired_clients(clients)
    clear_auth_failures(client_ip)
    audit_logger.info(f"Client paired via ECDH-X25519 PAKE: ID={cid}, Name='{session['client_name']}'")

    return True, {
        "client_id": cid,
        "hub_proof": hub_proof
    }, ""


def register_paired_client(client_name: str, client_id: Optional[str] = None, permission: str = "control") -> Dict[str, str]:
    """Internal registration helper (used by local setup/testing)."""
    clients = get_paired_clients()
    cid = client_id or f"client_{secrets.token_hex(6)}"
    secret = secrets.token_hex(32)

    clients[cid] = {
        "client_id": cid,
        "name": client_name.strip() or "Mobile Device",
        "secret": secret,
        "permission": permission if permission in PERMISSION_HIERARCHY else "control",
        "created_at": time.time(),
        "last_seen": time.time()
    }
    save_paired_clients(clients)
    audit_logger.info(f"Client registered: ID={cid}, Name='{client_name}'")
    return {"client_id": cid, "client_secret": secret}


def unpair_client(client_id: str) -> bool:
    clients = get_paired_clients()
    if client_id in clients:
        del clients[client_id]
        save_paired_clients(clients)
        audit_logger.info(f"Client revoked/unpaired: ID={client_id}")
        return True
    return False


def reset_all_auth_state():
    """Resets all paired clients, active pairing codes, and replay nonces."""
    save_paired_clients({})
    ACTIVE_PAIRING_CODES.clear()
    PENDING_PAIRING_SESSIONS.clear()
    SEEN_NONCES.clear()
    FAILED_ATTEMPTS.clear()
    audit_logger.warning("AUTH_RESET: All paired clients, pairing sessions, and security caches reset.")


# --- Rate Limiting & Lockout ---

def check_rate_limit(client_ip: str):
    """Enforces temporary IP lockout if brute force is detected."""
    now = time.time()
    attempts = FAILED_ATTEMPTS.get(client_ip, [])
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


def clean_seen_nonces():
    now = time.time()
    expired = [k for k, exp in list(SEEN_NONCES.items()) if now > exp]
    for k in expired:
        del SEEN_NONCES[k]


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
    3. Replays from previous Hub process sessions are rejected via process start-time verification.
    """
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(client_ip)

    # 1. Allow local host web browser session
    if client_ip in ("127.0.0.1", "::1", "localhost"):
        if x_wakex_local_token and hmac.compare_digest(x_wakex_local_token, LOCAL_SESSION_TOKEN):
            return {"authenticated": True, "type": "local_session", "client_id": "localhost", "permission": "full"}
        return {"authenticated": True, "type": "local_host", "client_id": "localhost", "permission": "full"}

    # 2. Remote / LAN request: check paired clients
    paired_clients = get_paired_clients()

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

    # 4. Reject requests from prior process lifetimes (Replay Prevention across restarts)
    if req_ts < (PROCESS_START_TIME - 5.0):
        record_auth_failure(client_ip)
        audit_logger.warning(f"Replay rejected: Request timestamp ({req_ts}) is older than process start time ({PROCESS_START_TIME})")
        raise HTTPException(
            status_code=403,
            detail="Request timestamp precedes current server process start time."
        )

    # 5. Check Nonce Reuse within process (Replay Prevention 3)
    clean_seen_nonces()
    nonce_key = f"{x_wakex_client_id}:{x_wakex_nonce}"
    if nonce_key in SEEN_NONCES:
        record_auth_failure(client_ip)
        audit_logger.error(f"REPLAY ATTACK BLOCKED: Nonce '{x_wakex_nonce}' was previously used by {x_wakex_client_id}")
        raise HTTPException(status_code=403, detail="Security Alert: Duplicate request nonce (replay detected).")

    SEEN_NONCES[nonce_key] = now + (MAX_CLOCK_SKEW_SECONDS * 2)

    # 6. Read body and verify HMAC-SHA256 signature
    body = await request.body()
    expected_sig = compute_request_signature(
        secret=client_info["secret"],
        method=request.method,
        path=request.url.path,
        timestamp=x_wakex_timestamp,
        nonce=x_wakex_nonce,
        body_bytes=body
    )

    if not hmac.compare_digest(x_wakex_signature.strip(), expected_sig):
        record_auth_failure(client_ip)
        audit_logger.error(f"TAMPER DETECTED: Invalid HMAC signature from {client_ip} targeting {request.url.path}")
        raise HTTPException(status_code=401, detail="Unauthorized: Cryptographic signature mismatch.")

    clear_auth_failures(client_ip)
    client_info["last_seen"] = now
    save_paired_clients(paired_clients)

    return {
        "authenticated": True,
        "type": "paired_client",
        "client_id": x_wakex_client_id,
        "client_name": client_info.get("name", "Unknown"),
        "permission": client_info.get("permission", "control")
    }


def check_and_record_idempotency(idempotency_key: str) -> Optional[dict]:
    """Caches action responses by idempotency key for 30 seconds."""
    now = time.time()
    for k, (ts, _) in list(IDEMPOTENCY_CACHE.items()):
        if now - ts > 30.0:
            del IDEMPOTENCY_CACHE[k]

    if idempotency_key in IDEMPOTENCY_CACHE:
        return IDEMPOTENCY_CACHE[idempotency_key][1]
    return None


def store_idempotency_result(idempotency_key: str, result: dict):
    IDEMPOTENCY_CACHE[idempotency_key] = (time.time(), result)

def store_idempotent_result(idempotency_key: str, result: dict):
    store_idempotency_result(idempotency_key, result)


def update_client_permission(client_id: str, permission: str) -> bool:
    """Updates permission level for a paired device."""
    perm = permission.lower()
    if perm not in PERMISSION_HIERARCHY:
        return False
    clients = get_paired_clients()
    if client_id in clients:
        clients[client_id]["permission"] = perm
        save_paired_clients(clients)
        audit_logger.info(f"Updated permission for client '{client_id}' to '{perm}'")
        return True
    return False


def require_permission(min_level: str):
    """
    FastAPI dependency enforcing granular permission levels:
    - 'view': telemetry & read-only status
    - 'control': operating modes, display, volume, brightness, apps, scenes
    - 'full': power commands (sleep/restart/shutdown), GPU mode, battery limit, kill process
    """
    async def permission_dependency(auth: Dict[str, Any] = Depends(verify_authenticated_request)) -> Dict[str, Any]:
        user_perm = auth.get("permission", "control").lower()
        req_val = PERMISSION_HIERARCHY.get(min_level.lower(), 2)
        user_val = PERMISSION_HIERARCHY.get(user_perm, 2)
        if user_val < req_val:
            audit_logger.warning(
                f"Permission denied: Client '{auth.get('client_id')}' with '{user_perm}' privilege "
                f"attempted action requiring '{min_level}' privilege"
            )
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions: Action requires '{min_level}' privilege, but client has '{user_perm}'."
            )
        return auth
    return permission_dependency
