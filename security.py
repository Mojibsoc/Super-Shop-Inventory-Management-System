import os
import re
import hmac
import hashlib
import secrets
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
SECRET_KEY_FILE = os.path.join(DATA_DIR, ".secret.key")
AUDIT_LOG_FILE = os.path.join(DATA_DIR, "audit.log")

def get_or_create_secret_key() -> bytes:
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, "rb") as f:
            return f.read()
    key = secrets.token_bytes(32)
    with open(SECRET_KEY_FILE, "wb") as f:
        f.write(key)
    return key

SECRET_KEY = get_or_create_secret_key()

def hash_password(password: str) -> str:
    """Hashes a password using PBKDF2-HMAC-SHA256 with a 16-byte cryptographic salt."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 260000)
    return f"pbkdf2_sha256$260000${salt.hex()}${dk.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies a password in constant time to prevent timing attacks."""
    try:
        algo, iterations, salt_hex, hash_hex = stored_hash.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False

def validate_password_strength(password: str) -> tuple[bool, str]:
    """Enforces strong enterprise password policies."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, "Strong password."

def sanitize_input(text: str, max_len: int = 100) -> str:
    """Strips dangerous characters to prevent XSS and log injection."""
    if not isinstance(text, str):
        return ""
    cleaned = re.sub(r'[<>"\';\r\n`]', "", text.strip())
    return cleaned[:max_len]

def generate_csrf_token() -> str:
    return secrets.token_hex(32)

def verify_csrf_token(session_token: str, form_token: str) -> bool:
    if not session_token or not form_token:
        return False
    return hmac.compare_digest(session_token, form_token)

def log_audit(username: str, action: str, details: str = "", ip: str = "127.0.0.1"):
    """Writes a cryptographically signed (HMAC-SHA256) audit log entry to prevent log tampering."""
    os.makedirs(DATA_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    clean_user = sanitize_input(username, 32)
    clean_action = sanitize_input(action, 50)
    clean_details = sanitize_input(details, 200)
    raw_msg = f"{ts} | IP:{ip} | USER:{clean_user} | ACTION:{clean_action} | {clean_details}"
    signature = hmac.new(SECRET_KEY, raw_msg.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
    entry = f"{raw_msg} | SIG:{signature}\n"
    with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)

def verify_audit_logs() -> list[dict]:
    """Reads audit logs and verifies each line's HMAC signature to detect unauthorized tampering."""
    results = []
    if not os.path.exists(AUDIT_LOG_FILE):
        return results
    with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if " | SIG:" in line:
                raw_msg, sig = line.rsplit(" | SIG:", 1)
                expected_sig = hmac.new(SECRET_KEY, raw_msg.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
                valid = hmac.compare_digest(sig, expected_sig)
                results.append({"entry": raw_msg, "valid": valid})
            else:
                results.append({"entry": line, "valid": False})
    return results[::-1]
