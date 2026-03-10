"""
Security utilities:
- Password hashing with bcrypt
- JWT creation and verification
- Fernet symmetric encryption for API keys
- CSRF token generation and validation
"""

import os
from datetime import datetime, timedelta, timezone

import bcrypt
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from jose import JWTError, jwt

load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────────

SECRET_KEY: str = os.getenv("SECRET_KEY", "change-this-to-a-random-32-char-secret-key!!")
ALGORITHM: str = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))  # 8 hours

_raw_fernet_key: str = os.getenv("FERNET_KEY", "")
if _raw_fernet_key:
    _fernet = Fernet(_raw_fernet_key.encode())
else:
    # Generate a key at runtime if not configured — keys won't survive restarts without .env
    _generated_key = Fernet.generate_key()
    _fernet = Fernet(_generated_key)

# ── Password hashing ──────────────────────────────────────────────────────────

def hash_password(plain_password: str) -> str:
    """Return a bcrypt hash of the given password."""
    return bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return True if the plain password matches the stored hash."""
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())


# ── JWT ───────────────────────────────────────────────────────────────────────

def create_access_token(subject: str, is_admin: bool = False) -> str:
    """Create a signed JWT with the given subject (username)."""
    expire = datetime.now(tz=timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": subject,
        "exp": expire,
        "is_admin": is_admin,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    """
    Decode and validate a JWT.  Returns the payload dict or None on failure.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") is None:
            return None
        return payload
    except JWTError:
        return None


# ── Fernet encryption for API keys ────────────────────────────────────────────

def encrypt_api_key(plain_key: str) -> str:
    """Encrypt an API key string and return the base64-encoded ciphertext."""
    return _fernet.encrypt(plain_key.encode()).decode()


def decrypt_api_key(encrypted_key: str) -> str:
    """Decrypt a Fernet-encrypted API key and return the plaintext string."""
    return _fernet.decrypt(encrypted_key.encode()).decode()


# ── CSRF tokens ───────────────────────────────────────────────────────────────

import hmac
import hashlib
import secrets


def generate_csrf_token() -> str:
    """Generate a cryptographically random CSRF token."""
    return secrets.token_urlsafe(32)


def verify_csrf_token(form_token: str | None, cookie_token: str | None) -> bool:
    """
    Validate CSRF using the double-submit cookie pattern.
    Both tokens must be present and equal (compared in constant time).
    """
    if not form_token or not cookie_token:
        return False
    return hmac.compare_digest(form_token, cookie_token)
