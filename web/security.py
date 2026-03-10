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
import jwt as _pyjwt
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────────

_INSECURE_DEFAULT_KEY = "change-this-to-a-random-32-char-secret-key!!"

SECRET_KEY: str = os.getenv("SECRET_KEY", _INSECURE_DEFAULT_KEY)
if SECRET_KEY == _INSECURE_DEFAULT_KEY:
    import sys
    print(
        "[TV1 Reporter] FATAL: SECRET_KEY is set to the insecure default. "
        "Generate a real key with: python3 -c \"import secrets; print(secrets.token_hex(32))\" "
        "and set it in your .env file.",
        file=sys.stderr,
    )
    sys.exit(1)

ALGORITHM: str = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))  # 2 hours

_raw_fernet_key: str = os.getenv("FERNET_KEY", "")
if not _raw_fernet_key:
    import sys
    print(
        "[TV1 Reporter] FATAL: FERNET_KEY is not set. "
        "Generate one with: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\" "
        "and set it in your .env file.",
        file=sys.stderr,
    )
    sys.exit(1)
_fernet = Fernet(_raw_fernet_key.encode())

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
    return _pyjwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    """
    Decode and validate a JWT.  Returns the payload dict or None on failure.
    """
    try:
        payload = _pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") is None:
            return None
        return payload
    except _pyjwt.PyJWTError:
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
