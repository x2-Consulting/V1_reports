"""
Application settings store — thin wrapper around the AppSetting DB table.

Sensitive settings are Fernet-encrypted at rest (same key as API keys).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from models import AppSetting
from security import encrypt_api_key, decrypt_api_key

# Registry of known settings: key → (description, is_encrypted)
KNOWN_SETTINGS: dict[str, tuple[str, bool]] = {
    "nvd_api_key": (
        "NIST NVD API key for CVE enrichment (https://nvd.nist.gov/developers/request-an-api-key)",
        True,
    ),
    "nvd_sync_status": (
        "Current NVD cache sync status: idle | syncing_full | syncing_incremental | failed",
        False,
    ),
    "nvd_last_full_sync": (
        "ISO datetime of the last successful full NVD sync",
        False,
    ),
    "nvd_last_incremental_sync": (
        "ISO datetime of the last successful incremental NVD sync",
        False,
    ),
    "nvd_total_cached": (
        "Total number of CVEs currently stored in the local cache",
        False,
    ),
    "nvd_sync_progress": (
        "Current sync progress as 'N / TOTAL' (shown during active sync)",
        False,
    ),
    "nvd_sync_error": (
        "Error message from the last failed NVD sync attempt",
        False,
    ),
}


def get_setting(db: Session, key: str) -> str | None:
    """Return the plaintext value of a setting, or None if not set."""
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    if not row or not row.value:
        return None
    if row.is_encrypted:
        try:
            return decrypt_api_key(row.value)
        except Exception:
            return None
    return row.value


def set_setting(db: Session, key: str, value: str) -> None:
    """Upsert a setting. Encrypts if the key is marked sensitive."""
    _, is_encrypted = KNOWN_SETTINGS.get(key, ("", False))
    description = KNOWN_SETTINGS.get(key, ("", False))[0]

    stored_value = encrypt_api_key(value) if (is_encrypted and value) else value

    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    if row:
        row.value = stored_value
        row.updated_at = datetime.now(tz=timezone.utc)
    else:
        row = AppSetting(
            key=key,
            value=stored_value,
            is_encrypted=is_encrypted,
            description=description,
            updated_at=datetime.now(tz=timezone.utc),
        )
        db.add(row)
    db.commit()


def delete_setting(db: Session, key: str) -> None:
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    if row:
        db.delete(row)
        db.commit()
