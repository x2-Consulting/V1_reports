"""
Audit logging helpers.

Usage:
    from audit import audit_log
    audit_log(db, request, actor="alice", event="user.create", target="user:bob")
"""

from __future__ import annotations

import logging
from fastapi import Request
from sqlalchemy.orm import Session

from models import AuditLog

_log = logging.getLogger("tv1.audit")


def audit_log(
    db: Session,
    request: Request | None,
    actor: str,
    event: str,
    target: str | None = None,
    detail: str | None = None,
    organisation_id: int | None = None,
) -> None:
    """Write one audit record to the database and the application log."""
    ip = None
    if request:
        # Honour X-Forwarded-For when behind a trusted reverse proxy
        forwarded = request.headers.get("x-forwarded-for")
        ip = forwarded.split(",")[0].strip() if forwarded else request.client.host if request.client else None

    entry = AuditLog(
        actor=actor,
        event=event,
        target=target,
        detail=detail,
        ip_address=ip,
        organisation_id=organisation_id,
    )
    db.add(entry)
    db.commit()
    _log.info("AUDIT actor=%s event=%s target=%s ip=%s detail=%s",
              actor, event, target, ip, detail)
