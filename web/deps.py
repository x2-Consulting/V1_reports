"""
FastAPI dependency injection helpers.
"""

from typing import Generator, Optional

from fastapi import Cookie, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from database import get_db
from models import Customer, CustomerPortalUser, Report, User
from security import decode_access_token, decode_portal_token, generate_csrf_token, verify_csrf_token


# ── Database session ──────────────────────────────────────────────────────────

def get_session(db: Session = Depends(get_db)) -> Session:
    return db


# ── Current user ─────────────────────────────────────────────────────────────

def get_current_user_optional(
    request: Request,
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Return the logged-in User or None (does not raise)."""
    token = request.cookies.get("session")
    if not token:
        return None
    payload = decode_access_token(token)
    if payload is None:
        return None
    username: str = payload.get("sub", "")
    if not username:
        return None
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    return user


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """Return the logged-in User or redirect to /login."""
    user = get_current_user_optional(request, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": "/login"},
        )
    return user


def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure the current user is an org admin or superadmin."""
    if not (current_user.is_admin or current_user.is_superadmin):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user


def require_superadmin(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure the current user is a platform superadmin."""
    if not current_user.is_superadmin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superadmin access required")
    return current_user


# ── Organisation-scoped query helpers ────────────────────────────────────────

def org_customer_filter(db: Session, current_user: User):
    """Return a Customer query scoped to the user's organisation."""
    q = db.query(Customer)
    if not current_user.is_superadmin:
        q = q.filter(Customer.organisation_id == current_user.organisation_id)
    return q


def org_report_filter(db: Session, current_user: User):
    """Return a Report query scoped to the user's organisation via Customer."""
    q = db.query(Report)
    if not current_user.is_superadmin:
        q = (
            q.join(Customer, Report.customer_id == Customer.id)
            .filter(Customer.organisation_id == current_user.organisation_id)
        )
    return q


def assert_customer_access(customer: Customer | None, current_user: User) -> Customer:
    """Raise 404 if customer is missing or belongs to a different org."""
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    if not current_user.is_superadmin:
        if customer.organisation_id != current_user.organisation_id:
            raise HTTPException(status_code=404, detail="Customer not found")
    return customer


def assert_report_access(report: Report | None, current_user: User, db: Session) -> Report:
    """Raise 404 if report is missing or belongs to a different org."""
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not current_user.is_superadmin:
        customer = db.query(Customer).filter(Customer.id == report.customer_id).first()
        if not customer or customer.organisation_id != current_user.organisation_id:
            raise HTTPException(status_code=404, detail="Report not found")
    return report


# ── Customer portal user ──────────────────────────────────────────────────────

def get_current_portal_user_optional(
    request: Request,
    db: Session = Depends(get_db),
) -> Optional[CustomerPortalUser]:
    """Return the logged-in portal user or None (does not raise)."""
    token = request.cookies.get("portal_session")
    if not token:
        return None
    payload = decode_portal_token(token)
    if payload is None:
        return None
    try:
        portal_user_id = int(str(payload["sub"]).split(":")[1])
    except (KeyError, ValueError, IndexError):
        return None
    return (
        db.query(CustomerPortalUser)
        .filter(
            CustomerPortalUser.id == portal_user_id,
            CustomerPortalUser.is_active == True,
        )
        .first()
    )


def get_current_portal_user(
    request: Request,
    db: Session = Depends(get_db),
) -> CustomerPortalUser:
    """Return the portal user or redirect to /portal/login."""
    user = get_current_portal_user_optional(request, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": "/portal/login"},
        )
    return user


# ── CSRF ─────────────────────────────────────────────────────────────────────

def get_csrf_token(request: Request) -> str:
    """Return the CSRF token from the cookie, generating a new one if absent."""
    token = request.cookies.get("csrf_token")
    if not token:
        token = generate_csrf_token()
    request.state.csrf_token = token
    return token


def validate_csrf_form(form_token: str | None, cookie_token: str | None) -> None:
    """Raise 403 if the CSRF tokens don't match."""
    if not verify_csrf_token(form_token, cookie_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing CSRF token",
        )
