"""
FastAPI dependency injection helpers.
"""

from typing import Generator, Optional

from fastapi import Cookie, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from database import get_db
from models import User
from security import decode_access_token, generate_csrf_token, verify_csrf_token


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
        # Raise an HTTPException that will be caught and turned into a redirect
        # by the route; or use a redirect directly.
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": "/login"},
        )
    return user


def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure the current user is an admin."""
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user


# ── CSRF ─────────────────────────────────────────────────────────────────────

def get_csrf_token(request: Request) -> str:
    """
    Return the CSRF token from the cookie, generating a new one if absent.
    The token is attached to request.state so the response can set the cookie.
    """
    token = request.cookies.get("csrf_token")
    if not token:
        token = generate_csrf_token()
    request.state.csrf_token = token
    return token


def validate_csrf(request: Request) -> None:
    """
    Dependency that validates the CSRF double-submit on POST/PUT/DELETE.
    Must be called only from form-handling routes.
    """
    # This is called inside route handlers after form data is parsed,
    # so we use a synchronous approach: read from request.state set by middleware
    # or from the cookie. Actual validation happens in each route handler
    # via validate_csrf_form() helper below.
    pass


def validate_csrf_form(form_token: str | None, cookie_token: str | None) -> None:
    """Raise 403 if the CSRF tokens don't match."""
    if not verify_csrf_token(form_token, cookie_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing CSRF token",
        )
