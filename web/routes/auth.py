"""
Authentication routes: login, logout.
"""

import os

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from database import get_db
from deps import get_csrf_token, get_current_user_optional, validate_csrf_form
from models import User
from security import create_access_token, verify_password

from templating import templates

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

_SECURE_COOKIES: bool = os.getenv("HTTPS_ENABLED", "false").lower() == "true"


def _set_flash(response: Response, message: str, category: str = "info") -> None:
    """Encode a flash message as a signed cookie."""
    import json
    from itsdangerous import URLSafeSerializer
    import os
    secret = os.getenv("SECRET_KEY")
    s = URLSafeSerializer(secret, salt="flash")
    encoded = s.dumps({"message": message, "category": category})
    response.set_cookie("flash", encoded, httponly=True, samesite="lax", max_age=60)


@router.get("/login", response_class=HTMLResponse)
async def login_get(
    request: Request,
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    """Show the login form. Redirect to dashboard if already authenticated."""
    user = get_current_user_optional(request, db)
    if user is not None:
        return RedirectResponse(url="/", status_code=302)

    response = templates.TemplateResponse(
        "login.html",
        {"request": request, "csrf_token": csrf_token},
    )
    response.set_cookie(
        "csrf_token",
        csrf_token,
        httponly=False,
        samesite="lax",
        secure=_SECURE_COOKIES,
    )
    return response


@router.post("/login", response_class=HTMLResponse)
@limiter.limit("10/minute")
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token_form: str = Form(alias="csrf_token"),
    db: Session = Depends(get_db),
):
    """Process login form. Set JWT HttpOnly cookie on success."""
    # CSRF validation
    csrf_cookie = request.cookies.get("csrf_token")
    validate_csrf_form(csrf_token_form, csrf_cookie)

    error = None
    user: User | None = db.query(User).filter(
        User.username == username, User.is_active == True
    ).first()

    if user is None or not verify_password(password, user.hashed_password):
        error = "Invalid username or password."

    if error:
        new_csrf = get_csrf_token(request)
        response = templates.TemplateResponse(
            "login.html",
            {"request": request, "error": error, "csrf_token": new_csrf},
        )
        response.set_cookie("csrf_token", new_csrf, httponly=False, samesite="lax", secure=_SECURE_COOKIES)
        return response

    # Successful login
    token = create_access_token(subject=user.username, is_admin=user.is_admin)
    redirect = RedirectResponse(url="/", status_code=302)
    redirect.set_cookie(
        "session",
        token,
        httponly=True,
        samesite="lax",
        secure=_SECURE_COOKIES,
        max_age=60 * 60 * 2,  # 2 hours (matches ACCESS_TOKEN_EXPIRE_MINUTES default)
    )
    _set_flash(redirect, f"Welcome back, {user.username}!", "success")
    return redirect


@router.post("/logout")
async def logout(request: Request):
    """Clear the session cookie and redirect to login."""
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("session")
    response.delete_cookie("csrf_token")
    response.delete_cookie("flash")
    return response
