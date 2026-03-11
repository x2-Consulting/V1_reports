"""Admin management of customer portal user accounts."""

import os

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from database import get_db
from deps import get_csrf_token, require_admin, validate_csrf_form
from models import Customer, CustomerPortalUser, User
from security import generate_csrf_token, hash_password
from templating import templates

router = APIRouter(prefix="/admin/portal-users")

_SECURE_COOKIES: bool = os.getenv("HTTPS_ENABLED", "false").lower() == "true"


def _flash(response, message: str, category: str = "info") -> None:
    from itsdangerous import URLSafeSerializer
    secret = os.getenv("SECRET_KEY")
    s = URLSafeSerializer(secret, salt="flash")
    response.set_cookie(
        "flash",
        s.dumps({"message": message, "category": category}),
        httponly=True,
        samesite="lax",
        max_age=60,
    )


def _set_csrf_cookie(response, token: str) -> None:
    response.set_cookie(
        "csrf_token", token, httponly=False, samesite="lax", secure=_SECURE_COOKIES
    )


def _check_portal_user_access(
    portal_user: CustomerPortalUser | None,
    current_user: User,
) -> CustomerPortalUser:
    """Raise 404 if the portal user is missing or belongs to a different org."""
    if not portal_user:
        raise HTTPException(status_code=404, detail="Portal user not found")
    if not current_user.is_superadmin:
        if (
            portal_user.customer is None
            or portal_user.customer.organisation_id != current_user.organisation_id
        ):
            raise HTTPException(status_code=404, detail="Portal user not found")
    return portal_user


def _org_customers(db: Session, current_user: User):
    """Return customers scoped to the current user's organisation."""
    q = db.query(Customer)
    if not current_user.is_superadmin:
        q = q.filter(Customer.organisation_id == current_user.organisation_id)
    return q.order_by(Customer.name).all()


# ── GET /admin/portal-users — List portal users ───────────────────────────────

@router.get("", response_class=HTMLResponse)
async def portal_user_list(
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    if current_user.is_superadmin:
        portal_users = (
            db.query(CustomerPortalUser)
            .order_by(CustomerPortalUser.username)
            .all()
        )
    else:
        portal_users = (
            db.query(CustomerPortalUser)
            .join(Customer, CustomerPortalUser.customer_id == Customer.id)
            .filter(Customer.organisation_id == current_user.organisation_id)
            .order_by(CustomerPortalUser.username)
            .all()
        )

    response = templates.TemplateResponse(
        "admin/portal_users.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "portal_users": portal_users,
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── GET /admin/portal-users/new — New portal user form ───────────────────────

@router.get("/new", response_class=HTMLResponse)
async def portal_user_new(
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    customers = _org_customers(db, current_user)
    response = templates.TemplateResponse(
        "admin/portal_user_form.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "customers": customers,
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── POST /admin/portal-users — Create portal user ────────────────────────────

@router.post("", response_class=HTMLResponse)
async def portal_user_create(
    request: Request,
    customer_id: int = Form(...),
    username: str = Form(...),
    email: str = Form(default=""),
    password: str = Form(...),
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    customers = _org_customers(db, current_user)
    allowed_customer_ids = {c.id for c in customers}

    def _render_error(error: str) -> HTMLResponse:
        new_csrf = generate_csrf_token()
        response = templates.TemplateResponse(
            "admin/portal_user_form.html",
            {
                "request": request,
                "current_user": current_user,
                "csrf_token": new_csrf,
                "customers": customers,
                "error": error,
                "form": {
                    "customer_id": customer_id,
                    "username": username,
                    "email": email,
                },
            },
        )
        _set_csrf_cookie(response, new_csrf)
        return response

    # Validate customer belongs to current org
    if customer_id not in allowed_customer_ids:
        raise HTTPException(status_code=403, detail="Access denied to that customer")

    # Validate username uniqueness
    if db.query(CustomerPortalUser).filter(
        CustomerPortalUser.username == username.strip()
    ).first():
        return _render_error(f"Username '{username}' is already taken.")

    # Validate password length
    if len(password) < 12:
        return _render_error("Password must be at least 12 characters.")

    portal_user = CustomerPortalUser(
        customer_id=customer_id,
        username=username.strip(),
        email=email.strip() if email.strip() else None,
        hashed_password=hash_password(password),
        is_active=True,
    )
    db.add(portal_user)
    try:
        db.commit()
    except Exception:
        db.rollback()
        return _render_error("Could not create portal user. The customer may no longer exist.")

    redirect = RedirectResponse(url="/admin/portal-users", status_code=302)
    _flash(redirect, f"Portal user '{portal_user.username}' created successfully.", "success")
    return redirect


# ── POST /admin/portal-users/{id}/reset-password ──────────────────────────────

@router.post("/{portal_user_id}/reset-password", response_class=HTMLResponse)
async def portal_user_reset_password(
    portal_user_id: int,
    request: Request,
    new_password: str = Form(...),
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    portal_user = db.query(CustomerPortalUser).filter(
        CustomerPortalUser.id == portal_user_id
    ).first()
    _check_portal_user_access(portal_user, current_user)

    if len(new_password) < 12:
        redirect = RedirectResponse(url="/admin/portal-users", status_code=302)
        _flash(redirect, "Password must be at least 12 characters.", "error")
        return redirect

    portal_user.hashed_password = hash_password(new_password)
    db.commit()

    redirect = RedirectResponse(url="/admin/portal-users", status_code=302)
    _flash(redirect, f"Password reset for '{portal_user.username}'.", "success")
    return redirect


# ── POST /admin/portal-users/{id}/toggle ─────────────────────────────────────

@router.post("/{portal_user_id}/toggle", response_class=HTMLResponse)
async def portal_user_toggle(
    portal_user_id: int,
    request: Request,
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    portal_user = db.query(CustomerPortalUser).filter(
        CustomerPortalUser.id == portal_user_id
    ).first()
    _check_portal_user_access(portal_user, current_user)

    portal_user.is_active = not portal_user.is_active
    db.commit()

    state = "activated" if portal_user.is_active else "deactivated"
    redirect = RedirectResponse(url="/admin/portal-users", status_code=302)
    _flash(redirect, f"Portal user '{portal_user.username}' {state}.", "success")
    return redirect


# ── POST /admin/portal-users/{id}/delete ─────────────────────────────────────

@router.post("/{portal_user_id}/delete", response_class=HTMLResponse)
async def portal_user_delete(
    portal_user_id: int,
    request: Request,
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    portal_user = db.query(CustomerPortalUser).filter(
        CustomerPortalUser.id == portal_user_id
    ).first()
    _check_portal_user_access(portal_user, current_user)

    username = portal_user.username
    db.delete(portal_user)
    db.commit()

    redirect = RedirectResponse(url="/admin/portal-users", status_code=302)
    _flash(redirect, f"Portal user '{username}' deleted.", "warning")
    return redirect
