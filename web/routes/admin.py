"""
Admin routes: portal user management (admin-only).
"""

import os
import threading

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

_limiter = Limiter(key_func=get_remote_address)

from audit import audit_log
from database import get_db
from deps import get_csrf_token, get_current_user, require_admin, validate_csrf_form
from models import AppSetting, Organisation, User
from security import generate_csrf_token, hash_password
from settings_store import KNOWN_SETTINGS, delete_setting, get_setting, set_setting
from templating import templates

router = APIRouter(prefix="/admin")


def _flash(response, message: str, category: str = "info") -> None:
    from itsdangerous import URLSafeSerializer
    secret = os.getenv("SECRET_KEY")
    s = URLSafeSerializer(secret, salt="flash")
    response.set_cookie("flash", s.dumps({"message": message, "category": category}),
                        httponly=True, samesite="lax", max_age=60)


_SECURE_COOKIES: bool = os.getenv("HTTPS_ENABLED", "false").lower() == "true"


def _set_csrf_cookie(response, token: str) -> None:
    response.set_cookie("csrf_token", token, httponly=False, samesite="lax", secure=_SECURE_COOKIES)


# ── User list ─────────────────────────────────────────────────────────────────

@router.get("/users", response_class=HTMLResponse)
async def user_list(
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    if current_user.is_superadmin:
        users = db.query(User).order_by(User.username).all()
    else:
        users = (
            db.query(User)
            .filter(User.organisation_id == current_user.organisation_id)
            .order_by(User.username)
            .all()
        )
    response = templates.TemplateResponse(
        "admin/users.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "users": users,
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── New user form ─────────────────────────────────────────────────────────────

@router.get("/users/new", response_class=HTMLResponse)
async def user_new(
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    orgs = db.query(Organisation).order_by(Organisation.name).all() if current_user.is_superadmin else None
    response = templates.TemplateResponse(
        "admin/user_form.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "edit_user": None,
            "orgs": orgs,
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── Create user ───────────────────────────────────────────────────────────────

@router.post("/users", response_class=HTMLResponse)
@_limiter.limit("10/hour")
async def user_create(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    is_admin: str = Form(default=""),
    organisation_id: str = Form(default=""),
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    if db.query(User).filter(User.username == username.strip()).first():
        csrf_token = generate_csrf_token()
        response = templates.TemplateResponse(
            "admin/user_form.html",
            {
                "request": request,
                "current_user": current_user,
                "csrf_token": csrf_token,
                "edit_user": None,
                "error": f"Username '{username}' is already taken.",
                "form": {"username": username, "email": email},
            },
        )
        _set_csrf_cookie(response, csrf_token)
        return response

    if db.query(User).filter(User.email == email.strip()).first():
        csrf_token = generate_csrf_token()
        response = templates.TemplateResponse(
            "admin/user_form.html",
            {
                "request": request,
                "current_user": current_user,
                "csrf_token": csrf_token,
                "edit_user": None,
                "error": f"Email '{email}' is already in use.",
                "form": {"username": username, "email": email},
            },
        )
        _set_csrf_cookie(response, csrf_token)
        return response

    if len(password) < 12:
        csrf_token = generate_csrf_token()
        response = templates.TemplateResponse(
            "admin/user_form.html",
            {
                "request": request,
                "current_user": current_user,
                "csrf_token": csrf_token,
                "edit_user": None,
                "error": "Password must be at least 12 characters.",
                "form": {"username": username, "email": email},
            },
        )
        _set_csrf_cookie(response, csrf_token)
        return response

    if current_user.is_superadmin and organisation_id:
        try:
            assigned_org_id = int(organisation_id)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="Invalid organisation_id")
    else:
        assigned_org_id = current_user.organisation_id

    user = User(
        username=username.strip(),
        email=email.strip(),
        hashed_password=hash_password(password),
        is_admin=bool(is_admin),
        is_active=True,
        organisation_id=assigned_org_id,
    )
    db.add(user)
    db.commit()
    audit_log(db, request, actor=current_user.username, event="user.create",
              target=f"user:{user.username}",
              detail=f"is_admin={user.is_admin}")

    redirect = RedirectResponse(url="/admin/users", status_code=302)
    _flash(redirect, f"User '{user.username}' created successfully.", "success")
    return redirect


# ── Edit user form ────────────────────────────────────────────────────────────

@router.get("/users/{user_id}/edit", response_class=HTMLResponse)
async def user_edit_form(
    user_id: int,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    edit_user = db.query(User).filter(User.id == user_id).first()
    if not edit_user:
        raise HTTPException(status_code=404, detail="User not found")
    if not current_user.is_superadmin and edit_user.organisation_id != current_user.organisation_id:
        raise HTTPException(status_code=404, detail="User not found")

    orgs = db.query(Organisation).order_by(Organisation.name).all() if current_user.is_superadmin else None
    response = templates.TemplateResponse(
        "admin/user_form.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "edit_user": edit_user,
            "orgs": orgs,
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── Update user ───────────────────────────────────────────────────────────────

@router.post("/users/{user_id}/edit", response_class=HTMLResponse)
async def user_update(
    user_id: int,
    request: Request,
    email: str = Form(...),
    is_admin: str = Form(default=""),
    organisation_id: str = Form(default=""),
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    edit_user = db.query(User).filter(User.id == user_id).first()
    if not edit_user:
        raise HTTPException(status_code=404, detail="User not found")
    if not current_user.is_superadmin and edit_user.organisation_id != current_user.organisation_id:
        raise HTTPException(status_code=404, detail="User not found")

    # Org admins cannot modify other admins — prevents privilege-level conflicts
    if not current_user.is_superadmin and edit_user.is_admin and edit_user.id != current_user.id:
        raise HTTPException(status_code=403, detail="Cannot modify another admin's account.")

    # Prevent removing admin from yourself
    new_is_admin = bool(is_admin)
    if edit_user.id == current_user.id and not new_is_admin:
        redirect = RedirectResponse(url="/admin/users", status_code=302)
        _flash(redirect, "You cannot remove your own admin privileges.", "error")
        return redirect

    email_conflict = db.query(User).filter(
        User.email == email.strip(), User.id != user_id
    ).first()
    if email_conflict:
        csrf_token = generate_csrf_token()
        response = templates.TemplateResponse(
            "admin/user_form.html",
            {
                "request": request,
                "current_user": current_user,
                "csrf_token": csrf_token,
                "edit_user": edit_user,
                "error": f"Email '{email}' is already in use.",
            },
        )
        _set_csrf_cookie(response, csrf_token)
        return response

    edit_user.email = email.strip()
    edit_user.is_admin = new_is_admin
    if current_user.is_superadmin:
        if organisation_id:
            try:
                edit_user.organisation_id = int(organisation_id)
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail="Invalid organisation_id")
        else:
            edit_user.organisation_id = None
    db.commit()
    audit_log(db, request, actor=current_user.username, event="user.update",
              target=f"user:{edit_user.username}",
              detail=f"is_admin={new_is_admin}, org_id={edit_user.organisation_id}")

    redirect = RedirectResponse(url="/admin/users", status_code=302)
    _flash(redirect, f"User '{edit_user.username}' updated.", "success")
    return redirect


# ── Toggle active/inactive ────────────────────────────────────────────────────

@router.post("/users/{user_id}/toggle", response_class=HTMLResponse)
async def user_toggle(
    user_id: int,
    request: Request,
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    edit_user = db.query(User).filter(User.id == user_id).first()
    if not edit_user:
        raise HTTPException(status_code=404, detail="User not found")
    if not current_user.is_superadmin and edit_user.organisation_id != current_user.organisation_id:
        raise HTTPException(status_code=404, detail="User not found")

    if edit_user.id == current_user.id:
        redirect = RedirectResponse(url="/admin/users", status_code=302)
        _flash(redirect, "You cannot deactivate your own account.", "error")
        return redirect

    edit_user.is_active = not edit_user.is_active
    db.commit()

    state = "activated" if edit_user.is_active else "deactivated"
    audit_log(db, request, actor=current_user.username, event=f"user.{state}",
              target=f"user:{edit_user.username}")

    redirect = RedirectResponse(url="/admin/users", status_code=302)
    _flash(redirect, f"User '{edit_user.username}' {state}.", "success")
    return redirect


# ── Reset password ────────────────────────────────────────────────────────────

@router.post("/users/{user_id}/reset-password", response_class=HTMLResponse)
async def user_reset_password(
    user_id: int,
    request: Request,
    new_password: str = Form(...),
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    edit_user = db.query(User).filter(User.id == user_id).first()
    if not edit_user:
        raise HTTPException(status_code=404, detail="User not found")
    if not current_user.is_superadmin and edit_user.organisation_id != current_user.organisation_id:
        raise HTTPException(status_code=404, detail="User not found")

    if len(new_password) < 12:
        redirect = RedirectResponse(url="/admin/users", status_code=302)
        _flash(redirect, "Password must be at least 12 characters.", "error")
        return redirect

    edit_user.hashed_password = hash_password(new_password)
    db.commit()
    audit_log(db, request, actor=current_user.username, event="user.password_reset",
              target=f"user:{edit_user.username}")

    redirect = RedirectResponse(url="/admin/users", status_code=302)
    _flash(redirect, f"Password reset for '{edit_user.username}'.", "success")
    return redirect


# ── Delete user ───────────────────────────────────────────────────────────────

@router.post("/users/{user_id}/delete", response_class=HTMLResponse)
async def user_delete(
    user_id: int,
    request: Request,
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    edit_user = db.query(User).filter(User.id == user_id).first()
    if not edit_user:
        raise HTTPException(status_code=404, detail="User not found")
    if not current_user.is_superadmin and edit_user.organisation_id != current_user.organisation_id:
        raise HTTPException(status_code=404, detail="User not found")

    if edit_user.id == current_user.id:
        redirect = RedirectResponse(url="/admin/users", status_code=302)
        _flash(redirect, "You cannot delete your own account.", "error")
        return redirect

    username = edit_user.username
    db.delete(edit_user)
    db.commit()
    audit_log(db, request, actor=current_user.username, event="user.delete",
              target=f"user:{username}")

    redirect = RedirectResponse(url="/admin/users", status_code=302)
    _flash(redirect, f"User '{username}' deleted.", "warning")
    return redirect


# ── Settings page ─────────────────────────────────────────────────────────────

@router.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    # Build list of settings with current plaintext values (masked for display)
    settings = []
    for key, (description, is_encrypted) in KNOWN_SETTINGS.items():
        row = db.query(AppSetting).filter(AppSetting.key == key).first()
        current_value = ""
        is_set = False
        updated_at = None
        if row and row.value:
            is_set = True
            updated_at = row.updated_at
            if not is_encrypted:
                current_value = row.value
        settings.append({
            "key": key,
            "description": description,
            "is_encrypted": is_encrypted,
            "is_set": is_set,
            "current_value": current_value,
            "updated_at": updated_at,
        })

    response = templates.TemplateResponse(
        "admin/settings.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "settings": settings,
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


@router.post("/settings/{key}", response_class=HTMLResponse)
@_limiter.limit("30/hour")
async def setting_update(
    key: str,
    request: Request,
    value: str = Form(default=""),
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    if key not in KNOWN_SETTINGS:
        raise HTTPException(status_code=400, detail="Unknown setting key")

    if value.strip():
        set_setting(db, key, value.strip())
        _flash_msg = f"Setting '{key}' updated."
        audit_log(db, request, actor=current_user.username, event="setting.update",
                  target=f"setting:{key}")
    else:
        delete_setting(db, key)
        _flash_msg = f"Setting '{key}' cleared."
        audit_log(db, request, actor=current_user.username, event="setting.clear",
                  target=f"setting:{key}")

    redirect = RedirectResponse(url="/admin/settings", status_code=302)
    _flash(redirect, _flash_msg, "success")
    return redirect


# ── NVD Cache management ───────────────────────────────────────────────────────

@router.get("/nvd", response_class=HTMLResponse)
async def nvd_cache_page(
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    from collectors.nvd_sync import get_sync_status
    sync_status = get_sync_status(db)
    response = templates.TemplateResponse(
        "admin/nvd.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "sync_status": sync_status,
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


@router.post("/nvd/sync-full", response_class=HTMLResponse)
async def nvd_sync_full(
    request: Request,
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    from collectors.nvd_sync import sync_full
    nvd_key = get_setting(db, "nvd_api_key")
    threading.Thread(target=sync_full, args=(nvd_key,), daemon=True).start()

    redirect = RedirectResponse(url="/admin/nvd", status_code=302)
    _flash(redirect, "Full NVD sync started — this will take several minutes.", "info")
    return redirect


@router.post("/nvd/sync-recent", response_class=HTMLResponse)
async def nvd_sync_recent(
    request: Request,
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    from collectors.nvd_sync import sync_incremental
    nvd_key = get_setting(db, "nvd_api_key")
    threading.Thread(target=sync_incremental, args=(nvd_key,), daemon=True).start()

    redirect = RedirectResponse(url="/admin/nvd", status_code=302)
    _flash(redirect, "Incremental sync started.", "info")
    return redirect
