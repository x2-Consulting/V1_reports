"""
Superadmin routes: organisation management (platform operators only).
All routes require is_superadmin=True.
"""

import os

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from audit import audit_log
from database import get_db
from deps import get_csrf_token, require_superadmin, validate_csrf_form
from models import Customer, Organisation, User
from security import generate_csrf_token
from templating import templates

router = APIRouter(prefix="/superadmin")

_SECURE_COOKIES: bool = os.getenv("HTTPS_ENABLED", "false").lower() == "true"


def _flash(response, message: str, category: str = "info") -> None:
    from itsdangerous import URLSafeSerializer
    secret = os.getenv("SECRET_KEY")
    s = URLSafeSerializer(secret, salt="flash")
    response.set_cookie(
        "flash", s.dumps({"message": message, "category": category}),
        httponly=True, samesite="lax", max_age=60,
    )


def _set_csrf_cookie(response, token: str) -> None:
    response.set_cookie("csrf_token", token, httponly=False, samesite="lax", secure=_SECURE_COOKIES)


# ── Organisation list ─────────────────────────────────────────────────────────

@router.get("/orgs", response_class=HTMLResponse)
async def org_list(
    request: Request,
    current_user: User = Depends(require_superadmin),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    orgs = db.query(Organisation).order_by(Organisation.name).all()
    response = templates.TemplateResponse(
        "superadmin/orgs.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "orgs": orgs,
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── New org form ──────────────────────────────────────────────────────────────

@router.get("/orgs/new", response_class=HTMLResponse)
async def org_new(
    request: Request,
    current_user: User = Depends(require_superadmin),
    csrf_token: str = Depends(get_csrf_token),
):
    response = templates.TemplateResponse(
        "superadmin/org_form.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "org": None,
            "form_action": "/superadmin/orgs",
            "form_title": "New Organisation",
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── Create org ────────────────────────────────────────────────────────────────

@router.post("/orgs", response_class=HTMLResponse)
async def org_create(
    request: Request,
    name: str = Form(...),
    slug: str = Form(...),
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    slug_clean = slug.strip().lower().replace(" ", "-")

    if db.query(Organisation).filter(Organisation.slug == slug_clean).first():
        csrf_token = generate_csrf_token()
        response = templates.TemplateResponse(
            "superadmin/org_form.html",
            {
                "request": request,
                "current_user": current_user,
                "csrf_token": csrf_token,
                "org": None,
                "form_action": "/superadmin/orgs",
                "form_title": "New Organisation",
                "error": f"Slug '{slug_clean}' is already in use.",
                "form": {"name": name, "slug": slug},
            },
        )
        _set_csrf_cookie(response, csrf_token)
        return response

    org = Organisation(name=name.strip(), slug=slug_clean, is_active=True)
    db.add(org)
    db.commit()
    audit_log(db, request, actor=current_user.username, event="org.create",
              target=f"org:{org.slug}", detail=f"name={org.name}")

    redirect = RedirectResponse(url=f"/superadmin/orgs/{org.id}", status_code=302)
    _flash(redirect, f"Organisation '{org.name}' created.", "success")
    return redirect


# ── Org detail (users + customers) ───────────────────────────────────────────

@router.get("/orgs/{org_id}", response_class=HTMLResponse)
async def org_detail(
    org_id: int,
    request: Request,
    current_user: User = Depends(require_superadmin),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    org = db.query(Organisation).filter(Organisation.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organisation not found")

    users = db.query(User).filter(User.organisation_id == org_id).order_by(User.username).all()
    customers = (
        db.query(Customer)
        .filter(Customer.organisation_id == org_id)
        .order_by(Customer.name)
        .all()
    )

    response = templates.TemplateResponse(
        "superadmin/org_detail.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "org": org,
            "users": users,
            "customers": customers,
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── Edit org form ─────────────────────────────────────────────────────────────

@router.get("/orgs/{org_id}/edit", response_class=HTMLResponse)
async def org_edit_form(
    org_id: int,
    request: Request,
    current_user: User = Depends(require_superadmin),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    org = db.query(Organisation).filter(Organisation.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organisation not found")

    response = templates.TemplateResponse(
        "superadmin/org_form.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "org": org,
            "form_action": f"/superadmin/orgs/{org_id}/edit",
            "form_title": "Edit Organisation",
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── Update org ────────────────────────────────────────────────────────────────

@router.post("/orgs/{org_id}/edit", response_class=HTMLResponse)
async def org_update(
    org_id: int,
    request: Request,
    name: str = Form(...),
    slug: str = Form(...),
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    org = db.query(Organisation).filter(Organisation.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organisation not found")

    slug_clean = slug.strip().lower().replace(" ", "-")
    conflict = db.query(Organisation).filter(
        Organisation.slug == slug_clean, Organisation.id != org_id
    ).first()
    if conflict:
        csrf_token = generate_csrf_token()
        response = templates.TemplateResponse(
            "superadmin/org_form.html",
            {
                "request": request,
                "current_user": current_user,
                "csrf_token": csrf_token,
                "org": org,
                "form_action": f"/superadmin/orgs/{org_id}/edit",
                "form_title": "Edit Organisation",
                "error": f"Slug '{slug_clean}' is already in use.",
            },
        )
        _set_csrf_cookie(response, csrf_token)
        return response

    org.name = name.strip()
    org.slug = slug_clean
    db.commit()
    audit_log(db, request, actor=current_user.username, event="org.update",
              target=f"org:{org.slug}", detail=f"name={org.name}")

    redirect = RedirectResponse(url=f"/superadmin/orgs/{org_id}", status_code=302)
    _flash(redirect, f"Organisation '{org.name}' updated.", "success")
    return redirect


# ── Toggle org active/inactive ────────────────────────────────────────────────

@router.post("/orgs/{org_id}/toggle", response_class=HTMLResponse)
async def org_toggle(
    org_id: int,
    request: Request,
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    org = db.query(Organisation).filter(Organisation.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organisation not found")

    org.is_active = not org.is_active
    db.commit()
    state = "activated" if org.is_active else "deactivated"
    audit_log(db, request, actor=current_user.username, event=f"org.{state}",
              target=f"org:{org.slug}")

    redirect = RedirectResponse(url="/superadmin/orgs", status_code=302)
    _flash(redirect, f"Organisation '{org.name}' {state}.", "success")
    return redirect
