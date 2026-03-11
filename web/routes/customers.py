"""
Customer management routes: CRUD and API key management.
All queries are scoped to the current user's organisation.
Superadmins can see all organisations' customers.
"""

import os

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

_SECURE_COOKIES: bool = os.getenv("HTTPS_ENABLED", "false").lower() == "true"

from audit import audit_log
from database import get_db
from deps import (
    assert_customer_access,
    get_csrf_token,
    get_current_user,
    org_customer_filter,
    validate_csrf_form,
)
import re

from models import Customer, CustomerApiKey, User
from security import encrypt_api_key

_ALLOWED_BASE_URL = re.compile(
    r'^https://(?:api\.xdr\.trendmicro\.com|[a-z0-9-]+\.xdr\.trendmicro\.com)$'
)
from templating import templates

router = APIRouter(prefix="/customers")


def _flash(response, message: str, category: str = "info") -> None:
    from itsdangerous import URLSafeSerializer
    secret = os.getenv("SECRET_KEY")
    s = URLSafeSerializer(secret, salt="flash")
    encoded = s.dumps({"message": message, "category": category})
    response.set_cookie("flash", encoded, httponly=True, samesite="lax", max_age=60)


def _set_csrf_cookie(response, token: str) -> None:
    response.set_cookie("csrf_token", token, httponly=False, samesite="lax", secure=_SECURE_COOKIES)


# ── Customer list ─────────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
async def customer_list(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    customers = org_customer_filter(db, current_user).order_by(Customer.name).all()
    response = templates.TemplateResponse(
        "customers/list.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "customers": customers,
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── New customer form ─────────────────────────────────────────────────────────

@router.get("/new", response_class=HTMLResponse)
async def customer_new(
    request: Request,
    current_user: User = Depends(get_current_user),
    csrf_token: str = Depends(get_csrf_token),
):
    response = templates.TemplateResponse(
        "customers/form.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "customer": None,
            "form_action": "/customers",
            "form_title": "Add Customer",
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── Create customer ───────────────────────────────────────────────────────────

@router.post("", response_class=HTMLResponse)
async def customer_create(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    contact_email: str = Form(""),
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    customer = Customer(
        name=name.strip(),
        description=description.strip() or None,
        contact_email=contact_email.strip() or None,
        created_by_id=current_user.id,
        organisation_id=current_user.organisation_id,
    )
    db.add(customer)
    db.commit()
    db.refresh(customer)

    redirect = RedirectResponse(url=f"/customers/{customer.id}", status_code=302)
    _flash(redirect, f"Customer '{customer.name}' created successfully.", "success")
    return redirect


# ── Customer detail ───────────────────────────────────────────────────────────

@router.get("/{customer_id}", response_class=HTMLResponse)
async def customer_detail(
    customer_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    customer = assert_customer_access(
        db.query(Customer).filter(Customer.id == customer_id).first(),
        current_user,
    )

    api_keys = (
        db.query(CustomerApiKey)
        .filter(CustomerApiKey.customer_id == customer_id)
        .order_by(CustomerApiKey.created_at.desc())
        .all()
    )
    reports = sorted(customer.reports, key=lambda r: r.created_at, reverse=True)[:10]

    response = templates.TemplateResponse(
        "customers/detail.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "customer": customer,
            "api_keys": api_keys,
            "reports": reports,
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── Edit customer form ────────────────────────────────────────────────────────

@router.get("/{customer_id}/edit", response_class=HTMLResponse)
async def customer_edit_form(
    customer_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    customer = assert_customer_access(
        db.query(Customer).filter(Customer.id == customer_id).first(),
        current_user,
    )

    response = templates.TemplateResponse(
        "customers/form.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "customer": customer,
            "form_action": f"/customers/{customer_id}/edit",
            "form_title": "Edit Customer",
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── Update customer ───────────────────────────────────────────────────────────

@router.post("/{customer_id}/edit", response_class=HTMLResponse)
async def customer_update(
    customer_id: int,
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    contact_email: str = Form(""),
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    customer = assert_customer_access(
        db.query(Customer).filter(Customer.id == customer_id).first(),
        current_user,
    )

    customer.name = name.strip()
    customer.description = description.strip() or None
    customer.contact_email = contact_email.strip() or None
    db.commit()

    redirect = RedirectResponse(url=f"/customers/{customer_id}", status_code=302)
    _flash(redirect, f"Customer '{customer.name}' updated.", "success")
    return redirect


# ── Delete customer ───────────────────────────────────────────────────────────

@router.post("/{customer_id}/delete", response_class=HTMLResponse)
async def customer_delete(
    customer_id: int,
    request: Request,
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    customer = assert_customer_access(
        db.query(Customer).filter(Customer.id == customer_id).first(),
        current_user,
    )

    name = customer.name
    db.delete(customer)
    db.commit()

    redirect = RedirectResponse(url="/customers", status_code=302)
    _flash(redirect, f"Customer '{name}' deleted.", "warning")
    return redirect


# ── Add API key ───────────────────────────────────────────────────────────────

@router.post("/{customer_id}/keys", response_class=HTMLResponse)
async def customer_add_key(
    customer_id: int,
    request: Request,
    label: str = Form(...),
    api_key: str = Form(...),
    base_url: str = Form("https://api.xdr.trendmicro.com"),
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    clean_base_url = base_url.strip().rstrip("/")
    if not _ALLOWED_BASE_URL.match(clean_base_url):
        raise HTTPException(
            status_code=400,
            detail="base_url must be a Trend Vision One API endpoint (https://*.xdr.trendmicro.com)."
        )

    customer = assert_customer_access(
        db.query(Customer).filter(Customer.id == customer_id).first(),
        current_user,
    )

    encrypted = encrypt_api_key(api_key.strip())
    key_record = CustomerApiKey(
        customer_id=customer_id,
        label=label.strip(),
        encrypted_key=encrypted,
        base_url=clean_base_url,
        is_active=True,
    )
    db.add(key_record)
    db.commit()

    redirect = RedirectResponse(url=f"/customers/{customer_id}", status_code=302)
    _flash(redirect, f"API key '{label}' added and encrypted.", "success")
    return redirect


# ── Delete API key ────────────────────────────────────────────────────────────

@router.post("/{customer_id}/keys/{key_id}/delete", response_class=HTMLResponse)
async def customer_delete_key(
    customer_id: int,
    key_id: int,
    request: Request,
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    # Verify customer is accessible by this user first
    assert_customer_access(
        db.query(Customer).filter(Customer.id == customer_id).first(),
        current_user,
    )

    key_record = db.query(CustomerApiKey).filter(
        CustomerApiKey.id == key_id,
        CustomerApiKey.customer_id == customer_id,
    ).first()
    if not key_record:
        raise HTTPException(status_code=404, detail="API key not found")

    label = key_record.label
    db.delete(key_record)
    db.commit()

    redirect = RedirectResponse(url=f"/customers/{customer_id}", status_code=302)
    _flash(redirect, f"API key '{label}' removed.", "warning")
    return redirect
