"""Customer-facing read-only security portal."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from database import get_db
from deps import (
    get_csrf_token,
    get_current_portal_user,
    get_current_portal_user_optional,
    validate_csrf_form,
)
from models import Customer, CustomerPortalUser, Report
from security import create_portal_token, verify_password
from templating import templates

router = APIRouter(prefix="/portal")
_limiter = Limiter(key_func=get_remote_address)

_SECURE_COOKIES: bool = os.getenv("HTTPS_ENABLED", "false").lower() == "true"

OUTPUT_DIR = Path(os.getenv("REPORT_OUTPUT_DIR", "/home/xspader/V1/output"))

_REPORT_TYPES = [
    "executive_summary",
    "endpoint_health",
    "user_risk",
    "oat_trend",
    "risk_index",
    "attack_surface",
    "incident_response",
]


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


def _build_dashboard_metrics(latest_data: dict) -> dict:
    """Build the dashboard_data dict from the latest report data per type."""
    result = {}

    # executive_summary
    if "executive_summary" in latest_data:
        report, data = latest_data["executive_summary"]
        result["executive_summary"] = {
            "total_alerts": data.get("total_alerts", 0),
            "critical_alerts": data.get("by_severity", {}).get("critical", 0),
            "alerts_by_day": data.get("alerts_by_day", []),
            "report_date": report.completed_at.strftime("%Y-%m-%d") if report.completed_at else "N/A",
        }
    else:
        result["executive_summary"] = None

    # endpoint_health
    if "endpoint_health" in latest_data:
        report, data = latest_data["endpoint_health"]
        result["endpoint_health"] = {
            "total_endpoints": data.get("total_endpoints", 0),
            "connected": data.get("connected", 0),
            "disconnected": data.get("disconnected", 0),
            "never_seen": data.get("never_seen", 0),
            "stale_count": len(data.get("stale_endpoints", [])),
            "report_date": report.completed_at.strftime("%Y-%m-%d") if report.completed_at else "N/A",
        }
    else:
        result["endpoint_health"] = None

    # user_risk
    if "user_risk" in latest_data:
        report, data = latest_data["user_risk"]
        by_risk = data.get("by_risk_level", {})
        result["user_risk"] = {
            "total_accounts": data.get("total_accounts", 0),
            "high_risk_count": by_risk.get("critical", 0) + by_risk.get("high", 0),
            "avg_risk_score": round(data.get("avg_risk_score", 0), 1),
            "report_date": report.completed_at.strftime("%Y-%m-%d") if report.completed_at else "N/A",
        }
    else:
        result["user_risk"] = None

    # oat_trend
    if "oat_trend" in latest_data:
        report, data = latest_data["oat_trend"]
        result["oat_trend"] = {
            "total_detections": data.get("total_detections", 0),
            "critical_count": data.get("by_risk_level", {}).get("critical", 0),
            "detections_by_day": data.get("detections_by_day", []),
            "report_date": report.completed_at.strftime("%Y-%m-%d") if report.completed_at else "N/A",
        }
    else:
        result["oat_trend"] = None

    # risk_index
    if "risk_index" in latest_data:
        report, data = latest_data["risk_index"]
        result["risk_index"] = {
            "avg_risk_score": round(data.get("avg_risk_score", 0), 1),
            "critical_assets": data.get("risk_distribution", {}).get("critical", 0),
            "total_assets": data.get("total_assets", 0),
            "report_date": report.completed_at.strftime("%Y-%m-%d") if report.completed_at else "N/A",
        }
    else:
        result["risk_index"] = None

    # attack_surface
    if "attack_surface" in latest_data:
        report, data = latest_data["attack_surface"]
        result["attack_surface"] = {
            "posture_score": data.get("overall_posture_score", 0),
            "posture_grade": data.get("posture_grade", "N/A"),
            "failed_assessments": data.get("failed_assessments", 0),
            "passed_assessments": data.get("passed_assessments", 0),
            "total_assessments": data.get("total_assessments", 0),
            "report_date": report.completed_at.strftime("%Y-%m-%d") if report.completed_at else "N/A",
        }
    else:
        result["attack_surface"] = None

    # incident_response
    if "incident_response" in latest_data:
        report, data = latest_data["incident_response"]
        by_status = data.get("by_status", {})
        result["incident_response"] = {
            "total_investigations": data.get("total_investigations", 0),
            "open_count": by_status.get("open", 0) + by_status.get("in_progress", 0),
            "avg_resolution_days": round(data.get("avg_resolution_days", 0), 1),
            "total_actions": data.get("total_actions", 0),
            "report_date": report.completed_at.strftime("%Y-%m-%d") if report.completed_at else "N/A",
        }
    else:
        result["incident_response"] = None

    return result


# ── GET /portal/login ─────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def portal_login_get(
    request: Request,
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    """Show the portal login form. Redirect to /portal/ if already authenticated."""
    portal_user = get_current_portal_user_optional(request, db)
    if portal_user is not None:
        return RedirectResponse(url="/portal/", status_code=302)

    response = templates.TemplateResponse(
        "portal/login.html",
        {"request": request, "csrf_token": csrf_token},
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── POST /portal/login ────────────────────────────────────────────────────────

@router.post("/login", response_class=HTMLResponse)
@_limiter.limit("10/minute")
async def portal_login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token_form: str = Form(alias="csrf_token"),
    db: Session = Depends(get_db),
):
    """Process portal login form."""
    csrf_cookie = request.cookies.get("csrf_token")
    validate_csrf_form(csrf_token_form, csrf_cookie)

    portal_user: CustomerPortalUser | None = (
        db.query(CustomerPortalUser)
        .filter(
            CustomerPortalUser.username == username,
            CustomerPortalUser.is_active == True,
        )
        .first()
    )

    if portal_user is None or not verify_password(password, portal_user.hashed_password):
        new_csrf = get_csrf_token(request)
        response = templates.TemplateResponse(
            "portal/login.html",
            {
                "request": request,
                "error": "Invalid username or password.",
                "csrf_token": new_csrf,
            },
        )
        _set_csrf_cookie(response, new_csrf)
        return response

    # Successful login — update last_login_at
    portal_user.last_login_at = datetime.now(tz=timezone.utc)
    db.commit()

    token = create_portal_token(
        portal_user_id=portal_user.id,
        customer_id=portal_user.customer_id,
    )
    redirect = RedirectResponse(url="/portal/", status_code=302)
    redirect.set_cookie(
        "portal_session",
        token,
        httponly=True,
        samesite="lax",
        secure=_SECURE_COOKIES,
        max_age=60 * 60 * 8,
    )
    return redirect


# ── POST /portal/logout ───────────────────────────────────────────────────────

@router.post("/logout")
async def portal_logout(request: Request):
    """Clear the portal session cookie and redirect to login."""
    response = RedirectResponse(url="/portal/login", status_code=302)
    response.delete_cookie("portal_session")
    return response


# ── GET /portal/ — Dashboard ──────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
async def portal_dashboard(
    request: Request,
    portal_user: CustomerPortalUser = Depends(get_current_portal_user),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    """Customer security dashboard showing aggregated metrics from latest reports."""
    customer = db.query(Customer).filter(Customer.id == portal_user.customer_id).first()

    # Fetch latest completed report with report_data_json for each type
    latest_data: dict = {}
    for report_type in _REPORT_TYPES:
        report = (
            db.query(Report)
            .filter(
                Report.customer_id == portal_user.customer_id,
                Report.report_type == report_type,
                Report.status == "done",
                Report.report_data_json != None,
            )
            .order_by(Report.completed_at.desc())
            .first()
        )
        if report and report.report_data_json:
            try:
                parsed = json.loads(report.report_data_json)
                latest_data[report_type] = (report, parsed)
            except (json.JSONDecodeError, ValueError):
                pass

    dashboard_data = _build_dashboard_metrics(latest_data)

    # Fetch last 5 completed reports for "Recent Reports" table
    recent_reports = (
        db.query(Report)
        .filter(
            Report.customer_id == portal_user.customer_id,
            Report.status == "done",
        )
        .order_by(Report.created_at.desc())
        .limit(5)
        .all()
    )

    response = templates.TemplateResponse(
        "portal/dashboard.html",
        {
            "request": request,
            "portal_user": portal_user,
            "customer": customer,
            "dashboard_data": dashboard_data,
            "recent_reports": recent_reports,
            "csrf_token": csrf_token,
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── GET /portal/reports — Report list ─────────────────────────────────────────

@router.get("/reports", response_class=HTMLResponse)
async def portal_reports(
    request: Request,
    portal_user: CustomerPortalUser = Depends(get_current_portal_user),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    """List all completed reports available to the portal user."""
    customer = db.query(Customer).filter(Customer.id == portal_user.customer_id).first()

    reports = (
        db.query(Report)
        .filter(
            Report.customer_id == portal_user.customer_id,
            Report.status == "done",
        )
        .order_by(Report.created_at.desc())
        .limit(50)
        .all()
    )

    response = templates.TemplateResponse(
        "portal/reports.html",
        {
            "request": request,
            "portal_user": portal_user,
            "customer": customer,
            "reports": reports,
            "csrf_token": csrf_token,
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── GET /portal/reports/{report_id}/download — PDF download ───────────────────

@router.get("/reports/{report_id}/download")
async def portal_report_download(
    report_id: int,
    request: Request,
    portal_user: CustomerPortalUser = Depends(get_current_portal_user),
    db: Session = Depends(get_db),
):
    """Download a completed PDF report (scoped to the portal user's customer)."""
    report = (
        db.query(Report)
        .filter(
            Report.id == report_id,
            Report.customer_id == portal_user.customer_id,
            Report.status == "done",
        )
        .first()
    )
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if not report.filename:
        raise HTTPException(status_code=404, detail="Report file not available")

    # Guard against path traversal — resolve and confirm it's inside OUTPUT_DIR
    pdf_path = (OUTPUT_DIR / report.filename).resolve()
    if not str(pdf_path).startswith(str(OUTPUT_DIR.resolve())):
        raise HTTPException(status_code=400, detail="Invalid report path")
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="PDF file not found on disk")

    _type_labels = {
        "security_overview": "Security_Overview",
        "patch_remediation": "Patch_Remediation",
        "executive_summary": "Executive_Summary",
        "mitre_heatmap": "MITRE_Heatmap",
        "targeted_assets": "Targeted_Assets",
        "threat_behaviour": "Threat_Behaviour",
        "alert_response": "Alert_Response",
        "blocked_threats": "Blocked_Threats",
        "endpoint_health": "Endpoint_Health_Summary",
        "user_risk": "User_Risk_Report",
        "oat_trend": "OAT_Detection_Trend",
        "risk_index": "Risk_Index_Report",
        "attack_surface": "Attack_Surface_Posture",
        "incident_response": "Incident_Response_Summary",
    }
    type_label = _type_labels.get(report.report_type, report.report_type.replace(" ", "_"))
    customer_name = report.customer.name.replace(" ", "_") if report.customer else "report"
    safe_customer = "".join(c if c.isalnum() or c in "-_" else "_" for c in customer_name)
    date_str = report.created_at.strftime("%Y-%m-%d")
    download_name = f"TV1_{type_label}_{safe_customer}_{date_str}.pdf"

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=download_name,
    )
