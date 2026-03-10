"""
Dashboard route — summary statistics and recent reports.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from deps import get_csrf_token, get_current_user
from models import Customer, Report, User
from templating import templates

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    """Render the dashboard with summary cards and recent report activity."""
    today_start = datetime.now(tz=timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    total_customers = db.query(func.count(Customer.id)).scalar() or 0

    reports_today = (
        db.query(func.count(Report.id))
        .filter(Report.created_at >= today_start)
        .scalar()
        or 0
    )

    pending_reports = (
        db.query(func.count(Report.id))
        .filter(Report.status.in_(["pending", "running"]))
        .scalar()
        or 0
    )

    recent_reports = (
        db.query(Report)
        .order_by(Report.created_at.desc())
        .limit(5)
        .all()
    )

    response = templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "total_customers": total_customers,
            "reports_today": reports_today,
            "pending_reports": pending_reports,
            "recent_reports": recent_reports,
        },
    )
    response.set_cookie("csrf_token", csrf_token, httponly=False, samesite="lax", secure=False)
    return response
