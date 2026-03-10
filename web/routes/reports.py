"""
Report routes: trigger, status, download, list.
"""

import json
import os
import sys

_SECURE_COOKIES: bool = os.getenv("HTTPS_ENABLED", "false").lower() == "true"
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from database import SessionLocal, get_db
from deps import get_csrf_token, get_current_user, validate_csrf_form
from models import Customer, CustomerApiKey, Report, User
from security import decrypt_api_key
from settings_store import get_setting
from templating import templates

router = APIRouter(prefix="/reports")

OUTPUT_DIR = Path(os.getenv("REPORT_OUTPUT_DIR", "/home/xspader/V1/output"))


def _flash(response, message: str, category: str = "info") -> None:
    from itsdangerous import URLSafeSerializer
    secret = os.getenv("SECRET_KEY")
    s = URLSafeSerializer(secret, salt="flash")
    encoded = s.dumps({"message": message, "category": category})
    response.set_cookie("flash", encoded, httponly=True, samesite="lax", max_age=60)


def _set_csrf_cookie(response, token: str) -> None:
    response.set_cookie("csrf_token", token, httponly=False, samesite="lax", secure=_SECURE_COOKIES)


# ── Background report execution ───────────────────────────────────────────────

def _run_report_background(report_id: int) -> None:
    """
    Execute the full report pipeline in a background thread.
    Uses its own DB session (cannot share the request session).
    """
    # Add parent directory to path so we can import collectors/client/reports
    parent_dir = str(Path(__file__).resolve().parents[2])
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)

    from client import TrendVisionOneClient
    from collectors import (
        collect_alerts,
        collect_endpoints,
        collect_suspicious_objects,
        collect_vulnerabilities,
    )
    from collectors.patch_remediation import collect_patch_groups
    from reports.pdf_report import generate_report
    from reports.patch_report import generate_patch_report

    db = SessionLocal()
    try:
        report = db.query(Report).filter(Report.id == report_id).first()
        if not report:
            return

        report.status = "running"
        db.commit()

        key_record = db.query(CustomerApiKey).filter(
            CustomerApiKey.id == report.api_key_id
        ).first()
        if not key_record:
            report.status = "failed"
            report.error_message = "API key record not found."
            db.commit()
            return

        try:
            plain_key = decrypt_api_key(key_record.encrypted_key)
        except Exception:
            report.status = "failed"
            report.error_message = "Failed to decrypt API key. Check that FERNET_KEY matches the key used when the API key was stored."
            db.commit()
            return

        end_time = datetime.now(tz=timezone.utc)
        start_time = end_time - timedelta(days=report.days_back)

        severity_list: list[str] | None = None
        if report.severity_filter:
            try:
                severity_list = json.loads(report.severity_filter)
            except json.JSONDecodeError:
                severity_list = None

        try:
            client = TrendVisionOneClient(
                api_key=plain_key, base_url=key_record.base_url
            )
        except Exception as exc:
            report.status = "failed"
            report.error_message = f"Failed to create API client: {exc}"
            db.commit()
            return

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        output_path = str(OUTPUT_DIR / f"{report_id}.pdf")
        collection_errors = []

        # ── Executive summary report ───────────────────────────────────────────
        if report.report_type == "executive_summary":
            from collectors.executive_summary import collect_executive_summary
            from reports.executive_summary_report import generate_executive_summary
            try:
                data = collect_executive_summary(client, start_time, end_time)
            except Exception as exc:
                collection_errors.append(f"Executive summary data: {exc}")
                data = {}
            client.close()
            customer_name = report.customer.name if report.customer else "Customer"
            try:
                generate_executive_summary(data, customer_name, report.days_back, output_path)
            except Exception as exc:
                report.status = "failed"
                report.error_message = f"PDF generation failed: {exc}"
                db.commit()
                return

        # ── MITRE ATT&CK heatmap report ────────────────────────────────────────
        elif report.report_type == "mitre_heatmap":
            from collectors.mitre_heatmap import collect_mitre_data
            from reports.mitre_report import generate_mitre_report
            try:
                data = collect_mitre_data(client, start_time, end_time)
            except Exception as exc:
                collection_errors.append(f"MITRE data: {exc}")
                data = {}
            client.close()
            customer_name = report.customer.name if report.customer else "Customer"
            try:
                generate_mitre_report(data, customer_name, report.days_back, output_path)
            except Exception as exc:
                report.status = "failed"
                report.error_message = f"PDF generation failed: {exc}"
                db.commit()
                return

        # ── Targeted assets report ─────────────────────────────────────────────
        elif report.report_type == "targeted_assets":
            from collectors.targeted_assets import collect_targeted_assets
            from reports.targeted_assets_report import generate_targeted_assets_report
            try:
                data = collect_targeted_assets(client, start_time, end_time)
            except Exception as exc:
                collection_errors.append(f"Targeted assets data: {exc}")
                data = {}
            client.close()
            customer_name = report.customer.name if report.customer else "Customer"
            try:
                generate_targeted_assets_report(data, customer_name, report.days_back, output_path)
            except Exception as exc:
                report.status = "failed"
                report.error_message = f"PDF generation failed: {exc}"
                db.commit()
                return

        # ── Threat behaviour analysis report ───────────────────────────────────
        elif report.report_type == "threat_behaviour":
            from collectors.threat_behaviour import collect_threat_behaviours
            from reports.threat_behaviour_report import generate_threat_behaviour_report
            try:
                data = collect_threat_behaviours(client, start_time, end_time)
            except Exception as exc:
                collection_errors.append(f"Threat behaviour data: {exc}")
                data = {}
            client.close()
            customer_name = report.customer.name if report.customer else "Customer"
            try:
                generate_threat_behaviour_report(data, customer_name, report.days_back, output_path)
            except Exception as exc:
                report.status = "failed"
                report.error_message = f"PDF generation failed: {exc}"
                db.commit()
                return

        # ── Alert response status report ───────────────────────────────────────
        elif report.report_type == "alert_response":
            from collectors.alert_response import collect_alert_response
            from reports.alert_response_report import generate_alert_response_report
            try:
                data = collect_alert_response(client, start_time, end_time)
            except Exception as exc:
                collection_errors.append(f"Alert response data: {exc}")
                data = {}
            client.close()
            customer_name = report.customer.name if report.customer else "Customer"
            try:
                generate_alert_response_report(data, customer_name, report.days_back, output_path)
            except Exception as exc:
                report.status = "failed"
                report.error_message = f"PDF generation failed: {exc}"
                db.commit()
                return

        # ── Blocked threats & IoCs report ──────────────────────────────────────
        elif report.report_type == "blocked_threats":
            from collectors.blocked_threats import collect_blocked_threats
            from reports.blocked_threats_report import generate_blocked_threats_report
            try:
                data = collect_blocked_threats(client)
            except Exception as exc:
                collection_errors.append(f"Blocked threats data: {exc}")
                data = {}
            client.close()
            customer_name = report.customer.name if report.customer else "Customer"
            try:
                generate_blocked_threats_report(data, customer_name, output_path)
            except Exception as exc:
                report.status = "failed"
                report.error_message = f"PDF generation failed: {exc}"
                db.commit()
                return

        # ── Patch remediation report ───────────────────────────────────────────
        elif report.report_type == "patch_remediation":
            patch_groups = []
            try:
                patch_groups = collect_patch_groups(client, severity_filter=severity_list)
            except Exception as exc:
                collection_errors.append(f"Patch data: {exc}")

            client.close()
            customer_name = report.customer.name if report.customer else "Customer"

            try:
                generate_patch_report(
                    patch_groups=[g.to_dict() for g in patch_groups],
                    customer_name=customer_name,
                    output_path=output_path,
                )
            except Exception as exc:
                report.status = "failed"
                report.error_message = f"PDF generation failed: {exc}"
                db.commit()
                return

        # ── Security overview report (default) ────────────────────────────────
        else:
            alerts = []
            endpoints = []
            iocs = []
            vulns = []

            try:
                alerts = collect_alerts(
                    client, start_time=start_time, end_time=end_time, severity=severity_list
                )
            except Exception as exc:
                collection_errors.append(f"Alerts: {exc}")

            try:
                endpoints = collect_endpoints(client)
            except Exception as exc:
                collection_errors.append(f"Endpoints: {exc}")

            try:
                iocs = collect_suspicious_objects(client)
            except Exception as exc:
                collection_errors.append(f"Suspicious objects: {exc}")

            try:
                vulns = collect_vulnerabilities(client, severity=severity_list)
            except Exception as exc:
                collection_errors.append(f"Vulnerabilities: {exc}")

            client.close()

            try:
                generate_report(
                    alerts=alerts,
                    endpoints=endpoints,
                    iocs=iocs,
                    vulns=vulns,
                    output_path=output_path,
                )
            except Exception as exc:
                report.status = "failed"
                report.error_message = f"PDF generation failed: {exc}"
                db.commit()
                return

        report.filename = f"{report_id}.pdf"
        report.status = "done"
        report.completed_at = datetime.now(tz=timezone.utc)
        if collection_errors:
            report.error_message = "Partial collection errors: " + "; ".join(collection_errors)
        db.commit()

    except Exception as exc:
        try:
            report = db.query(Report).filter(Report.id == report_id).first()
            if report:
                report.status = "failed"
                report.error_message = f"Unexpected error: {exc}"
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


# ── Trigger report ────────────────────────────────────────────────────────────

@router.post("/run", response_class=HTMLResponse)
async def report_run(
    request: Request,
    background_tasks: BackgroundTasks,
    customer_id: int = Form(...),
    api_key_id: int = Form(...),
    report_type: str = Form(default="security_overview"),
    days_back: int = Form(30),
    severity: list[str] = Form(default=[]),
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a Report row, kick off background generation, redirect to status page."""
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    customer = db.query(Customer).filter(Customer.id == customer_id).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    key_record = db.query(CustomerApiKey).filter(
        CustomerApiKey.id == api_key_id,
        CustomerApiKey.customer_id == customer_id,
    ).first()
    if not key_record:
        raise HTTPException(status_code=404, detail="API key not found")

    severity_json = json.dumps(severity) if severity else json.dumps(
        ["critical", "high", "medium", "low", "info"]
    )

    allowed_types = {"security_overview", "patch_remediation", "executive_summary",
                     "mitre_heatmap", "targeted_assets", "threat_behaviour",
                     "alert_response", "blocked_threats"}
    safe_report_type = report_type if report_type in allowed_types else "security_overview"

    report = Report(
        customer_id=customer_id,
        api_key_id=api_key_id,
        report_type=safe_report_type,
        status="pending",
        days_back=max(1, min(days_back, 365)),
        severity_filter=severity_json,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    background_tasks.add_task(_run_report_background, report.id)

    redirect = RedirectResponse(url=f"/reports/{report.id}", status_code=302)
    _flash(redirect, "Report queued — generation started.", "info")
    return redirect


# ── CSV upload: patch report from exported CSV ────────────────────────────────
# MUST be defined before /{report_id} so FastAPI doesn't swallow "upload-csv"

@router.get("/upload-csv", response_class=HTMLResponse)
async def csv_upload_form(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    customers = db.query(Customer).order_by(Customer.name).all()
    nvd_key = get_setting(db, "nvd_api_key") or os.getenv("NVD_API_KEY", "")
    response = templates.TemplateResponse(
        "reports/csv_upload.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "customers": customers,
            "nvd_configured": bool(nvd_key),
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


@router.post("/upload-csv", response_class=HTMLResponse)
async def csv_upload_run(
    request: Request,
    csv_file: UploadFile = File(...),
    customer_name: str = Form(...),
    enrich_nvd: str = Form(default=""),
    csrf_token_form: str = Form(alias="csrf_token"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    validate_csrf_form(csrf_token_form, request.cookies.get("csrf_token"))

    parent_dir = str(Path(__file__).resolve().parents[3])
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)

    from collectors.csv_patch import parse_csv_to_patch_groups
    from reports.patch_report import generate_patch_report

    raw = await csv_file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # Pass db when NVD enrichment is requested so the parser can resolve proper
    # patch identifiers (KB articles, GHSA, RHSA, …) from NVD reference URLs
    # and enrich CVE details in a single pass.
    parse_db = db if enrich_nvd else None
    try:
        patch_groups = parse_csv_to_patch_groups(raw, db=parse_db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"CSV parse error: {exc}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in customer_name)
    filename = f"csv_patch_{safe_name}_{ts}.pdf"
    output_path = str(OUTPUT_DIR / filename)

    try:
        generate_patch_report(
            patch_groups=[g.to_dict() for g in patch_groups],
            customer_name=customer_name,
            output_path=output_path,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")

    download_name = f"TV1_PatchReport_{safe_name}_{ts}.pdf"
    return FileResponse(
        path=output_path,
        media_type="application/pdf",
        filename=download_name,
    )


# ── Report status page ────────────────────────────────────────────────────────

@router.get("/{report_id}", response_class=HTMLResponse)
async def report_detail(
    report_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    severity_list: list[str] = []
    if report.severity_filter:
        try:
            severity_list = json.loads(report.severity_filter)
        except json.JSONDecodeError:
            pass

    response = templates.TemplateResponse(
        "reports/detail.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "report": report,
            "severity_list": severity_list,
            "auto_refresh": report.status in ("pending", "running"),
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


# ── Download PDF ──────────────────────────────────────────────────────────────

@router.get("/{report_id}/download")
async def report_download(
    report_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != "done" or not report.filename:
        raise HTTPException(status_code=400, detail="Report is not ready for download")

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
        "mitre_heatmap":     "MITRE_Heatmap",
        "targeted_assets":   "Targeted_Assets",
        "threat_behaviour":  "Threat_Behaviour",
        "alert_response":    "Alert_Response",
        "blocked_threats":   "Blocked_Threats",
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


# ── All reports list ──────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
async def report_list(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    csrf_token: str = Depends(get_csrf_token),
):
    reports = (
        db.query(Report)
        .order_by(Report.created_at.desc())
        .limit(100)
        .all()
    )

    response = templates.TemplateResponse(
        "reports/list.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
            "reports": reports,
        },
    )
    _set_csrf_cookie(response, csrf_token)
    return response


