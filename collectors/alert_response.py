"""
Collector for the Alert Response Status report.

Analyses workbench alerts for investigation status, resolution times,
unowned open alerts, and stale (long-open) alerts.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from client import TrendVisionOneClient


def _parse_dt(s: str | None) -> datetime | None:
    """Parse an ISO datetime string to a timezone-aware datetime or None."""
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(s[:26], fmt[:len(fmt)])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def collect_alert_response(
    client: "TrendVisionOneClient",
    start_time: datetime,
    end_time: datetime,
) -> dict:
    """
    Collect alert response metrics from workbench alerts.

    Returns a dict with:
        total_alerts, by_investigation_status, by_status,
        open_unowned, open_with_no_findings, resolution_times,
        avg_resolution_hours, alerts_by_severity_and_status,
        stale_alerts, case_count, incident_count
    """
    start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    by_investigation_status: dict[str, int] = defaultdict(int)
    by_status: dict[str, int] = defaultdict(int)
    open_unowned: list[dict] = []
    open_with_no_findings = 0
    resolution_times: list[float] = []
    alerts_by_severity_and_status: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    stale_alerts: list[dict] = []
    case_ids: set = set()
    incident_ids: set = set()
    now = datetime.now(tz=timezone.utc)

    try:
        params = {
            "startDateTime": start_str,
            "endDateTime": end_str,
        }
        for alert in client.paginate("/v3.0/workbench/alerts", params=params):
            alert_id = alert.get("id") or ""
            sev = (alert.get("severity") or "unknown").lower()
            status = alert.get("status") or "unknown"
            inv_status = alert.get("investigationStatus") or "unknown"
            inv_result = alert.get("investigationResult") or ""
            owner_ids = alert.get("ownerIds") or []
            score = alert.get("score")
            model = alert.get("model") or "Unknown"
            created_str = alert.get("createdDateTime") or ""
            updated_str = alert.get("updatedDateTime") or ""

            case_id = alert.get("caseId")
            incident_id = alert.get("incidentId")
            if case_id:
                case_ids.add(case_id)
            if incident_id:
                incident_ids.add(incident_id)

            by_investigation_status[inv_status] += 1
            by_status[status] += 1
            alerts_by_severity_and_status[sev][status] += 1

            is_open = status in ("New", "Open", "In Progress")

            # Open unowned
            if is_open and not owner_ids:
                open_unowned.append({
                    "id": alert_id,
                    "severity": sev,
                    "model": model,
                    "created": created_str,
                    "score": score,
                })

            # Open with no findings
            if is_open and "no finding" in inv_result.lower():
                open_with_no_findings += 1

            # Resolution time for closed alerts
            if status in ("Closed",) and created_str and updated_str:
                created_dt = _parse_dt(created_str)
                updated_dt = _parse_dt(updated_str)
                if created_dt and updated_dt and updated_dt > created_dt:
                    hours = (updated_dt - created_dt).total_seconds() / 3600
                    resolution_times.append(round(hours, 2))

            # Stale alerts: open longer than 7 days
            if is_open and created_str:
                created_dt = _parse_dt(created_str)
                if created_dt:
                    days_open = (now - created_dt).days
                    if days_open > 7:
                        stale_alerts.append({
                            "id": alert_id,
                            "severity": sev,
                            "model": model,
                            "created": created_str,
                            "days_open": days_open,
                        })
    except Exception:
        pass

    avg_resolution_hours = (
        round(sum(resolution_times) / len(resolution_times), 2)
        if resolution_times else 0.0
    )

    # Sort stale alerts by days_open desc
    stale_alerts.sort(key=lambda x: x["days_open"], reverse=True)
    # Sort open_unowned by severity (critical first)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    open_unowned.sort(key=lambda x: sev_order.get(x["severity"], 5))

    total_alerts = sum(by_status.values())
    investigated_statuses = {"True Positive", "False Positive", "Benign True Positive",
                              "Closed", "true positive", "false positive"}
    investigated_count = sum(
        c for s, c in by_investigation_status.items()
        if s.lower() not in ("new", "unknown", "in progress", "")
    )
    closed_count = by_status.get("Closed", 0)

    return {
        "total_alerts": total_alerts,
        "by_investigation_status": dict(by_investigation_status),
        "by_status": dict(by_status),
        "open_unowned": open_unowned,
        "open_with_no_findings": open_with_no_findings,
        "resolution_times": resolution_times,
        "avg_resolution_hours": avg_resolution_hours,
        "alerts_by_severity_and_status": {
            sev: dict(statuses)
            for sev, statuses in alerts_by_severity_and_status.items()
        },
        "stale_alerts": stale_alerts,
        "case_count": len(case_ids),
        "incident_count": len(incident_ids),
    }
