"""
Collector for XDR investigation / incident response data.

Fetches all investigations for the given time window and aggregates
status and severity breakdowns, open-investigation details, average
resolution time, action-type counts, affected entity counts, daily
investigation volume, and stale open investigations.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from client import TrendVisionOneClient

_ACTION_MAP = {
    "isolate_endpoint": "isolate_endpoint",
    "isolateendpoint": "isolate_endpoint",
    "block_file": "block_file",
    "blockfile": "block_file",
    "collect_file": "collect_file",
    "collectfile": "collect_file",
    "quarantine_email": "quarantine_email",
    "quarantineemail": "quarantine_email",
}


def collect_incident_response(
    client: "TrendVisionOneClient",
    start_time: datetime,
    end_time: datetime,
) -> dict:
    """
    Collect and aggregate XDR investigation / incident-response data.

    Returns a dict with investigation status/severity counts, open
    investigation details, average resolution days, action-type tallies,
    affected entity counts, daily investigation volume, and stale
    open investigations (open > 14 days).
    """
    investigations: list[dict] = []
    try:
        params = {
            "startDateTime": start_time.isoformat(),
            "endDateTime": end_time.isoformat(),
        }
        for item in client.paginate(
            "/v3.0/xdr/investigations", params=params, items_key="items"
        ):
            investigations.append(item)
    except Exception:
        investigations = []

    now = datetime.now(tz=timezone.utc)

    by_status: dict[str, int] = {
        "open": 0,
        "in_progress": 0,
        "closed": 0,
        "other": 0,
    }
    by_severity: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    open_investigations: list[dict] = []
    resolution_days: list[float] = []
    actions_taken: dict[str, int] = {
        "isolate_endpoint": 0,
        "block_file": 0,
        "collect_file": 0,
        "quarantine_email": 0,
        "other": 0,
    }
    total_actions = 0
    affected_entity_counts = {"endpoints": 0, "accounts": 0}
    day_map: dict[str, int] = defaultdict(int)
    stale_investigations: list[dict] = []

    for inv in investigations:
        inv_id = inv.get("investigationId") or ""
        title = inv.get("title") or ""
        status_raw = (inv.get("status") or "").lower().replace(" ", "_")
        severity = (inv.get("severity") or "unknown").lower()
        created_dt_str = inv.get("createdDateTime") or ""
        updated_dt_str = inv.get("updatedDateTime") or ""
        assigned_to = inv.get("assignedTo") or ""
        actions = inv.get("actions") or []
        affected_entities = inv.get("affectedEntities") or []

        # Status bucketing
        if status_raw == "open":
            by_status["open"] += 1
        elif status_raw in ("in_progress", "inprogress"):
            by_status["in_progress"] += 1
        elif status_raw == "closed":
            by_status["closed"] += 1
        else:
            by_status["other"] += 1

        # Severity counts
        if severity in by_severity:
            by_severity[severity] += 1

        # Parse created datetime
        created_dt = None
        if created_dt_str:
            try:
                created_dt = datetime.fromisoformat(
                    created_dt_str.replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        days_open = (now - created_dt).days if created_dt else 0

        # Daily counts
        if created_dt:
            day_map[created_dt.strftime("%Y-%m-%d")] += 1

        # Open / in-progress investigations list
        if status_raw in ("open", "in_progress", "inprogress"):
            open_investigations.append(
                {
                    "id": inv_id,
                    "title": title,
                    "severity": severity,
                    "created": created_dt_str,
                    "assigned_to": assigned_to,
                    "days_open": days_open,
                }
            )

            # Stale: open > 14 days
            if days_open > 14:
                stale_investigations.append(
                    {
                        "id": inv_id,
                        "title": title,
                        "days_open": days_open,
                        "severity": severity,
                    }
                )

        # Average resolution time for closed investigations
        if status_raw == "closed" and created_dt and updated_dt_str:
            try:
                updated_dt = datetime.fromisoformat(
                    updated_dt_str.replace("Z", "+00:00")
                )
                resolution_days.append(max(0, (updated_dt - created_dt).days))
            except (ValueError, TypeError):
                pass

        # Action-type tally
        for action in actions:
            action_type_raw = (action.get("type") or "").lower().replace(" ", "_")
            total_actions += 1
            mapped = _ACTION_MAP.get(action_type_raw, "other")
            actions_taken[mapped] += 1

        # Affected entity counts
        for entity in affected_entities:
            etype = (entity.get("entityType") or "").lower()
            if etype in ("host", "endpoint", "computer"):
                affected_entity_counts["endpoints"] += 1
            elif etype in ("account", "user"):
                affected_entity_counts["accounts"] += 1

    # Sort open investigations by days_open descending
    open_investigations.sort(key=lambda x: x["days_open"], reverse=True)

    # Sort stale investigations by days_open descending
    stale_investigations.sort(key=lambda x: x["days_open"], reverse=True)

    avg_resolution_days = (
        round(sum(resolution_days) / len(resolution_days), 2)
        if resolution_days
        else 0.0
    )

    investigations_by_day = [
        {"date": d, "count": c} for d, c in sorted(day_map.items())
    ]

    return {
        "total_investigations": len(investigations),
        "by_status": by_status,
        "by_severity": by_severity,
        "open_investigations": open_investigations,
        "avg_resolution_days": avg_resolution_days,
        "actions_taken": actions_taken,
        "total_actions": total_actions,
        "affected_entity_counts": affected_entity_counts,
        "investigations_by_day": investigations_by_day,
        "stale_investigations": stale_investigations,
    }
