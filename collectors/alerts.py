"""
Collect Workbench alerts from Trend Vision One.
API reference: GET /v3.0/workbench/alerts
"""

from datetime import datetime, timezone
from typing import Any

from client import TrendVisionOneClient


def collect_alerts(
    client: TrendVisionOneClient,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    severity: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Fetch Workbench alerts.

    Args:
        client:     Authenticated API client.
        start_time: Filter alerts created after this time (UTC).
        end_time:   Filter alerts created before this time (UTC).
        severity:   Optional list of severities to include, e.g. ['critical', 'high'].

    Returns:
        List of alert dicts.
    """
    params: dict[str, Any] = {}

    if start_time:
        params["startDateTime"] = _iso(start_time)
    if end_time:
        params["endDateTime"] = _iso(end_time)

    alerts = list(
        client.paginate("/v3.0/workbench/alerts", params=params, items_key="items")
    )

    if severity:
        allowed = {s.lower() for s in severity}
        alerts = [a for a in alerts if a.get("severity", "").lower() in allowed]

    return alerts


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
