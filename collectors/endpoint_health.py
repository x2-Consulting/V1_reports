"""
Collector for endpoint health and protection coverage.

Fetches all endpoints from the EIQS inventory, then aggregates
connectivity status, OS distribution, agent version spread, stale
endpoints, and protection-product coverage gaps.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from client import TrendVisionOneClient

_KEY_PRODUCTS = {"Endpoint Sensor", "Endpoint Protection"}


def collect_endpoint_health(client: "TrendVisionOneClient") -> dict:
    """
    Collect and aggregate endpoint health data.

    Returns a dict with connectivity counts, OS/version breakdowns,
    stale-endpoint list, coverage gaps, and protection-status counts.
    """
    endpoints: list[dict] = []
    try:
        for item in client.paginate("/v3.0/eiqs/endpoints", items_key="items"):
            endpoints.append(item)
    except Exception:
        endpoints = []

    now = datetime.now(tz=timezone.utc)

    connected = 0
    disconnected = 0
    never_seen = 0

    by_os: dict[str, int] = defaultdict(int)
    by_agent_version: dict[str, int] = defaultdict(int)

    stale_endpoints: list[dict] = []
    coverage_gaps: list[dict] = []

    protection_status_counts = {"protected": 0, "not_protected": 0, "unknown": 0}

    for ep in endpoints:
        conn_status = ep.get("connectionStatus") or ""
        last_conn = ep.get("lastConnectedDateTime") or ""
        os_name = ep.get("osName") or ""
        os_version = ep.get("osVersion") or ""
        agent_version = ep.get("agentVersion") or "unknown"
        display_name = ep.get("displayName") or ep.get("agentGuid") or ""
        installed_products = ep.get("installedProducts") or []
        prot_status = (ep.get("protectionStatus") or "unknown").lower()

        # Connectivity counts
        if conn_status == "Connected":
            connected += 1
        else:
            disconnected += 1

        if not last_conn:
            never_seen += 1

        # OS grouping
        os_label = f"{os_name} {os_version}".strip() or "Unknown"
        by_os[os_label] += 1

        # Agent version grouping
        by_agent_version[agent_version] += 1

        # Protection status
        if prot_status == "protected":
            protection_status_counts["protected"] += 1
        elif prot_status in ("not_protected", "notprotected"):
            protection_status_counts["not_protected"] += 1
        else:
            protection_status_counts["unknown"] += 1

        # Stale endpoint detection (disconnected > 30 days)
        if conn_status != "Connected" and last_conn:
            try:
                dt = datetime.fromisoformat(last_conn.replace("Z", "+00:00"))
                days_offline = (now - dt).days
                if days_offline > 30:
                    stale_endpoints.append(
                        {
                            "name": display_name,
                            "last_seen": last_conn,
                            "os": os_label,
                            "days_offline": days_offline,
                        }
                    )
            except (ValueError, TypeError):
                pass

        # Coverage gap detection
        installed_names = {
            (p.get("name") or "") for p in installed_products
        }
        missing = [
            prod for prod in _KEY_PRODUCTS if prod not in installed_names
        ]
        if missing:
            coverage_gaps.append(
                {
                    "name": display_name,
                    "missing_products": sorted(missing),
                }
            )

    # Sort stale endpoints by days offline descending
    stale_endpoints.sort(key=lambda x: x["days_offline"], reverse=True)

    return {
        "total_endpoints": len(endpoints),
        "connected": connected,
        "disconnected": disconnected,
        "never_seen": never_seen,
        "by_os": dict(by_os),
        "by_agent_version": dict(by_agent_version),
        "stale_endpoints": stale_endpoints,
        "coverage_gaps": coverage_gaps,
        "protection_status_counts": protection_status_counts,
    }
