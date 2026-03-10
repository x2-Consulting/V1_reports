"""
Collector for the Most Targeted Assets report.

Merges host and account data from workbench alerts and OAT detections
to build risk-ranked asset lists.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from client import TrendVisionOneClient


def collect_targeted_assets(
    client: "TrendVisionOneClient",
    start_time: datetime,
    end_time: datetime,
) -> dict:
    """
    Collect targeted asset data from alerts and OAT detections.

    Returns a dict with:
        hosts, accounts, total_unique_hosts, total_unique_accounts, high_risk_hosts
    """
    start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    # host_data[name] = {alert_count, oat_count, ips, alert_severities, threat_types, last_seen}
    host_data: dict[str, dict] = {}
    # account_data[name] = {alert_count, alert_types, last_seen}
    account_data: dict[str, dict] = {}

    # ── Process workbench alerts ──────────────────────────────────────────────
    try:
        params = {
            "startDateTime": start_str,
            "endDateTime": end_str,
        }
        for alert in client.paginate("/v3.0/workbench/alerts", params=params):
            sev = (alert.get("severity") or "unknown").lower()
            model = alert.get("model") or "Unknown"
            created = alert.get("createdDateTime") or ""

            impact = alert.get("impactScope") or {}
            entities = impact.get("entities") or []

            for entity in entities:
                etype = (entity.get("entityType") or "").lower()
                evalue = entity.get("entityValue") or {}

                if isinstance(evalue, dict):
                    name = evalue.get("name") or ""
                    ips = evalue.get("ips") or []
                else:
                    name = str(evalue)
                    ips = []

                if not name:
                    continue

                if etype in ("host", "endpoint", "computer"):
                    if name not in host_data:
                        host_data[name] = {
                            "name": name,
                            "ip": "",
                            "alert_count": 0,
                            "oat_count": 0,
                            "total_hits": 0,
                            "alert_severities": defaultdict(int),
                            "top_threat_types": [],
                            "_threat_type_set": defaultdict(int),
                            "last_seen": "",
                            "_ips": set(),
                        }
                    h = host_data[name]
                    h["alert_count"] += 1
                    h["alert_severities"][sev] += 1
                    h["_threat_type_set"][model] += 1
                    for ip in ips:
                        if ip:
                            h["_ips"].add(ip)
                    if created > h["last_seen"]:
                        h["last_seen"] = created

                elif etype in ("account", "user"):
                    if name not in account_data:
                        account_data[name] = {
                            "name": name,
                            "alert_count": 0,
                            "_alert_type_set": defaultdict(int),
                            "last_seen": "",
                        }
                    a = account_data[name]
                    a["alert_count"] += 1
                    a["_alert_type_set"][model] += 1
                    if created > a["last_seen"]:
                        a["last_seen"] = created
    except Exception:
        pass

    # ── Process OAT detections ────────────────────────────────────────────────
    try:
        params = {
            "startDateTime": start_str,
            "endDateTime": end_str,
        }
        for det in client.paginate("/v3.0/oat/detections", params=params):
            entity_name = det.get("entityName") or ""
            entity_type = (det.get("entityType") or "").lower()
            detected = det.get("detectedDateTime") or ""
            filters = det.get("filters") or []
            filter_names = [f.get("name") or "Unknown" for f in filters]

            if not entity_name:
                continue

            if entity_type in ("host", "endpoint", "computer", ""):
                if entity_name not in host_data:
                    host_data[entity_name] = {
                        "name": entity_name,
                        "ip": "",
                        "alert_count": 0,
                        "oat_count": 0,
                        "total_hits": 0,
                        "alert_severities": defaultdict(int),
                        "top_threat_types": [],
                        "_threat_type_set": defaultdict(int),
                        "last_seen": "",
                        "_ips": set(),
                    }
                h = host_data[entity_name]
                h["oat_count"] += 1
                for fn in filter_names:
                    h["_threat_type_set"][fn] += 1
                if detected > h["last_seen"]:
                    h["last_seen"] = detected
    except Exception:
        pass

    # ── Finalise host records ─────────────────────────────────────────────────
    hosts: list[dict] = []
    for name, h in host_data.items():
        h["total_hits"] = h["alert_count"] + h["oat_count"]
        # Pick first IP
        ips_sorted = sorted(h["_ips"])
        h["ip"] = ips_sorted[0] if ips_sorted else ""
        # Top 3 threat types by count
        h["top_threat_types"] = [
            k for k, _ in sorted(
                h["_threat_type_set"].items(), key=lambda x: x[1], reverse=True
            )[:3]
        ]
        h["alert_severities"] = dict(h["alert_severities"])
        # Remove internal fields
        del h["_threat_type_set"]
        del h["_ips"]
        hosts.append(h)

    hosts.sort(key=lambda x: x["total_hits"], reverse=True)

    # ── Finalise account records ──────────────────────────────────────────────
    accounts: list[dict] = []
    for name, a in account_data.items():
        a["alert_types"] = [
            k for k, _ in sorted(
                a["_alert_type_set"].items(), key=lambda x: x[1], reverse=True
            )[:5]
        ]
        del a["_alert_type_set"]
        accounts.append(a)

    accounts.sort(key=lambda x: x["alert_count"], reverse=True)

    high_risk_hosts = sum(1 for h in hosts if h["alert_count"] > 5)

    return {
        "hosts": hosts,
        "accounts": accounts,
        "total_unique_hosts": len(hosts),
        "total_unique_accounts": len(accounts),
        "high_risk_hosts": high_risk_hosts,
    }
