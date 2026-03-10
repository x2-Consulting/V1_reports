"""
Collector for the Executive Summary report.

Fetches workbench alerts, OAT detections, and suspicious objects,
then aggregates key metrics for the PDF generator.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from client import TrendVisionOneClient


def collect_executive_summary(
    client: "TrendVisionOneClient",
    start_time: datetime,
    end_time: datetime,
) -> dict:
    """
    Collect and aggregate data for the Executive Summary report.

    Returns a dict with:
        total_alerts, alerts_by_severity, alerts_by_status,
        open_unowned, avg_risk_score, top_threat_models,
        alerts_by_day, total_oat_detections, oat_by_risk,
        top_oat_behaviours, total_iocs, iocs_by_risk,
        most_impacted_hosts, most_impacted_accounts, incident_count
    """
    start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── Fetch alerts ──────────────────────────────────────────────────────────
    alerts: list[dict] = []
    try:
        params = {
            "startDateTime": start_str,
            "endDateTime": end_str,
        }
        for item in client.paginate("/v3.0/workbench/alerts", params=params):
            alerts.append(item)
    except Exception as exc:
        alerts = []

    # ── Fetch OAT detections ──────────────────────────────────────────────────
    oat_detections: list[dict] = []
    try:
        params = {
            "startDateTime": start_str,
            "endDateTime": end_str,
        }
        for item in client.paginate("/v3.0/oat/detections", params=params):
            oat_detections.append(item)
    except Exception as exc:
        oat_detections = []

    # ── Fetch suspicious objects (IoCs) ───────────────────────────────────────
    iocs: list[dict] = []
    try:
        for item in client.paginate("/v3.0/threatintel/suspiciousObjects"):
            iocs.append(item)
    except Exception as exc:
        iocs = []

    # ── Alert aggregation ─────────────────────────────────────────────────────
    alerts_by_severity: dict[str, int] = defaultdict(int)
    alerts_by_status: dict[str, int] = defaultdict(int)
    open_unowned = 0
    risk_scores: list[float] = []
    model_counts: dict[str, dict] = {}
    day_counts: dict[str, int] = defaultdict(int)
    incident_ids: set = set()

    # host_alert_count and account_alert_count for most-impacted
    host_alert_count: dict[str, int] = defaultdict(int)
    account_alert_count: dict[str, int] = defaultdict(int)

    for alert in alerts:
        sev = (alert.get("severity") or "unknown").lower()
        alerts_by_severity[sev] += 1

        status = alert.get("status") or "unknown"
        alerts_by_status[status] += 1

        owner_ids = alert.get("ownerIds") or []
        if status in ("New", "Open", "In Progress") and not owner_ids:
            open_unowned += 1

        score = alert.get("score")
        if score is not None:
            try:
                risk_scores.append(float(score))
            except (TypeError, ValueError):
                pass

        # Threat model counts
        model = alert.get("model") or "Unknown"
        if model not in model_counts:
            model_counts[model] = {"name": model, "count": 0, "severity": sev}
        model_counts[model]["count"] += 1

        # Alerts by day
        created = alert.get("createdDateTime") or ""
        if created:
            day = created[:10]
            day_counts[day] += 1

        # Incident IDs
        inc_id = alert.get("incidentId")
        if inc_id:
            incident_ids.add(inc_id)

        # Extract hosts and accounts from impactScope
        impact = alert.get("impactScope") or {}
        entities = impact.get("entities") or []
        for entity in entities:
            etype = (entity.get("entityType") or "").lower()
            evalue = entity.get("entityValue") or {}
            if isinstance(evalue, dict):
                name = evalue.get("name") or ""
            else:
                name = str(evalue)
            if not name:
                continue
            if etype in ("host", "endpoint", "computer"):
                host_alert_count[name] += 1
            elif etype in ("account", "user"):
                account_alert_count[name] += 1

    avg_risk_score = round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0.0

    # Top 10 threat models
    top_threat_models = sorted(
        model_counts.values(), key=lambda x: x["count"], reverse=True
    )[:10]

    # Alerts by day sorted ascending
    alerts_by_day = [
        {"date": d, "count": c}
        for d, c in sorted(day_counts.items())
    ]

    # ── OAT aggregation ───────────────────────────────────────────────────────
    oat_by_risk: dict[str, int] = defaultdict(int)
    oat_behaviour_counts: dict[str, dict] = {}
    host_oat_count: dict[str, int] = defaultdict(int)

    for det in oat_detections:
        filters = det.get("filters") or []
        entity_name = det.get("entityName") or ""
        entity_type = (det.get("entityType") or "").lower()

        for f in filters:
            risk = (f.get("riskLevel") or "unknown").lower()
            oat_by_risk[risk] += 1
            fname = f.get("name") or "Unknown"
            if fname not in oat_behaviour_counts:
                oat_behaviour_counts[fname] = {
                    "name": fname, "count": 0, "risk_level": risk
                }
            oat_behaviour_counts[fname]["count"] += 1

        if entity_name and entity_type in ("host", "endpoint", "computer", ""):
            host_oat_count[entity_name] += 1

    top_oat_behaviours = sorted(
        oat_behaviour_counts.values(), key=lambda x: x["count"], reverse=True
    )[:10]

    # ── IoC aggregation ───────────────────────────────────────────────────────
    iocs_by_risk: dict[str, int] = defaultdict(int)
    for ioc in iocs:
        risk = (ioc.get("riskLevel") or "unknown").lower()
        iocs_by_risk[risk] += 1

    # ── Most impacted hosts (merge alerts + OAT) ─────────────────────────────
    all_host_names: set[str] = set(host_alert_count.keys()) | set(host_oat_count.keys())
    host_combined: list[dict] = []
    for name in all_host_names:
        ac = host_alert_count.get(name, 0)
        oc = host_oat_count.get(name, 0)
        host_combined.append({
            "name": name,
            "alert_count": ac,
            "oat_count": oc,
            "total_hits": ac + oc,
        })
    most_impacted_hosts = sorted(
        host_combined, key=lambda x: x["total_hits"], reverse=True
    )[:10]

    # ── Most impacted accounts ────────────────────────────────────────────────
    most_impacted_accounts = sorted(
        [{"name": n, "count": c} for n, c in account_alert_count.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:5]

    return {
        "total_alerts": len(alerts),
        "alerts_by_severity": dict(alerts_by_severity),
        "alerts_by_status": dict(alerts_by_status),
        "open_unowned": open_unowned,
        "avg_risk_score": avg_risk_score,
        "top_threat_models": top_threat_models,
        "alerts_by_day": alerts_by_day,
        "total_oat_detections": len(oat_detections),
        "oat_by_risk": dict(oat_by_risk),
        "top_oat_behaviours": top_oat_behaviours,
        "total_iocs": len(iocs),
        "iocs_by_risk": dict(iocs_by_risk),
        "most_impacted_hosts": most_impacted_hosts,
        "most_impacted_accounts": most_impacted_accounts,
        "incident_count": len(incident_ids),
    }
