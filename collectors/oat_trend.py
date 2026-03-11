"""
Collector for Observed Attack Techniques (OAT) detection trends.

Fetches OAT detections for the given time window and aggregates
risk-level distribution, entity-type breakdown, daily detection
counts, top MITRE techniques, top filter names, and most-targeted
entities for the reporting period.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from client import TrendVisionOneClient


def collect_oat_trend(
    client: "TrendVisionOneClient",
    start_time: datetime,
    end_time: datetime,
) -> dict:
    """
    Collect and aggregate OAT detection trend data.

    Returns a dict with detection counts by risk level, entity type,
    day-by-day breakdown, top MITRE techniques, top filter names, and
    most-targeted entities.
    """
    detections: list[dict] = []
    try:
        params = {
            "startDateTime": start_time.isoformat(),
            "endDateTime": end_time.isoformat(),
        }
        for item in client.paginate(
            "/v3.0/oat/detections", params=params, items_key="items"
        ):
            detections.append(item)
    except Exception:
        detections = []

    by_risk_level: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_entity_type: dict[str, int] = {"host": 0, "account": 0, "other": 0}

    # day -> {"count": int, "high_risk_count": int}
    day_map: dict[str, dict] = defaultdict(lambda: {"count": 0, "high_risk_count": 0})

    # technique_id -> {"count": int, "risk_level": str}
    technique_counts: dict[str, dict] = {}
    # filter_name -> {"count": int, "risk_level": str}
    filter_name_counts: dict[str, dict] = {}
    # entity_name -> {"type": str, "detection_count": int}
    entity_counts: dict[str, dict] = {}

    for det in detections:
        detected_dt = det.get("detectedDateTime") or ""
        entity_type_raw = (det.get("entityType") or "").lower()
        entity_name = det.get("entityName") or ""
        filters = det.get("filters") or []

        # Daily count
        day = ""
        if detected_dt:
            try:
                dt = datetime.fromisoformat(detected_dt.replace("Z", "+00:00"))
                day = dt.strftime("%Y-%m-%d")
            except (ValueError, TypeError):
                day = detected_dt[:10] if len(detected_dt) >= 10 else ""

        # Entity type bucketing
        if entity_type_raw in ("host", "endpoint", "computer"):
            bucket = "host"
        elif entity_type_raw in ("account", "user"):
            bucket = "account"
        else:
            bucket = "other"
        by_entity_type[bucket] += 1

        # Entity occurrence tracking
        if entity_name:
            if entity_name not in entity_counts:
                entity_counts[entity_name] = {"type": entity_type_raw, "detection_count": 0}
            entity_counts[entity_name]["detection_count"] += 1

        # Per-filter aggregation
        detection_is_high_risk = False
        for f in filters:
            risk = (f.get("riskLevel") or "unknown").lower()
            fname = f.get("name") or "Unknown"
            mitre_ids = f.get("mitreTechniqueIds") or []

            # Risk level counts
            if risk in by_risk_level:
                by_risk_level[risk] += 1
            if risk in ("critical", "high"):
                detection_is_high_risk = True

            # Filter name counts
            if fname not in filter_name_counts:
                filter_name_counts[fname] = {"count": 0, "risk_level": risk}
            filter_name_counts[fname]["count"] += 1

            # MITRE technique counts
            for tid in mitre_ids:
                if not tid:
                    continue
                if tid not in technique_counts:
                    technique_counts[tid] = {"count": 0, "risk_level": risk}
                technique_counts[tid]["count"] += 1

        # Daily aggregation
        if day:
            day_map[day]["count"] += 1
            if detection_is_high_risk:
                day_map[day]["high_risk_count"] += 1

    # Build sorted detections_by_day
    detections_by_day = [
        {"date": d, "count": v["count"], "high_risk_count": v["high_risk_count"]}
        for d, v in sorted(day_map.items())
    ]

    # Top 15 MITRE techniques
    top_techniques = sorted(
        [
            {"technique_id": tid, "count": v["count"], "risk_level": v["risk_level"]}
            for tid, v in technique_counts.items()
        ],
        key=lambda x: x["count"],
        reverse=True,
    )[:15]

    # Top 15 filter names
    top_filter_names = sorted(
        [
            {"name": n, "count": v["count"], "risk_level": v["risk_level"]}
            for n, v in filter_name_counts.items()
        ],
        key=lambda x: x["count"],
        reverse=True,
    )[:15]

    # Top 10 most-targeted entities
    most_targeted_entities = sorted(
        [
            {"name": n, "type": v["type"], "detection_count": v["detection_count"]}
            for n, v in entity_counts.items()
        ],
        key=lambda x: x["detection_count"],
        reverse=True,
    )[:10]

    return {
        "total_detections": len(detections),
        "by_risk_level": by_risk_level,
        "by_entity_type": by_entity_type,
        "detections_by_day": detections_by_day,
        "top_techniques": top_techniques,
        "top_filter_names": top_filter_names,
        "most_targeted_entities": most_targeted_entities,
    }
