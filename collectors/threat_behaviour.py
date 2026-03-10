"""
Collector for the Threat Behaviour Analysis report.

Groups OAT detections into behaviour categories based on filter name keywords,
then builds per-category summaries and a date-based timeline.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from client import TrendVisionOneClient

# ── Category keyword mapping ──────────────────────────────────────────────────

_CATEGORY_KEYWORDS: list[tuple[list[str], str]] = [
    (["Logon", "Kerberos", "Credential"],             "Credential Access & Logon Failures"),
    (["PowerShell", "Registry", "Discovery"],          "Reconnaissance & Discovery"),
    (["Service"],                                      "Persistence & Service Manipulation"),
    (["Exfiltration", "HTTP", "DNS"],                  "Data Exfiltration Signals"),
    (["RMM", "AnyDesk", "Remote", "SuperOps"],         "Remote Access Tools"),
    (["Domain", "URL", "Web Reputation", "Untested"],  "Suspicious Network Activity"),
    (["Email", "Mail", "Sender"],                      "Email-Based Threats"),
]
_DEFAULT_CATEGORY = "Other Behavioural Signals"


def _categorise(filter_name: str) -> str:
    """Map a filter name to a behaviour category."""
    for keywords, category in _CATEGORY_KEYWORDS:
        for kw in keywords:
            if kw.lower() in filter_name.lower():
                return category
    return _DEFAULT_CATEGORY


def collect_threat_behaviours(
    client: "TrendVisionOneClient",
    start_time: datetime,
    end_time: datetime,
) -> dict:
    """
    Collect and categorise OAT detections into behaviour groups.

    Returns a dict with:
        categories, timeline, total_detections, unique_filters_seen
    """
    start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    # category -> filter_name -> {count, risk_level, entity_set, mitre_techniques}
    cat_filter_data: dict[str, dict[str, dict]] = defaultdict(dict)
    # category -> top entities (name -> count)
    cat_entities: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    # date -> category -> count
    timeline_raw: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    total_detections = 0
    unique_filters: set[str] = set()

    try:
        params = {
            "startDateTime": start_str,
            "endDateTime": end_str,
        }
        for det in client.paginate("/v3.0/oat/detections", params=params):
            total_detections += 1
            entity_name = det.get("entityName") or ""
            detected = det.get("detectedDateTime") or ""
            day = detected[:10] if detected else "unknown"
            filters = det.get("filters") or []

            for f in filters:
                fname = f.get("name") or "Unknown"
                risk = (f.get("riskLevel") or "unknown").lower()
                tids = f.get("mitreTechniqueIds") or []
                taids = f.get("mitreTacticIds") or []

                unique_filters.add(fname)
                category = _categorise(fname)
                timeline_raw[day][category] += 1

                if fname not in cat_filter_data[category]:
                    cat_filter_data[category][fname] = {
                        "filter_name": fname,
                        "count": 0,
                        "risk_level": risk,
                        "example_entities": [],
                        "_entity_set": set(),
                        "mitre_techniques": list(set(tids + taids)),
                    }
                entry = cat_filter_data[category][fname]
                entry["count"] += 1
                if entity_name:
                    entry["_entity_set"].add(entity_name)
                    cat_entities[category][entity_name] += 1
    except Exception:
        pass

    # ── Finalise category records ─────────────────────────────────────────────
    categories: list[dict] = []
    for cat, filter_dict in cat_filter_data.items():
        total_count = sum(fd["count"] for fd in filter_dict.values())
        detections_list: list[dict] = []
        for fname, fd in sorted(
            filter_dict.items(), key=lambda x: x[1]["count"], reverse=True
        ):
            example_entities = sorted(fd["_entity_set"])[:5]
            detections_list.append({
                "filter_name": fd["filter_name"],
                "count": fd["count"],
                "risk_level": fd["risk_level"],
                "example_entities": example_entities,
                "mitre_techniques": sorted(set(fd["mitre_techniques"])),
            })

        top_entities_raw = cat_entities.get(cat, {})
        top_entities = [
            k for k, _ in sorted(
                top_entities_raw.items(), key=lambda x: x[1], reverse=True
            )[:5]
        ]

        categories.append({
            "name": cat,
            "total_count": total_count,
            "detections": detections_list,
            "top_entities": top_entities,
        })

    categories.sort(key=lambda x: x["total_count"], reverse=True)

    # ── Build timeline ────────────────────────────────────────────────────────
    timeline = [
        {"date": day, "category_counts": dict(cats)}
        for day, cats in sorted(timeline_raw.items())
    ]

    return {
        "categories": categories,
        "timeline": timeline,
        "total_detections": total_detections,
        "unique_filters_seen": len(unique_filters),
    }
