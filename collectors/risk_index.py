"""
Collector for ASRM risk index data from Trend Vision One.

Fetches risk index records for all asset types and aggregates
asset-type distribution, average risk score, risk-level distribution
using ASRM thresholds, top high-risk assets, and average scores per
risk component type.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from client import TrendVisionOneClient


def _risk_band(score: float) -> str:
    """Map a numeric risk score to a named risk band."""
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def collect_risk_index(
    client: "TrendVisionOneClient",
    start_time: datetime,
    end_time: datetime,
) -> dict:
    """
    Collect and aggregate ASRM risk index data.

    Returns a dict with asset counts by type, average risk score,
    risk distribution, top-risk assets, and component-type averages.
    """
    assets: list[dict] = []
    try:
        for item in client.paginate("/v3.0/asrm/riskIndexes", items_key="items"):
            assets.append(item)
    except Exception:
        assets = []

    by_asset_type: dict[str, int] = {
        "endpoint": 0,
        "user": 0,
        "cloud_app": 0,
        "other": 0,
    }
    risk_distribution: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    risk_scores: list[float] = []

    # component_type -> list of scores (to compute average later)
    component_scores: dict[str, list[float]] = defaultdict(list)

    top_risk_candidates: list[dict] = []

    for asset in assets:
        asset_type_raw = (asset.get("assetType") or "").lower()
        asset_name = asset.get("assetName") or ""
        risk_score_raw = asset.get("riskScore")
        risk_level = (asset.get("riskLevel") or "").lower()
        components = asset.get("riskIndexComponents") or []

        # Risk score
        try:
            risk_score = float(risk_score_raw) if risk_score_raw is not None else 0.0
        except (TypeError, ValueError):
            risk_score = 0.0
        risk_scores.append(risk_score)

        # Asset type bucketing
        if asset_type_raw in ("endpoint", "host", "computer"):
            type_key = "endpoint"
        elif asset_type_raw in ("user", "account"):
            type_key = "user"
        elif asset_type_raw in ("cloud_app", "cloudapp", "cloud"):
            type_key = "cloud_app"
        else:
            type_key = "other"
        by_asset_type[type_key] += 1

        # Risk distribution (use computed band; fall back to reported level)
        band = _risk_band(risk_score) if risk_score_raw is not None else (
            risk_level if risk_level in risk_distribution else "low"
        )
        risk_distribution[band] += 1

        # Component scores
        top_component_type = ""
        top_component_score = -1.0
        for comp in components:
            comp_type = (comp.get("componentType") or "").lower()
            comp_score_raw = comp.get("score")
            try:
                comp_score = float(comp_score_raw) if comp_score_raw is not None else 0.0
            except (TypeError, ValueError):
                comp_score = 0.0

            if comp_type:
                component_scores[comp_type].append(comp_score)

            if comp_score > top_component_score:
                top_component_score = comp_score
                top_component_type = comp_type

        top_risk_candidates.append(
            {
                "name": asset_name,
                "type": asset_type_raw,
                "score": risk_score,
                "risk_level": band,
                "top_component": top_component_type,
            }
        )

    avg_risk_score = (
        round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0.0
    )

    # Top 20 assets by score
    top_risk_assets = sorted(
        top_risk_candidates, key=lambda x: x["score"], reverse=True
    )[:20]

    # Average score per component type for the three key types
    def _avg(scores: list[float]) -> float:
        return round(sum(scores) / len(scores), 2) if scores else 0.0

    risk_by_component_type = {
        "vulnerability": _avg(component_scores.get("vulnerability", [])),
        "threat_detection": _avg(component_scores.get("threat_detection", [])),
        "identity_risk": _avg(component_scores.get("identity_risk", [])),
    }

    return {
        "total_assets": len(assets),
        "by_asset_type": by_asset_type,
        "avg_risk_score": avg_risk_score,
        "risk_distribution": risk_distribution,
        "top_risk_assets": top_risk_assets,
        "risk_by_component_type": risk_by_component_type,
    }
