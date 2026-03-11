"""
Collector for attack surface posture data from Trend Vision One ASRM.

Calls three independent ASRM endpoints — overall posture, risk levels
by category, and individual assessments — and aggregates the results
into a single posture summary dict. Each API call is wrapped in its own
try/except so a single failure returns partial data rather than nothing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from client import TrendVisionOneClient


def _posture_grade(score: float) -> str:
    """Convert a numeric posture score (0-100) to a letter grade."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 45:
        return "D"
    return "F"


def collect_attack_surface(
    client: "TrendVisionOneClient",
    start_time: datetime,
    end_time: datetime,
) -> dict:
    """
    Collect and aggregate attack surface posture data.

    Returns a dict with the overall posture score and grade, per-category
    risk levels, assessment pass/fail counts, critical findings, and top
    recommendations. Any failed API call contributes empty/zero values.
    """
    # ── Overall posture score ────────────────────────────────────────────────
    overall_posture_score = 0.0
    try:
        surface_data = client.get("/v3.0/asrm/attackSurface")
        raw_score = surface_data.get("score") if surface_data else None
        overall_posture_score = float(raw_score) if raw_score is not None else 0.0
    except Exception:
        pass

    posture_grade = _posture_grade(overall_posture_score)

    # ── Risk levels by category ──────────────────────────────────────────────
    by_risk_category: dict[str, dict] = {
        "endpoint": {"score": 0.0, "level": "unknown"},
        "identity": {"score": 0.0, "level": "unknown"},
        "cloud": {"score": 0.0, "level": "unknown"},
        "network": {"score": 0.0, "level": "unknown"},
    }
    try:
        rl_data = client.get("/v3.0/asrm/attackSurfaceRiskLevels")
        categories = rl_data.get("categories") or [] if rl_data else []
        for cat in categories:
            cat_name = (cat.get("name") or "").lower()
            cat_score_raw = cat.get("score")
            cat_level = (cat.get("riskLevel") or "unknown").lower()
            try:
                cat_score = float(cat_score_raw) if cat_score_raw is not None else 0.0
            except (TypeError, ValueError):
                cat_score = 0.0
            if cat_name in by_risk_category:
                by_risk_category[cat_name] = {"score": cat_score, "level": cat_level}
    except Exception:
        pass

    # ── Assessments ──────────────────────────────────────────────────────────
    total_assessments = 0
    passed_assessments = 0
    failed_assessments = 0
    critical_findings: list[dict] = []
    all_recommendations: list[str] = []

    try:
        assessments: list[dict] = []
        for item in client.paginate("/v3.0/asrm/assessments", items_key="items"):
            assessments.append(item)

        total_assessments = len(assessments)

        for assessment in assessments:
            status = (assessment.get("status") or "").lower()
            title = assessment.get("title") or ""
            category = assessment.get("category") or ""
            impact = assessment.get("impact") or ""
            recommendation = assessment.get("recommendation") or ""

            if status == "passed":
                passed_assessments += 1
            else:
                failed_assessments += 1
                critical_findings.append(
                    {
                        "title": title,
                        "category": category,
                        "impact": impact,
                        "recommendation": recommendation,
                    }
                )

            if recommendation:
                all_recommendations.append(recommendation)

    except Exception:
        pass

    # Top 5 unique recommendations from failed assessments
    seen_recs: list[str] = []
    for rec in all_recommendations:
        if rec not in seen_recs:
            seen_recs.append(rec)
        if len(seen_recs) == 5:
            break
    top_recommendations = seen_recs

    return {
        "overall_posture_score": overall_posture_score,
        "posture_grade": posture_grade,
        "by_risk_category": by_risk_category,
        "total_assessments": total_assessments,
        "passed_assessments": passed_assessments,
        "failed_assessments": failed_assessments,
        "critical_findings": critical_findings,
        "top_recommendations": top_recommendations,
    }
