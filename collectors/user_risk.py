"""
Collector for user / account risk data from Trend Vision One ASRM.

Fetches account risk profiles and aggregates risk-level distribution,
sign-in anomaly scores, account types, and top threat factors for
the reporting period.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from client import TrendVisionOneClient


def collect_user_risk(
    client: "TrendVisionOneClient",
    start_time: datetime,
    end_time: datetime,
) -> dict:
    """
    Collect and aggregate user / account risk data.

    Returns a dict with risk-level breakdown, average score,
    high-risk account details, sign-in anomaly distribution,
    account-type counts, and top threat factor types.
    """
    accounts: list[dict] = []
    try:
        for item in client.paginate("/v3.0/asrm/accounts", items_key="items"):
            accounts.append(item)
    except Exception:
        accounts = []

    by_risk_level: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    risk_scores: list[float] = []
    sign_in_anomaly_dist = {"severe": 0, "elevated": 0, "normal": 0}
    accounts_by_type: dict[str, int] = {"cloud": 0, "on_premises": 0, "unknown": 0}
    threat_factor_counts: dict[str, int] = defaultdict(int)

    high_risk_candidates: list[dict] = []

    for acct in accounts:
        risk_score_raw = acct.get("riskScore")
        risk_level = (acct.get("riskLevel") or "unknown").lower()
        sign_in_anomaly_raw = acct.get("signInAnomalyScore")
        account_name = acct.get("accountName") or ""
        last_active = acct.get("lastActiveDateTime") or ""
        account_type = (acct.get("accountType") or "unknown").lower()
        threat_factors = acct.get("threatFactors") or []

        # Risk score
        try:
            risk_score = float(risk_score_raw) if risk_score_raw is not None else 0.0
        except (TypeError, ValueError):
            risk_score = 0.0
        risk_scores.append(risk_score)

        # Risk level counts
        if risk_level in by_risk_level:
            by_risk_level[risk_level] += 1

        # Sign-in anomaly distribution
        try:
            anomaly_score = float(sign_in_anomaly_raw) if sign_in_anomaly_raw is not None else 0.0
        except (TypeError, ValueError):
            anomaly_score = 0.0

        if anomaly_score >= 80:
            sign_in_anomaly_dist["severe"] += 1
        elif anomaly_score >= 50:
            sign_in_anomaly_dist["elevated"] += 1
        else:
            sign_in_anomaly_dist["normal"] += 1

        # Account type
        if account_type in ("cloud",):
            accounts_by_type["cloud"] += 1
        elif account_type in ("on_premises", "onpremises", "on-premises"):
            accounts_by_type["on_premises"] += 1
        else:
            accounts_by_type["unknown"] += 1

        # Threat factors
        top_factor_type = ""
        top_factor_score = -1.0
        for tf in threat_factors:
            tf_type = tf.get("type") or ""
            tf_score_raw = tf.get("score")
            try:
                tf_score = float(tf_score_raw) if tf_score_raw is not None else 0.0
            except (TypeError, ValueError):
                tf_score = 0.0

            if tf_type:
                threat_factor_counts[tf_type] += 1
            if tf_score > top_factor_score:
                top_factor_score = tf_score
                top_factor_type = tf_type

        # Collect high-risk accounts
        if risk_level in ("critical", "high"):
            high_risk_candidates.append(
                {
                    "name": account_name,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "sign_in_anomaly_score": anomaly_score,
                    "last_active": last_active,
                    "top_threat_factor": top_factor_type,
                }
            )

    avg_risk_score = (
        round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0.0
    )

    # Top 20 high-risk accounts by score
    high_risk_accounts = sorted(
        high_risk_candidates, key=lambda x: x["risk_score"], reverse=True
    )[:20]

    # Top 10 threat factor types
    top_threat_factors = sorted(
        [{"type": t, "count": c} for t, c in threat_factor_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]

    return {
        "total_accounts": len(accounts),
        "by_risk_level": by_risk_level,
        "avg_risk_score": avg_risk_score,
        "high_risk_accounts": high_risk_accounts,
        "sign_in_anomaly_distribution": sign_in_anomaly_dist,
        "accounts_by_type": accounts_by_type,
        "top_threat_factors": top_threat_factors,
    }
