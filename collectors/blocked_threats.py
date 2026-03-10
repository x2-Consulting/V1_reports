"""
Collector for the Blocked Threats & IoCs report.

Fetches all suspicious objects from the Trend Vision One threat intelligence API
and aggregates them by type, risk level, and expiry date.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from client import TrendVisionOneClient


def collect_blocked_threats(client: "TrendVisionOneClient") -> dict:
    """
    Collect all suspicious objects (IoCs) from the threat intelligence API.

    Returns a dict with:
        suspicious_objects, by_type, by_risk, expiring_soon, total
    """
    suspicious_objects: list[dict] = []

    try:
        for item in client.paginate("/v3.0/threatintel/suspiciousObjects"):
            suspicious_objects.append(item)
    except Exception:
        pass

    by_type: dict[str, int] = defaultdict(int)
    by_risk: dict[str, int] = defaultdict(int)
    expiring_soon: list[dict] = []

    now = datetime.now(tz=timezone.utc)
    threshold_30 = now + timedelta(days=30)
    threshold_7 = now + timedelta(days=7)

    normalised: list[dict] = []
    for item in suspicious_objects:
        obj_type = (item.get("type") or "unknown").lower()
        risk_level = (item.get("riskLevel") or "unknown").lower()
        scan_action = item.get("scanAction") or ""
        in_exception = item.get("inExceptionList") or False
        last_modified = item.get("lastModifiedDateTime") or ""
        expires_str = item.get("expiredDateTime") or ""

        # Value: url field for url/domain types, otherwise value field
        value = (
            item.get("url")
            or item.get("domain")
            or item.get("ip")
            or item.get("fileHashValue")
            or item.get("value")
            or ""
        )

        by_type[obj_type] += 1
        by_risk[risk_level] += 1

        # Parse expiry
        expires_soon_flag = False
        critical_expiry = False
        if expires_str:
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                        "%Y-%m-%dT%H:%M:%S+00:00"):
                try:
                    exp_dt = datetime.strptime(expires_str[:26], fmt[:len(fmt)])
                    if exp_dt.tzinfo is None:
                        exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                    if exp_dt <= threshold_30:
                        expires_soon_flag = True
                    if exp_dt <= threshold_7:
                        critical_expiry = True
                    break
                except ValueError:
                    continue

        record = {
            "type": obj_type,
            "value": value,
            "risk_level": risk_level,
            "scan_action": scan_action,
            "in_exception_list": in_exception,
            "expires": expires_str,
            "last_modified": last_modified,
            "critical_expiry": critical_expiry,
        }
        normalised.append(record)

        if expires_soon_flag:
            expiring_soon.append(record)

    # Sort expiring soon by expiry date ascending
    expiring_soon.sort(key=lambda x: x["expires"] or "")

    return {
        "suspicious_objects": normalised,
        "by_type": dict(by_type),
        "by_risk": dict(by_risk),
        "expiring_soon": expiring_soon,
        "total": len(normalised),
    }
