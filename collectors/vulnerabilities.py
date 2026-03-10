"""
Collect vulnerability assessment data from Trend Vision One.
API reference: GET /v3.0/asrm/vulnerabilities
"""

from typing import Any

from client import TrendVisionOneClient

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def collect_vulnerabilities(
    client: TrendVisionOneClient,
    severity: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Fetch vulnerability assessment findings.

    Args:
        client:   Authenticated API client.
        severity: Optional list of severities to include.

    Returns:
        List of vulnerability dicts, sorted by severity.
    """
    vulns = list(
        client.paginate("/v3.0/asrm/vulnerabilities", items_key="items")
    )

    if severity:
        allowed = {s.lower() for s in severity}
        vulns = [v for v in vulns if v.get("severity", "").lower() in allowed]

    vulns.sort(key=lambda v: SEVERITY_ORDER.get(v.get("severity", "").lower(), 99))
    return vulns
