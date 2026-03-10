"""
Collect endpoint sensor data from Trend Vision One.
API reference: GET /v3.0/eiqs/endpoints
"""

from typing import Any

from client import TrendVisionOneClient


def collect_endpoints(
    client: TrendVisionOneClient,
    agent_guid: str | None = None,
) -> list[dict[str, Any]]:
    """
    Fetch endpoint inventory and sensor status.

    Args:
        client:     Authenticated API client.
        agent_guid: Optional specific agent GUID to fetch.

    Returns:
        List of endpoint dicts.
    """
    if agent_guid:
        data = client.get(f"/v3.0/eiqs/endpoints/{agent_guid}")
        return [data]

    return list(
        client.paginate("/v3.0/eiqs/endpoints", items_key="items")
    )
