"""
Collect threat intelligence / IoCs from Trend Vision One.
API references:
  - Suspicious objects: GET /v3.0/threatintel/suspiciousObjects
  - STIX packages:      GET /v3.0/threatintel/stixPackages  (optional)
"""

from typing import Any

from client import TrendVisionOneClient

# Object types supported by the suspicious objects endpoint
OBJECT_TYPES = ("ip", "url", "domain", "fileSha256", "fileSha1", "sender")


def collect_suspicious_objects(
    client: TrendVisionOneClient,
    object_types: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Fetch suspicious objects (IoCs) from Trend Vision One.

    Args:
        client:       Authenticated API client.
        object_types: Filter by object type(s). Defaults to all types.

    Returns:
        List of suspicious object dicts.
    """
    types = object_types or list(OBJECT_TYPES)
    results: list[dict[str, Any]] = []

    for obj_type in types:
        objects = list(
            client.paginate(
                "/v3.0/threatintel/suspiciousObjects",
                params={"type": obj_type},
                items_key="items",
            )
        )
        for obj in objects:
            obj.setdefault("objectType", obj_type)
        results.extend(objects)

    return results
