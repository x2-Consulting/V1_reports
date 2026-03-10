"""
NIST NVD (National Vulnerability Database) API v2 client.

Enriches a list of CVE IDs with official data:
  - Authoritative English description
  - CVSS v3.1 (or v3.0 / v2.0 fallback) base score and severity
  - CWE weakness identifier(s)
  - Patch / advisory reference URLs

Rate limits (per NVD docs):
  Without API key : 5 requests / 30 seconds
  With API key    : 50 requests / 30 seconds

The client automatically throttles to stay within the limit and retries
once on HTTP 403/429.

Usage:
    from collectors.nvd import enrich_cves
    enriched = enrich_cves(["CVE-2024-21412", "CVE-2024-38063"], api_key="abc123")
    # enriched["CVE-2024-21412"] → dict with description, cvss, severity, cwe, refs
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

# Make web/ importable when this module is used from collectors/ context
_web_dir = str(Path(__file__).resolve().parent.parent / "web")
if _web_dir not in sys.path:
    sys.path.insert(0, _web_dir)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Requests per window allowed by NVD
_WINDOW_SECS = 30
_LIMIT_WITH_KEY = 50
_LIMIT_NO_KEY   = 5


class NVDClient:
    """Thin NVD API v2 client with rate limiting and a per-instance cache."""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("NVD_API_KEY", "")
        self._limit = _LIMIT_WITH_KEY if self.api_key else _LIMIT_NO_KEY
        self._cache: dict[str, dict] = {}
        self._request_times: list[float] = []

    # ── Rate limiting ─────────────────────────────────────────────────────────

    def _throttle(self) -> None:
        """Block until we can safely make another request."""
        now = time.monotonic()
        cutoff = now - _WINDOW_SECS
        self._request_times = [t for t in self._request_times if t > cutoff]
        if len(self._request_times) >= self._limit:
            sleep_for = _WINDOW_SECS - (now - self._request_times[0]) + 0.1
            if sleep_for > 0:
                time.sleep(sleep_for)
        self._request_times.append(time.monotonic())

    # ── Single CVE lookup ─────────────────────────────────────────────────────

    def lookup(self, cve_id: str) -> dict:
        """
        Return enrichment dict for a single CVE ID.
        Returns an empty dict if the CVE is not found or the request fails.
        """
        cve_id = cve_id.upper().strip()
        if cve_id in self._cache:
            return self._cache[cve_id]

        headers = {"apiKey": self.api_key} if self.api_key else {}
        self._throttle()

        for attempt in range(2):
            try:
                resp = httpx.get(
                    NVD_BASE,
                    params={"cveId": cve_id},
                    headers=headers,
                    timeout=15,
                )
                if resp.status_code in (403, 429):
                    time.sleep(35)   # back off a full window
                    continue
                resp.raise_for_status()
                data = resp.json()
                break
            except Exception:
                if attempt == 0:
                    time.sleep(5)
                    continue
                self._cache[cve_id] = {}
                return {}

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            self._cache[cve_id] = {}
            return {}

        result = _parse_nvd_cve(vulns[0].get("cve", {}))
        self._cache[cve_id] = result
        return result


# ── NVD response parser ───────────────────────────────────────────────────────

def _parse_nvd_cve(cve: dict) -> dict:
    """Extract the fields we care about from a raw NVD CVE object."""

    # Description (English preferred)
    descriptions = cve.get("descriptions", [])
    desc = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "",
    )

    # CVSS — prefer v3.1, then v3.0, then v2.0
    cvss_score    = 0.0
    cvss_severity = "unknown"
    cvss_vector   = ""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        # Prefer "Primary" source
        primary = next((e for e in entries if e.get("type") == "Primary"), None)
        entry = primary or (entries[0] if entries else None)
        if entry:
            cd = entry.get("cvssData", {})
            cvss_score    = float(cd.get("baseScore", 0) or 0)
            cvss_severity = (cd.get("baseSeverity") or entry.get("baseSeverity", "unknown")).lower()
            cvss_vector   = cd.get("vectorString", "")
            break

    # CWE identifiers
    weaknesses = cve.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)
    cwe = ", ".join(dict.fromkeys(cwes)) or ""  # deduplicated, order-preserving

    # References — collect patch/advisory URLs (favour vendor advisories)
    references = cve.get("references", [])
    patch_url = ""
    advisory_url = ""
    all_urls: list[str] = []
    for ref in references:
        url = ref.get("url", "")
        tags = ref.get("tags", [])
        if not url:
            continue
        all_urls.append(url)
        if "Patch" in tags and not patch_url:
            patch_url = url
        if "Vendor Advisory" in tags and not advisory_url:
            advisory_url = url

    best_url = patch_url or advisory_url or (all_urls[0] if all_urls else "")

    return {
        "description":  desc,
        "cvss":         cvss_score,
        "severity":     cvss_severity,
        "cvss_vector":  cvss_vector,
        "cwe":          cwe,
        "patch_url":    best_url,
        "all_refs":     all_urls[:10],   # cap for storage
        "published":    cve.get("published", ""),
        "modified":     cve.get("lastModified", ""),
        "status":       cve.get("vulnStatus", ""),
    }


# ── Batch enrichment ──────────────────────────────────────────────────────────

def enrich_cves(
    cve_ids: list[str],
    api_key: str | None = None,
    progress_cb=None,
) -> dict[str, dict]:
    """
    Look up a list of CVE IDs in the NVD and return a mapping
    {cve_id: enrichment_dict}.

    Args:
        cve_ids:     List of CVE IDs to look up (duplicates deduplicated).
        api_key:     NVD API key. Falls back to NVD_API_KEY env var if omitted.
        progress_cb: Optional callable(current, total) called after each lookup.

    Returns:
        Dict mapping each CVE ID to its enrichment dict (empty dict on failure).
    """
    client = NVDClient(api_key=api_key)
    unique = list(dict.fromkeys(id.upper().strip() for id in cve_ids))
    results: dict[str, dict] = {}

    for i, cve_id in enumerate(unique, 1):
        results[cve_id] = client.lookup(cve_id)
        if progress_cb:
            progress_cb(i, len(unique))

    return results


def lookup_cached(cve_id: str, db) -> dict:
    """
    Return enrichment data for *cve_id*, using the local DB cache when possible.

    Logic:
      1. Check cve_cache for cve_id.
      2. If found and cached_at is within 30 days, return reconstructed dict.
      3. Otherwise call the live NVD API, store the result, and return it.

    The returned dict matches the _parse_nvd_cve format exactly.
    Returns {} on failure.
    """
    from models import CVECache  # local import to avoid circular at module load

    cve_id = cve_id.upper().strip()
    cutoff = datetime.now() - timedelta(days=30)  # naive UTC, matches MariaDB storage

    row = db.query(CVECache).filter(CVECache.cve_id == cve_id).first()
    # Make cached_at naive for comparison (MariaDB strips tzinfo)
    cached_at = row.cached_at.replace(tzinfo=None) if (row and row.cached_at) else None
    if row and cached_at and cached_at >= cutoff:
        # Reconstruct dict from cached row
        try:
            all_refs = json.loads(row.refs_json) if row.refs_json else []
        except (json.JSONDecodeError, TypeError):
            all_refs = []
        return {
            "description": row.description or "",
            "cvss":        row.cvss_score or 0.0,
            "severity":    row.cvss_severity or "unknown",
            "cvss_vector": row.cvss_vector or "",
            "cwe":         row.cwe or "",
            "patch_url":   row.patch_url or "",
            "all_refs":    all_refs,
            "published":   row.published or "",
            "modified":    row.modified or "",
            "status":      row.nvd_status or "",
        }

    # Cache miss or stale — call live API
    client = NVDClient()
    result = client.lookup(cve_id)
    if not result:
        return {}

    # Store/update in cache (store naive UTC — MariaDB DATETIME has no tz)
    now = datetime.utcnow()
    refs_json = json.dumps(result.get("all_refs", []))
    if row:
        row.description  = result.get("description", "")
        row.cvss_score   = result.get("cvss", None)
        row.cvss_severity = result.get("severity", None)
        row.cvss_vector  = result.get("cvss_vector", None)
        row.cwe          = result.get("cwe", None)
        row.patch_url    = result.get("patch_url", None)
        row.refs_json    = refs_json
        row.published    = result.get("published", None)
        row.modified     = result.get("modified", None)
        row.nvd_status   = result.get("status", None)
        row.cached_at    = now
    else:
        row = CVECache(
            cve_id      = cve_id,
            description  = result.get("description", ""),
            cvss_score   = result.get("cvss", None),
            cvss_severity = result.get("severity", None),
            cvss_vector  = result.get("cvss_vector", None),
            cwe          = result.get("cwe", None),
            patch_url    = result.get("patch_url", None),
            refs_json    = refs_json,
            published    = result.get("published", None),
            modified     = result.get("modified", None),
            nvd_status   = result.get("status", None),
            cached_at    = now,
        )
        db.add(row)
    try:
        db.commit()
    except Exception:
        db.rollback()

    return result


def apply_nvd_enrichment(
    patch_groups,   # list of PatchGroup objects
    api_key: str | None = None,
    db=None,
) -> None:
    """
    Mutate PatchGroup objects in-place, overwriting/enriching CVE fields
    with authoritative NVD data.

    Fields updated per CVE detail dict:
        description, cvssScore, severity, cwe, nvd_vector, nvd_status, nvd_modified

    The group's patch_url is set to the best NVD reference URL if it is
    currently empty.
    """
    # Collect all unique CVE IDs across all groups
    all_cves: list[str] = []
    for g in patch_groups:
        all_cves.extend(g.cve_ids)

    if not all_cves:
        return

    if db is not None:
        # Use cache-aware lookup for each CVE
        unique = list(dict.fromkeys(id.upper().strip() for id in all_cves))
        nvd_data = {cve_id: lookup_cached(cve_id, db) for cve_id in unique}
    else:
        nvd_data = enrich_cves(all_cves, api_key=api_key)

    for g in patch_groups:
        best_patch_url = g.patch_url  # keep existing if set

        for detail in g.cve_details:
            cve_id = detail.get("cveId", "").upper()
            nvd = nvd_data.get(cve_id, {})
            if not nvd:
                continue

            # Update description if NVD has a better one
            if nvd.get("description"):
                detail["description"] = nvd["description"]

            # Update CVSS from NVD (authoritative)
            if nvd.get("cvss", 0) > 0:
                detail["cvssScore"] = nvd["cvss"]

            # Update severity from NVD
            if nvd.get("severity") and nvd["severity"] != "unknown":
                detail["severity"] = nvd["severity"]

            # Add CWE
            if nvd.get("cwe"):
                detail["cwe"] = nvd["cwe"]

            # Add extra NVD metadata
            detail["nvd_vector"]   = nvd.get("cvss_vector", "")
            detail["nvd_status"]   = nvd.get("status", "")
            detail["nvd_modified"] = nvd.get("modified", "")
            detail["nvd_refs"]     = nvd.get("all_refs", [])

            # Best patch URL from NVD references
            if nvd.get("patch_url") and not best_patch_url:
                best_patch_url = nvd["patch_url"]

        if best_patch_url and not g.patch_url:
            g.patch_url = best_patch_url

        # Re-sort CVEs within group by updated severity
        from collectors.patch_remediation import SEVERITY_ORDER
        g.cve_details.sort(
            key=lambda v: SEVERITY_ORDER.get(v.get("severity", "unknown").lower(), 99)
        )
        g.cve_ids = [v["cveId"] for v in g.cve_details]
