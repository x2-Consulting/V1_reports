"""
Collect vulnerability data from Trend Vision One and group by the patch
that fixes them.

A single patch (KB article, vendor update, or advisory) can remediate
multiple CVEs across multiple assets.  This module returns a list of
PatchGroup objects — one entry per distinct patch — so a report can say
"Install KB5034441 to fix 7 CVEs on 3 endpoints" rather than listing
each CVE individually.

Grouping priority (first match wins):
  1. kbArticleId   — Microsoft KB articles
  2. patchId       — vendor-supplied patch identifier
  3. vendorAdvisoryId / advisoryId — security advisory
  4. vendorName + productName + productVersion — logical patch group
  5. "no_patch"    — no patch information available yet

API endpoints tried (in order):
  • /v3.0/vulnerabilityManagement/vulnerabilities  (preferred, richer data)
  • /v3.0/asrm/vulnerabilities                     (fallback)
"""

from __future__ import annotations

from typing import Any

from client import TrendVisionOneClient

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 99}


# ── Data structure ─────────────────────────────────────────────────────────────

class PatchGroup:
    """All CVEs remediable by a single patch action."""

    def __init__(self, patch_key: str, patch_type: str):
        self.patch_key: str = patch_key          # KB5034441, APSB24-12, etc.
        self.patch_type: str = patch_type        # microsoft_kb | vendor_patch | advisory | logical | no_patch
        self.vendor: str = ""
        self.product: str = ""
        self.product_version: str = ""
        self.patch_url: str = ""
        self.cve_ids: list[str] = []             # deduplicated
        self.cve_details: list[dict] = []        # full records
        self.affected_assets: list[str] = []     # deduplicated hostnames/IPs
        self.affected_asset_details: list[dict] = []

    # ── Derived properties ─────────────────────────────────────────────────────

    @property
    def worst_severity(self) -> str:
        if not self.cve_details:
            return "unknown"
        return min(
            self.cve_details,
            key=lambda v: SEVERITY_ORDER.get(v.get("severity", "unknown").lower(), 99),
        ).get("severity", "unknown")

    @property
    def worst_cvss(self) -> float:
        scores = [
            float(v.get("cvssScore", v.get("riskScore", 0)) or 0)
            for v in self.cve_details
        ]
        return max(scores, default=0.0)

    @property
    def install_priority(self) -> str:
        score = self.worst_cvss
        sev = self.worst_severity.lower()
        if sev == "critical" or score >= 9.0:
            return "Immediate"
        if sev == "high" or score >= 7.0:
            return "High"
        if sev == "medium" or score >= 4.0:
            return "Medium"
        return "Low"

    @property
    def cve_count(self) -> int:
        return len(self.cve_ids)

    @property
    def asset_count(self) -> int:
        return len(self.affected_assets)

    def to_dict(self) -> dict:
        return {
            "patch_key": self.patch_key,
            "patch_type": self.patch_type,
            "vendor": self.vendor,
            "product": self.product,
            "product_version": self.product_version,
            "patch_url": self.patch_url,
            "cve_ids": self.cve_ids,
            "cve_details": self.cve_details,
            "affected_assets": self.affected_assets,
            "affected_asset_details": self.affected_asset_details,
            "worst_severity": self.worst_severity,
            "worst_cvss": self.worst_cvss,
            "install_priority": self.install_priority,
            "cve_count": self.cve_count,
            "asset_count": self.asset_count,
        }


# ── Raw data collection ────────────────────────────────────────────────────────

def _fetch_raw(client: TrendVisionOneClient, severity_filter: list[str] | None) -> list[dict]:
    """Fetch raw vulnerability records, trying the richer endpoint first."""
    raw: list[dict] = []

    # Try the vulnerability management endpoint first (has richer patch data)
    for endpoint in (
        "/v3.0/vulnerabilityManagement/vulnerabilities",
        "/v3.0/asrm/vulnerabilities",
    ):
        try:
            raw = list(client.paginate(endpoint, items_key="items"))
            if raw:
                break
        except Exception:
            continue

    if severity_filter:
        allowed = {s.lower() for s in severity_filter}
        raw = [v for v in raw if v.get("severity", "").lower() in allowed]

    return raw


# ── Patch key extraction ───────────────────────────────────────────────────────

def _extract_patch_key(vuln: dict) -> tuple[str, str]:
    """
    Return (patch_key, patch_type) for a vulnerability record.
    patch_key is what we group by; patch_type describes the source.
    """
    # 1. Microsoft KB articles (may be a list)
    kb_ids = vuln.get("kbArticleIds") or vuln.get("kbArticleId")
    if kb_ids:
        if isinstance(kb_ids, list):
            kb_ids = kb_ids[0]  # primary KB article
        return str(kb_ids).strip(), "microsoft_kb"

    # 2. Vendor-supplied patch ID
    patch_id = vuln.get("patchId") or vuln.get("patch_id")
    if patch_id:
        return str(patch_id).strip(), "vendor_patch"

    # 3. Security advisory ID
    advisory = (
        vuln.get("vendorAdvisoryId")
        or vuln.get("advisoryId")
        or vuln.get("securityAdvisoryId")
    )
    if advisory:
        return str(advisory).strip(), "advisory"

    # 4. Logical grouping: vendor + product + version
    vendor = vuln.get("vendorName", vuln.get("vendor", "Unknown"))
    product = vuln.get("productName", vuln.get("product", "Unknown"))
    version = vuln.get("productVersion", vuln.get("version", ""))
    if vendor != "Unknown" or product != "Unknown":
        key = f"{vendor}::{product}::{version}".rstrip(":").lower()
        return key, "logical"

    return "no_patch", "no_patch"


def _extract_asset(vuln: dict) -> tuple[str, dict]:
    """Return (display_name, detail_dict) for the affected asset."""
    asset = vuln.get("affectedAsset") or {}
    if isinstance(asset, dict):
        hostname = (
            asset.get("hostName")
            or asset.get("hostname")
            or asset.get("displayName")
            or asset.get("agentGuid", "")
        )
        ip = asset.get("ip", asset.get("ipAddress", ""))
        name = hostname or ip or "Unknown Asset"
        return name, {"hostname": hostname, "ip": ip, "agentGuid": asset.get("agentGuid", "")}

    # Flat string fields
    name = (
        vuln.get("assetName")
        or vuln.get("hostName")
        or vuln.get("hostname")
        or vuln.get("displayName")
        or "Unknown Asset"
    )
    ip = vuln.get("ipAddress", vuln.get("ip", ""))
    return name, {"hostname": name, "ip": ip, "agentGuid": ""}


# ── Main grouping function ─────────────────────────────────────────────────────

def collect_patch_groups(
    client: TrendVisionOneClient,
    severity_filter: list[str] | None = None,
) -> list[PatchGroup]:
    """
    Fetch all vulnerability data and return a list of PatchGroup objects,
    each representing a single patch action that fixes one or more CVEs.

    Sorted by install priority (Immediate → High → Medium → Low).
    """
    raw = _fetch_raw(client, severity_filter)

    groups: dict[str, PatchGroup] = {}
    seen_cves: dict[str, set[str]] = {}       # patch_key → set of CVE IDs already added
    seen_assets: dict[str, set[str]] = {}     # patch_key → set of asset names already added

    for vuln in raw:
        patch_key, patch_type = _extract_patch_key(vuln)
        cve_id = vuln.get("cveId", vuln.get("id", "UNKNOWN"))
        asset_name, asset_detail = _extract_asset(vuln)

        if patch_key not in groups:
            g = PatchGroup(patch_key, patch_type)
            # Populate metadata from first record in this group
            g.vendor = vuln.get("vendorName", vuln.get("vendor", ""))
            g.product = vuln.get("productName", vuln.get("product", ""))
            g.product_version = vuln.get("productVersion", vuln.get("version", ""))
            g.patch_url = (
                vuln.get("patchUrl")
                or vuln.get("vendorAdvisoryUrl")
                or vuln.get("referenceUrl")
                or ""
            )
            groups[patch_key] = g
            seen_cves[patch_key] = set()
            seen_assets[patch_key] = set()

        g = groups[patch_key]

        # Add CVE (deduplicated)
        if cve_id not in seen_cves[patch_key]:
            g.cve_ids.append(cve_id)
            g.cve_details.append(vuln)
            seen_cves[patch_key].add(cve_id)

        # Add asset (deduplicated)
        if asset_name not in seen_assets[patch_key]:
            g.affected_assets.append(asset_name)
            g.affected_asset_details.append(asset_detail)
            seen_assets[patch_key].add(asset_name)

    # Sort CVEs within each group by severity
    for g in groups.values():
        g.cve_details.sort(
            key=lambda v: SEVERITY_ORDER.get(v.get("severity", "unknown").lower(), 99)
        )
        g.cve_ids = [v.get("cveId", v.get("id", "UNKNOWN")) for v in g.cve_details]

    # Sort groups: priority tier first, then by impact score (CVEs × assets),
    # then worst CVSS as tiebreaker.  This puts the single patch action that
    # fixes the most vulnerabilities across the most machines at the top.
    priority_order = {"Immediate": 0, "High": 1, "Medium": 2, "Low": 3}
    result = sorted(
        groups.values(),
        key=lambda g: (
            priority_order.get(g.install_priority, 9),
            -(g.cve_count * g.asset_count),
            -g.worst_cvss,
        ),
    )

    return result
