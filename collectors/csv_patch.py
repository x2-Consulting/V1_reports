"""
Parse a Trend Vision One vulnerability CSV export and group vulnerabilities
by the patch that fixes them.

Confirmed TV1 export columns (as of 2026):
    Device name, Operating system, IP address, Last User, Last detected,
    Data source, Vulnerability ID, Status, OS/Application,
    Global exploit potential, Prevention rule, Published,
    CVSS score, Device ID, Mitigation options

Column mapping is case/whitespace-insensitive so minor header variations
from future TV1 releases are handled gracefully.

Patch grouping logic:
  1. KB article number extracted from "Mitigation options" (regex KB\\d+)
  2. Remaining "Mitigation options" text used as patch_id if no KB found
  3. "OS/Application" used as logical product group if no explicit patch key
  4. "no_patch" fallback

Sorting: CVE count descending → worst CVSS descending
(patch fixing most vulnerabilities appears first)

Global exploit potential → severity mapping:
  "actively exploited / high"  → critical
  "proof of concept / medium"  → high
  "no known exploit / low"     → medium/low  (by CVSS)
  Standard words (critical/high/medium/low) passed through directly.

Rows where Status == "Fixed" (or "Resolved") are skipped by default.
"""

from __future__ import annotations

import csv
import re
from typing import IO, Iterator

from collectors.patch_remediation import PatchGroup, SEVERITY_ORDER

# ── Column aliases (all lowercase, spaces normalised) ─────────────────────────

_ALIASES: dict[str, list[str]] = {
    "cve_id":      ["vulnerability id", "cve id", "cve", "cve_id", "vuln id",
                    "cve number", "vulnerability"],
    "exploit":     ["global exploit potential", "exploit potential", "exploitability",
                    "exploit"],
    "cvss":        ["cvss score", "cvss", "risk score", "cvss_score",
                    "cvss v3 score", "cvss v2 score", "cvss v3", "cvss v2"],
    "desc":        ["description", "summary", "vulnerability name", "title",
                    "vulnerability description", "name"],
    "hostname":    ["device name", "hostname", "host", "endpoint", "asset",
                    "affected endpoint", "affected asset", "computer name",
                    "machine name", "asset name", "host name"],
    "os":          ["operating system", "os", "platform"],
    "ip":          ["ip address", "ip", "ip_address", "ipaddress"],
    "last_user":   ["last user", "last logged on user", "last logged in user"],
    "last_seen":   ["last detected", "last seen", "last found", "detected"],
    "data_source": ["data source", "source", "datasource"],
    "status":      ["status", "vuln status", "vulnerability status"],
    "product":     ["os/application", "os application", "product name", "product",
                    "software", "application", "affected product"],
    "mitigation":  ["mitigation options", "mitigation", "remediation",
                    "fix", "patch notes", "solution"],
    "prevention":  ["prevention rule", "prevention", "rule"],
    "published":   ["published", "published date", "cve published", "release date"],
    "device_id":   ["device id", "device_id", "agent guid", "agentguid",
                    "asset id", "machine id"],
    "url":         ["reference url", "patch url", "url", "advisory url",
                    "reference", "more information"],
}

# ── Regex to extract KB article numbers from free-text fields ─────────────────
_KB_RE = re.compile(r'\b(KB\d{4,8})\b', re.IGNORECASE)


def _build_col_map(headers: list[str]) -> dict[str, int]:
    """Return {field_name: column_index} for recognised headers."""
    normalised = [h.strip().lower().replace("_", " ") for h in headers]
    col_map: dict[str, int] = {}
    for field, aliases in _ALIASES.items():
        for alias in aliases:
            if alias in normalised:
                col_map[field] = normalised.index(alias)
                break
    return col_map


def _get(row: list[str], col_map: dict[str, int], field: str, default: str = "") -> str:
    idx = col_map.get(field)
    if idx is None or idx >= len(row):
        return default
    return row[idx].strip()


def _map_exploit_to_severity(exploit: str, cvss: float) -> str:
    """
    Map TV1 'Global exploit potential' text to a standard severity label.
    Falls back to CVSS-based severity when the text is ambiguous.
    """
    e = exploit.lower()

    # Direct severity words
    for word in ("critical", "high", "medium", "moderate", "low", "info"):
        if word in e:
            return "medium" if word == "moderate" else word

    # TV1-specific phrases
    if any(p in e for p in ("actively exploit", "in the wild", "weaponized")):
        return "critical"
    if any(p in e for p in ("proof of concept", "poc", "exploit available")):
        return "high"
    if any(p in e for p in ("no known exploit", "theoretical", "unlikely")):
        # Fall through to CVSS
        pass

    # CVSS fallback
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "unknown"


def _extract_kb_from_mitigation(mitigation_text: str) -> str:
    """Return the first KB article number found in free-text, or empty string."""
    m = _KB_RE.search(mitigation_text)
    return m.group(1).upper() if m else ""


# ── Main parser ────────────────────────────────────────────────────────────────

def parse_csv_to_patch_groups(
    file_data: bytes | str | IO,
    severity_filter: list[str] | None = None,
    skip_fixed: bool = True,
) -> list[PatchGroup]:
    """
    Parse a TV1 vulnerability CSV export and return PatchGroup objects.

    Args:
        file_data:       Raw bytes, string, or file-like object of the CSV.
        severity_filter: Optional list of severities to keep (e.g. ['critical','high']).
                         None = all severities included.
        skip_fixed:      If True (default), skip rows where Status is Fixed/Resolved.

    Returns:
        List of PatchGroup objects sorted by CVE count desc, then worst CVSS desc.
    """
    # Normalise input to text lines
    if isinstance(file_data, bytes):
        for enc in ("utf-8-sig", "utf-8", "latin-1"):
            try:
                text = file_data.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        else:
            text = file_data.decode("latin-1", errors="replace")
        stream: Iterator[str] = iter(text.splitlines())
    elif isinstance(file_data, str):
        stream = iter(file_data.splitlines())
    else:
        stream = file_data

    reader = csv.reader(stream)

    try:
        headers = next(reader)
    except StopIteration:
        return []

    col_map = _build_col_map(headers)

    # Require at least one identifying column
    if "cve_id" not in col_map and "hostname" not in col_map:
        raise ValueError(
            "Could not identify required columns in the CSV.\n"
            f"Headers detected: {headers}\n"
            "Expected at minimum: 'Vulnerability ID' and 'Device name'."
        )

    allowed_severities = {s.lower() for s in severity_filter} if severity_filter else None
    fixed_statuses = {"fixed", "resolved", "remediated", "patched"}

    groups: dict[str, PatchGroup] = {}
    seen_cves: dict[str, set[str]] = {}
    seen_assets: dict[str, set[str]] = {}

    for row in reader:
        if not any(cell.strip() for cell in row):
            continue

        # ── Extract fields ──
        cve_id     = _get(row, col_map, "cve_id") or "UNKNOWN"
        cvss_raw   = _get(row, col_map, "cvss", "0")
        exploit    = _get(row, col_map, "exploit")
        desc       = _get(row, col_map, "desc")
        hostname   = _get(row, col_map, "hostname")
        os_name    = _get(row, col_map, "os")
        ip         = _get(row, col_map, "ip")
        last_user  = _get(row, col_map, "last_user")
        last_seen  = _get(row, col_map, "last_seen")
        status     = _get(row, col_map, "status").lower()
        product    = _get(row, col_map, "product")   # OS/Application
        mitigation = _get(row, col_map, "mitigation")
        device_id  = _get(row, col_map, "device_id")
        url        = _get(row, col_map, "url")
        published  = _get(row, col_map, "published")

        # Skip already-fixed items
        if skip_fixed and status in fixed_statuses:
            continue

        # Parse CVSS
        try:
            cvss = float(cvss_raw)
        except (ValueError, TypeError):
            cvss = 0.0

        # Derive severity from exploit potential (or CVSS fallback)
        if exploit:
            severity = _map_exploit_to_severity(exploit, cvss)
        else:
            severity = _map_exploit_to_severity("", cvss)

        # Severity filter
        if allowed_severities and severity not in allowed_severities:
            continue

        # ── Determine patch key ──
        kb = _extract_kb_from_mitigation(mitigation)
        if kb:
            patch_key, patch_type = kb, "microsoft_kb"
        elif mitigation and mitigation.lower() not in ("n/a", "none", "-", ""):
            # Use full mitigation text as patch identifier (deduplicated by exact text)
            patch_key = mitigation[:120]   # cap length for readability
            patch_type = "vendor_patch"
        elif product:
            patch_key = product.lower().strip()
            patch_type = "logical"
        else:
            patch_key, patch_type = "no_patch", "no_patch"

        # Asset name
        asset_name = hostname or ip or "Unknown Asset"

        # ── Build / update PatchGroup ──
        if patch_key not in groups:
            g = PatchGroup(patch_key, patch_type)
            g.vendor          = ""
            g.product         = product
            g.product_version = ""
            g.patch_url       = url
            groups[patch_key]      = g
            seen_cves[patch_key]   = set()
            seen_assets[patch_key] = set()

        g = groups[patch_key]

        # Add CVE (deduplicated per group)
        if cve_id not in seen_cves[patch_key]:
            g.cve_ids.append(cve_id)
            g.cve_details.append({
                "cveId":       cve_id,
                "severity":    severity,
                "cvssScore":   cvss,
                "description": desc,
                "published":   published,
                "exploit":     exploit,
            })
            seen_cves[patch_key].add(cve_id)

        # Add asset (deduplicated per group)
        if asset_name not in seen_assets[patch_key]:
            g.affected_assets.append(asset_name)
            g.affected_asset_details.append({
                "hostname":  hostname,
                "ip":        ip,
                "agentGuid": device_id,
                "os":        os_name,
                "last_user": last_user,
                "last_seen": last_seen,
            })
            seen_assets[patch_key].add(asset_name)

    # Sort CVEs within each group by severity
    for g in groups.values():
        g.cve_details.sort(
            key=lambda v: SEVERITY_ORDER.get(v.get("severity", "unknown").lower(), 99)
        )
        g.cve_ids = [v["cveId"] for v in g.cve_details]

    # Sort groups: most CVEs fixed first, then highest CVSS as tiebreaker
    return sorted(
        groups.values(),
        key=lambda g: (-g.cve_count, -g.worst_cvss),
    )
