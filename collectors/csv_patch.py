"""
Parse a Trend Vision One vulnerability CSV export and group vulnerabilities
by the patch that fixes them.

Confirmed TV1 export columns (as of 2026):
    Device name, Operating system, IP address, Last User, Last detected,
    Data source, Vulnerability ID, Status, OS/Application,
    Global exploit potential, Prevention rule, Published,
    CVSS score, Device ID, Mitigation options

Patch grouping strategy
-----------------------
When a database session (db=) is supplied the NVD cache is used to resolve
a proper patch identifier for each CVE.  NVD reference URLs are scanned for
known patch / advisory patterns (KB articles, GHSA, RHSA, APSB, etc.).
This is far more reliable than parsing the free-text "Mitigation options"
field, which typically contains vague strings like "Apply vendor patch" or
just the product name.

When db= is None the legacy mitigation-text path is used as a fallback.

Priority order when resolving a patch key:
  1. Microsoft KB extracted from NVD reference URLs
  2. Known advisory ID from NVD reference URLs (GHSA, RHSA, APSB, …)
  3. KB extracted from CSV "Mitigation options" text  (legacy fallback)
  4. OS/Application product name  (logical grouping)
  5. "no_patch"

Column mapping is case/whitespace-insensitive so minor header variations
from future TV1 releases are handled gracefully.
"""

from __future__ import annotations

import csv
import re
from typing import IO, Iterator

from collectors.patch_remediation import PatchGroup, SEVERITY_ORDER

# ── Column aliases ─────────────────────────────────────────────────────────────

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

# ── Regex patterns ─────────────────────────────────────────────────────────────

# KB number in free-text (legacy CSV fallback)
_KB_TEXT_RE = re.compile(r'\b(KB\d{4,8})\b', re.IGNORECASE)

# Patterns to extract patch/advisory IDs from NVD reference URLs.
# Each entry: (compiled_regex, group_index, patch_type, prefix)
#   prefix  — string prepended to the captured group (e.g. "KB")
#   group   — regex group that holds the identifier
_URL_PATTERNS: list[tuple[re.Pattern, int, str, str]] = [
    # Microsoft KB — support.microsoft.com/help/5034441
    (re.compile(r'support\.microsoft\.com/(?:[a-z-]+/)?(?:help|kb)/(?:KB)?(\d{5,8})', re.I), 1, "microsoft_kb", "KB"),
    # Microsoft KB — catalog.update.microsoft.com?q=KB5040434
    (re.compile(r'catalog\.update\.microsoft\.com[^?]*\?q=KB(\d{5,8})', re.I), 1, "microsoft_kb", "KB"),
    # KB number anywhere in a microsoft.com URL
    (re.compile(r'microsoft\.com.*?\bKB(\d{5,8})\b', re.I), 1, "microsoft_kb", "KB"),
    # MSRC security update guide
    (re.compile(r'msrc\.microsoft\.com.*?/(CVE-\d{4}-\d+)', re.I), 1, "advisory", ""),
    # GitHub Security Advisory
    (re.compile(r'github\.com/advisories/(GHSA-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+)', re.I), 1, "advisory", ""),
    # Red Hat / CentOS / Fedora errata
    (re.compile(r'(RHSA-\d{4}:\d+)', re.I), 1, "advisory", ""),
    (re.compile(r'(FEDORA-\d{4}-[a-f0-9]+)', re.I), 1, "advisory", ""),
    # Adobe security bulletin
    (re.compile(r'(APSB\d{2}-\d+)', re.I), 1, "advisory", ""),
    # Mozilla Foundation Security Advisory
    (re.compile(r'(mfsa\d{4}-\d+)', re.I), 1, "advisory", ""),
    # Debian Security Advisory
    (re.compile(r'(DSA-\d{4}-\d+)', re.I), 1, "advisory", ""),
    # Ubuntu Security Notice
    (re.compile(r'(USN-\d{4}-\d+)', re.I), 1, "advisory", ""),
    # VMware Security Advisory
    (re.compile(r'(VMSA-\d{4}-\d{4})', re.I), 1, "advisory", ""),
    # Oracle Critical Patch Update
    (re.compile(r'oracle\.com/security-alerts/(cpu[a-z]+\d{4})', re.I), 1, "advisory", ""),
    # Apple security HT articles
    (re.compile(r'support\.apple\.com[^?]*(HT\d{6,9})', re.I), 1, "advisory", ""),
    # Cisco Security Advisory
    (re.compile(r'cisco\.com.*?(cisco-sa-[a-z0-9-]+)', re.I), 1, "advisory", ""),
    # Google Chrome / Android release notes
    (re.compile(r'chromereleases\.googleblog\.com.*?/(\d{4}/\d{2}/[a-z0-9-]+)', re.I), 1, "advisory", "chrome-"),
]


def _extract_patch_key_from_urls(urls: list[str]) -> tuple[str, str] | None:
    """
    Scan a list of URLs for a recognizable patch / advisory identifier.
    Returns (patch_key, patch_type) or None if nothing matched.
    """
    for url in urls:
        for pattern, grp, ptype, prefix in _URL_PATTERNS:
            m = pattern.search(url)
            if m:
                identifier = prefix + m.group(grp).upper()
                return identifier, ptype
    return None


def _build_col_map(headers: list[str]) -> dict[str, int]:
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
    e = exploit.lower()
    for word in ("critical", "high", "medium", "moderate", "low", "info"):
        if word in e:
            return "medium" if word == "moderate" else word
    if any(p in e for p in ("actively exploit", "in the wild", "weaponized")):
        return "critical"
    if any(p in e for p in ("proof of concept", "poc", "exploit available")):
        return "high"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "unknown"


# ── Main parser ────────────────────────────────────────────────────────────────

def parse_csv_to_patch_groups(
    file_data: bytes | str | IO,
    severity_filter: list[str] | None = None,
    skip_fixed: bool = True,
    db=None,
) -> list[PatchGroup]:
    """
    Parse a TV1 vulnerability CSV export and return PatchGroup objects.

    Args:
        file_data:       Raw bytes, string, or file-like object of the CSV.
        severity_filter: Optional list of severities to keep (e.g. ['critical','high']).
                         None = all severities included.
        skip_fixed:      If True (default), skip rows where Status is Fixed/Resolved.
        db:              SQLAlchemy Session.  When provided, NVD cache is used to
                         resolve authoritative patch identifiers and enrich CVE
                         details (description, CVSS, severity, CWE, refs).
                         When None, falls back to parsing the CSV "Mitigation
                         options" field for patch key extraction.

    Returns:
        List of PatchGroup objects sorted by install priority then worst CVSS.
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
    if "cve_id" not in col_map and "hostname" not in col_map:
        raise ValueError(
            "Could not identify required columns in the CSV.\n"
            f"Headers detected: {headers}\n"
            "Expected at minimum: 'Vulnerability ID' and 'Device name'."
        )

    allowed_severities = {s.lower() for s in severity_filter} if severity_filter else None
    fixed_statuses = {"fixed", "resolved", "remediated", "patched"}

    # ── First pass: collect every row into a flat record list ─────────────────
    # We defer patch-key assignment until after NVD lookup so all CVEs are
    # available for bulk cache query.

    records: list[dict] = []
    unique_cves: list[str] = []
    seen_cve_set: set[str] = set()

    for row in reader:
        if not any(cell.strip() for cell in row):
            continue

        status = _get(row, col_map, "status").lower()
        if skip_fixed and status in fixed_statuses:
            continue

        cve_id   = _get(row, col_map, "cve_id") or "UNKNOWN"
        cvss_raw = _get(row, col_map, "cvss", "0")
        exploit  = _get(row, col_map, "exploit")

        try:
            cvss = float(cvss_raw)
        except (ValueError, TypeError):
            cvss = 0.0

        severity = _map_exploit_to_severity(exploit, cvss)
        if allowed_severities and severity not in allowed_severities:
            continue

        rec = {
            "cve_id":     cve_id,
            "cvss":       cvss,
            "exploit":    exploit,
            "severity":   severity,
            "desc":       _get(row, col_map, "desc"),
            "hostname":   _get(row, col_map, "hostname"),
            "os_name":    _get(row, col_map, "os"),
            "ip":         _get(row, col_map, "ip"),
            "last_user":  _get(row, col_map, "last_user"),
            "last_seen":  _get(row, col_map, "last_seen"),
            "product":    _get(row, col_map, "product"),
            "mitigation": _get(row, col_map, "mitigation"),
            "device_id":  _get(row, col_map, "device_id"),
            "url":        _get(row, col_map, "url"),
            "published":  _get(row, col_map, "published"),
        }
        records.append(rec)

        norm = cve_id.upper().strip()
        if norm not in seen_cve_set and norm != "UNKNOWN":
            unique_cves.append(norm)
            seen_cve_set.add(norm)

    if not records:
        return []

    # ── NVD bulk lookup ────────────────────────────────────────────────────────
    nvd_cache: dict[str, dict] = {}
    if db is not None and unique_cves:
        from collectors.nvd import lookup_cached
        for cve_id in unique_cves:
            try:
                nvd_cache[cve_id] = lookup_cached(cve_id, db)
            except Exception:
                nvd_cache[cve_id] = {}

    # ── Determine patch key for each CVE (once, not per-row) ──────────────────
    cve_to_patch: dict[str, tuple[str, str]] = {}   # cve_id → (patch_key, patch_type)
    for cve_id in unique_cves:
        nvd = nvd_cache.get(cve_id, {})

        # 1. Mine NVD reference URLs for a known patch identifier
        if nvd:
            urls = nvd.get("all_refs") or ([nvd["patch_url"]] if nvd.get("patch_url") else [])
            result = _extract_patch_key_from_urls(urls)
            if result:
                cve_to_patch[cve_id] = result
                continue

        # 2. No NVD hit — fall back to whatever product info NVD description has
        #    (we'll use the CSV product column as the patch group key)
        cve_to_patch[cve_id] = ("__pending__", "__pending__")

    # ── Second pass: build PatchGroups ────────────────────────────────────────
    groups: dict[str, PatchGroup] = {}
    seen_cves_in_group: dict[str, set[str]] = {}
    seen_assets_in_group: dict[str, set[str]] = {}

    for rec in records:
        cve_id = rec["cve_id"]
        norm   = cve_id.upper().strip()

        patch_key, patch_type = cve_to_patch.get(norm, ("__pending__", "__pending__"))

        if patch_key == "__pending__":
            # 3. KB from CSV mitigation text
            m = _KB_TEXT_RE.search(rec["mitigation"])
            if m:
                patch_key = m.group(1).upper()
                patch_type = "microsoft_kb"
            # 4. Product name grouping
            elif rec["product"]:
                patch_key = rec["product"].lower().strip()
                patch_type = "logical"
            else:
                patch_key = "no_patch"
                patch_type = "no_patch"

        asset_name = rec["hostname"] or rec["ip"] or "Unknown Asset"

        if patch_key not in groups:
            g = PatchGroup(patch_key, patch_type)
            g.vendor          = ""
            g.product         = rec["product"]
            g.product_version = ""
            g.patch_url       = rec["url"]
            groups[patch_key]           = g
            seen_cves_in_group[patch_key]   = set()
            seen_assets_in_group[patch_key] = set()

        g = groups[patch_key]

        # Add CVE (deduplicated per group)
        if norm not in seen_cves_in_group[patch_key]:
            nvd = nvd_cache.get(norm, {})
            detail: dict = {
                "cveId":       cve_id,
                "exploit":     rec["exploit"],
                "published":   rec["published"],
            }

            if nvd:
                # NVD authoritative data takes precedence
                detail["severity"]    = nvd.get("severity") or rec["severity"]
                detail["cvssScore"]   = nvd.get("cvss") or rec["cvss"]
                detail["description"] = nvd.get("description") or rec["desc"]
                detail["cwe"]         = nvd.get("cwe", "")
                detail["nvd_vector"]  = nvd.get("cvss_vector", "")
                detail["nvd_status"]  = nvd.get("status", "")
                detail["nvd_refs"]    = nvd.get("all_refs", [])
                # Use best NVD patch URL if the group has none yet
                if nvd.get("patch_url") and not g.patch_url:
                    g.patch_url = nvd["patch_url"]
            else:
                detail["severity"]    = rec["severity"]
                detail["cvssScore"]   = rec["cvss"]
                detail["description"] = rec["desc"]

            g.cve_ids.append(cve_id)
            g.cve_details.append(detail)
            seen_cves_in_group[patch_key].add(norm)

        # Add asset (deduplicated per group)
        if asset_name not in seen_assets_in_group[patch_key]:
            g.affected_assets.append(asset_name)
            g.affected_asset_details.append({
                "hostname":  rec["hostname"],
                "ip":        rec["ip"],
                "agentGuid": rec["device_id"],
                "os":        rec["os_name"],
                "last_user": rec["last_user"],
                "last_seen": rec["last_seen"],
            })
            seen_assets_in_group[patch_key].add(asset_name)

    # ── Sort CVEs within each group by severity ────────────────────────────────
    for g in groups.values():
        g.cve_details.sort(
            key=lambda v: SEVERITY_ORDER.get(v.get("severity", "unknown").lower(), 99)
        )
        g.cve_ids = [v["cveId"] for v in g.cve_details]

    # ── Sort groups: priority tier → impact score (CVEs × assets) → CVSS ─────
    priority_order = {"Immediate": 0, "High": 1, "Medium": 2, "Low": 3}
    return sorted(
        groups.values(),
        key=lambda g: (
            priority_order.get(g.install_priority, 9),
            -(g.cve_count * g.asset_count),
            -g.worst_cvss,
        ),
    )
