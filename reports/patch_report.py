"""
Patch Remediation PDF Report Generator.

Organises vulnerabilities by the patch that fixes them, not by individual CVE.
One row / section per distinct patch — showing all CVEs it resolves and all
assets it must be applied to.

Priority tiers: Immediate (CVSS ≥ 9 / Critical) → High → Medium → Low
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _age_label(published: str) -> str:
    """Return a human-readable age string from an ISO date, e.g. '2yr 3mo ago'."""
    if not published:
        return "—"
    try:
        dt = datetime.fromisoformat(str(published)[:10])
        days = (datetime.utcnow().date() - dt.date()).days
        if days < 0:
            return "—"
        if days == 0:
            return "Today"
        if days < 30:
            return f"{days}d ago"
        if days < 365:
            return f"{days // 30}mo ago"
        yrs = days // 365
        mos = (days % 365) // 30
        return f"{yrs}yr {mos}mo ago" if mos else f"{yrs}yr ago"
    except (ValueError, AttributeError, TypeError):
        return "—"

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

# ── Palette (matched to Trend Vision One portal) ───────────────────────────────
TV1_RED    = colors.HexColor("#D71920")
TV1_NAVY   = colors.HexColor("#172239")
TV1_NAVY2  = colors.HexColor("#1e2d4a")
MID_GREY   = colors.HexColor("#6B6B6B")
LIGHT_GREY = colors.HexColor("#F4F6FA")
WHITE      = colors.white

PRIORITY_COLORS = {
    "Immediate": colors.HexColor("#D71920"),
    "High":      colors.HexColor("#E8610A"),
    "Medium":    colors.HexColor("#D4A017"),
    "Low":       colors.HexColor("#2E7D32"),
}

SEVERITY_COLORS = {
    "critical": colors.HexColor("#D71920"),
    "high":     colors.HexColor("#E8610A"),
    "medium":   colors.HexColor("#D4A017"),
    "low":      colors.HexColor("#2E7D32"),
    "info":     colors.HexColor("#1565C0"),
}

PATCH_TYPE_LABELS = {
    "microsoft_kb": "Microsoft KB",
    "vendor_patch":  "Vendor Patch",
    "advisory":      "Security Advisory",
    "logical":       "Product Update",
    "no_patch":      "No Patch Available",
}

MARGIN        = 2 * cm
BOTTOM_MARGIN = 2.5 * cm

# Portrait (A4)
PAGE_W, PAGE_H  = A4
CONTENT_W       = PAGE_W - 2 * MARGIN          # ~17.0 cm

# Landscape (A4 rotated)
PAGE_LAND_W, PAGE_LAND_H = landscape(A4)
CONTENT_LAND_W  = PAGE_LAND_W - 2 * MARGIN     # ~25.7 cm


# ── Styles ─────────────────────────────────────────────────────────────────────

def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    BODY_COLOR = colors.HexColor("#1A1A2E")
    return {
        "cover_title": ParagraphStyle(
            "CoverTitle", parent=base["Title"],
            fontSize=26, textColor=WHITE, alignment=TA_CENTER, spaceAfter=4,
            leading=32,
        ),
        "cover_sub": ParagraphStyle(
            "CoverSub", parent=base["Normal"],
            fontSize=12, textColor=colors.HexColor("#BBCCDD"),
            alignment=TA_CENTER, spaceAfter=2,
        ),
        "cover_meta": ParagraphStyle(
            "CoverMeta", parent=base["Normal"],
            fontSize=10, textColor=colors.HexColor("#BBCCDD"),
            alignment=TA_CENTER, spaceAfter=4,
        ),
        "section": ParagraphStyle(
            "Section", parent=base["Heading1"],
            fontSize=13, textColor=TV1_RED,
            spaceBefore=16, spaceAfter=6, leading=18,
        ),
        "patch_title": ParagraphStyle(
            "PatchTitle", parent=base["Normal"],
            fontSize=9.5, textColor=TV1_NAVY,
            fontName="Helvetica-Bold", spaceAfter=3, spaceBefore=4,
        ),
        "body": ParagraphStyle(
            "Body", parent=base["Normal"],
            fontSize=9, textColor=BODY_COLOR, leading=13,
        ),
        "small": ParagraphStyle(
            "Small", parent=base["Normal"],
            fontSize=7.5, textColor=MID_GREY, leading=11,
        ),
        "cell": ParagraphStyle(
            "Cell", parent=base["Normal"],
            fontSize=8, textColor=BODY_COLOR,
            leading=11, wordWrap="CJK",
        ),
        "cell_desc": ParagraphStyle(
            "CellDesc", parent=base["Normal"],
            fontSize=7.5, textColor=BODY_COLOR,
            leading=10.5, wordWrap="CJK",
        ),
        "caption": ParagraphStyle(
            "Caption", parent=base["Normal"],
            fontSize=8, textColor=MID_GREY, alignment=TA_CENTER,
        ),
        "right": ParagraphStyle(
            "Right", parent=base["Normal"],
            fontSize=8, textColor=MID_GREY, alignment=TA_RIGHT,
        ),
    }


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _t(value: Any, max_len: int = 80) -> str:
    s = str(value) if value is not None else "—"
    return s[:max_len] + "…" if len(s) > max_len else s


def _priority_badge(priority: str, sty: dict) -> Paragraph:
    col = PRIORITY_COLORS.get(priority, MID_GREY).hexval()
    return Paragraph(f'<font color="{col}"><b>{priority.upper()}</b></font>', sty["cell"])


def _severity_badge(severity: str, sty: dict) -> Paragraph:
    col = SEVERITY_COLORS.get(severity.lower(), MID_GREY).hexval()
    return Paragraph(
        f'<font color="{col}"><b>{severity.upper()}</b></font>', sty["cell"]
    )


def _table_style(col_count: int, header_bg=TV1_NAVY) -> list:
    return [
        ("BACKGROUND",    (0, 0), (col_count - 1, 0), header_bg),
        ("TEXTCOLOR",     (0, 0), (col_count - 1, 0), WHITE),
        ("FONTNAME",      (0, 0), (col_count - 1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (col_count - 1, 0), 8),
        ("TOPPADDING",    (0, 0), (col_count - 1, 0), 6),
        ("BOTTOMPADDING", (0, 0), (col_count - 1, 0), 6),
        ("ROWBACKGROUNDS", (0, 1), (col_count - 1, -1), [WHITE, LIGHT_GREY]),
        ("GRID",          (0, 0), (-1, -1), 0.25, colors.HexColor("#DDDDDD")),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("TOPPADDING",    (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
    ]


# ── Cover page ─────────────────────────────────────────────────────────────────

def _cover(sty: dict, customer_name: str, generated_at: str) -> list:
    elems = []

    # Full-width navy header block
    header_data = [[
        Paragraph("TREND VISION ONE", sty["cover_title"]),
        "",
    ]]
    header_tbl = Table(header_data, colWidths=[CONTENT_W])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), TV1_NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 48),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("SPAN",          (0, 0), (-1, -1)),
    ]))
    elems.append(header_tbl)

    # Red band — report type
    sub_data = [[Paragraph("Patch Remediation Report", sty["cover_sub"])]]
    sub_tbl = Table(sub_data, colWidths=[CONTENT_W])
    sub_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), TV1_RED),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
    ]))
    elems.append(sub_tbl)

    # Navy footer band — customer / date
    meta_data = [[
        Paragraph(f"<b>{customer_name}</b>", sty["cover_meta"]),
        Paragraph(generated_at, sty["cover_meta"]),
    ]]
    meta_tbl = Table(meta_data, colWidths=[CONTENT_W * 0.6, CONTENT_W * 0.4])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), TV1_NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("ALIGN",         (1, 0), (1, 0),  "RIGHT"),
    ]))
    elems.append(meta_tbl)
    elems.append(Spacer(1, 0.6 * cm))
    elems.append(HRFlowable(width="100%", thickness=1, color=TV1_RED))
    return elems


# ── Executive summary ──────────────────────────────────────────────────────────

def _summary(sty: dict, groups: list) -> list:
    elems = [Paragraph("Executive Summary", sty["section"])]

    total_patches = len(groups)
    total_cves = sum(g["cve_count"] for g in groups)
    total_assets = len({a for g in groups for a in g["affected_assets"]})

    # Priority counts
    prio_counts: dict[str, int] = {"Immediate": 0, "High": 0, "Medium": 0, "Low": 0}
    for g in groups:
        prio_counts[g["install_priority"]] = prio_counts.get(g["install_priority"], 0) + 1

    # Summary stat table
    stat_rows = [
        ["Metric", "Count"],
        ["Distinct patches / actions required", str(total_patches)],
        ["Total CVEs remediated", str(total_cves)],
        ["Affected assets", str(total_assets)],
        ["Immediate priority patches", str(prio_counts["Immediate"])],
        ["High priority patches", str(prio_counts["High"])],
        ["Medium priority patches", str(prio_counts["Medium"])],
        ["Low priority patches", str(prio_counts["Low"])],
    ]
    stat_tbl = Table(stat_rows, colWidths=[10 * cm, 4 * cm], repeatRows=1)
    stat_tbl.setStyle(TableStyle(_table_style(2)))
    elems.append(stat_tbl)
    elems.append(Spacer(1, 0.5 * cm))

    elems.append(Paragraph(
        "<b>How to read this report:</b> Each entry represents a single patch or update "
        "action. Installing one patch may fix multiple CVEs across multiple assets. "
        "Patches are ordered by <b>priority tier</b> first (Immediate → High → Medium → Low), "
        "then by <b>impact score</b> (CVEs fixed × assets affected) so the highest-value "
        "remediation within each tier appears first. The Patch Index on the following "
        "page provides a complete sortable reference.",
        sty["body"],
    ))
    return elems


# ── Patch index table (overview) ───────────────────────────────────────────────

def _patch_index(sty: dict, groups: list) -> list:
    # This section renders in landscape — uses CONTENT_LAND_W
    cw = CONTENT_LAND_W

    elems = [
        Paragraph("Patch Index — All Actions Required", sty["section"]),
        Paragraph(
            "Sorted by impact: patches fixing the most CVEs across the most assets appear first. "
            "Address <b>Immediate</b> items before moving to lower priority tiers.",
            sty["body"],
        ),
        Spacer(1, 0.3 * cm),
    ]

    headers = ["#", "Patch / Identifier", "Type", "Vendor / Product",
               "Priority", "CVEs\nFixed", "Assets\nAffected", "Impact\nScore"]
    rows = [headers]

    for idx, g in enumerate(groups, 1):
        product_str = g["product"]
        if g["product_version"]:
            product_str += f" {g['product_version']}"
        vendor_product = f"{g['vendor']} — {product_str}" if g["vendor"] else product_str
        impact = g["cve_count"] * g["asset_count"]

        rows.append([
            Paragraph(str(idx), sty["cell"]),
            Paragraph(_t(g["patch_key"], 40), sty["cell"]),
            Paragraph(PATCH_TYPE_LABELS.get(g["patch_type"], g["patch_type"]), sty["cell"]),
            Paragraph(_t(vendor_product, 44), sty["cell"]),
            _priority_badge(g["install_priority"], sty),
            Paragraph(str(g["cve_count"]), sty["cell"]),
            Paragraph(str(g["asset_count"]), sty["cell"]),
            Paragraph(str(impact), sty["cell"]),
        ])

    # 8 cols on ~25.7 cm landscape content width
    # #(0.7) | Patch(6.5) | Type(3.0) | Vendor/Product(6.5) | Priority(2.4) | CVEs(1.8) | Assets(1.9) | Impact(1.9)
    col_widths = [0.7*cm, 6.5*cm, 3.0*cm, 6.5*cm, 2.4*cm, 1.8*cm, 1.9*cm, 1.9*cm]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1, splitByRow=True)

    sty_cmds = _table_style(8)
    # Centre the numeric columns
    sty_cmds += [
        ("ALIGN", (5, 0), (7, -1), "CENTER"),
        ("FONTNAME", (5, 0), (7, 0), "Helvetica-Bold"),
    ]
    tbl.setStyle(TableStyle(sty_cmds))
    elems.append(tbl)
    return elems


# ── Detailed patch entries ─────────────────────────────────────────────────────

def _patch_detail_section(sty: dict, groups: list) -> list:
    elems = [
        PageBreak(),
        Paragraph("Detailed Patch Entries", sty["section"]),
    ]

    for idx, g in enumerate(groups, 1):
        prio_col = PRIORITY_COLORS.get(g["install_priority"], MID_GREY)

        # ── Patch header bar ──
        cvss_display = f"CVSS {g['worst_cvss']:.1f}"
        header_data = [[
            Paragraph(
                f'<font color="white"><b>#{idx} — {_t(g["patch_key"], 40)}</b>  '
                f'<font size="8">{PATCH_TYPE_LABELS.get(g["patch_type"], "")} · '
                f'{g["install_priority"].upper()} PRIORITY</font></font>',
                sty["body"],
            ),
            Paragraph(
                f'<font color="white"><b>{cvss_display}</b></font>',
                ParagraphStyle("HdrRight", parent=sty["body"],
                               alignment=TA_RIGHT, textColor=WHITE),
            ),
        ]]
        header_tbl = Table(header_data, colWidths=[CONTENT_W * 0.78, CONTENT_W * 0.22])
        header_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), prio_col),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ROUNDEDCORNERS", [4, 4, 0, 0]),
        ]))

        # ── Metadata row ──
        product_str = g["product"]
        if g["product_version"]:
            product_str += f"  {g['product_version']}"

        meta_items = [
            ("Vendor",   g["vendor"] or "—"),
            ("Product",  product_str or "—"),
            ("CVEs",     str(g["cve_count"])),
            ("Assets",   str(g["asset_count"])),
            ("Worst CVSS", f"{g['worst_cvss']:.1f}"),
        ]
        meta_row = [[
            Paragraph(f"<b>{k}:</b> {v}", sty["small"])
            for k, v in meta_items
        ]]
        meta_tbl = Table(meta_row, colWidths=[CONTENT_W / 5] * 5)
        meta_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), LIGHT_GREY),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("GRID",          (0, 0), (-1, -1), 0.25, colors.HexColor("#DDDDDD")),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))

        if g["patch_url"]:
            url_data = [[Paragraph(f'<b>Reference:</b> <link href="{g["patch_url"]}">{_t(g["patch_url"], 80)}</link>', sty["small"])]]
            url_tbl = Table(url_data, colWidths=[CONTENT_W])
            url_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), LIGHT_GREY),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING",    (0, 0), (-1, -1), 2),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("GRID",          (0, 0), (-1, -1), 0.25, colors.HexColor("#DDDDDD")),
            ]))
        else:
            url_tbl = None

        # ── CVE table ──
        # Column layout adapts to available data fields.
        # When both CWE and Exploit are present we keep the table to 5 cols
        # (drop Description) — 6 cols is too cramped on A4.
        has_cwe     = any(v.get("cwe")     for v in g["cve_details"])
        has_exploit = any(v.get("exploit") for v in g["cve_details"])

        # CVE-ID column: max 18 chars (e.g. "CVE-2024-123456" = 15)
        # CVSS column:   max 4 chars ("10.0")
        # Severity:      fixed badge width
        ID_W    = 3.2 * cm
        SEV_W   = 2.2 * cm
        CVSS_W  = 1.4 * cm
        AGE_W   = 2.0 * cm
        CWE_W   = 2.4 * cm
        EXP_W   = 3.6 * cm
        DESC_W  = CONTENT_W - ID_W - SEV_W - CVSS_W - AGE_W  # remaining for description

        if has_cwe and has_exploit:
            # 6 cols: CVE | Sev | CVSS | Age | CWE | Exploit
            cve_headers = ["CVE ID", "Severity", "CVSS", "Age", "CWE", "Exploit Potential"]
            cve_rows = [cve_headers]
            for v in g["cve_details"]:
                cve_rows.append([
                    Paragraph(_t(v.get("cveId", v.get("id", "—")), 20), sty["cell"]),
                    _severity_badge(v.get("severity", "unknown"), sty),
                    Paragraph(str(v.get("cvssScore", v.get("riskScore", "—"))), sty["cell"]),
                    Paragraph(_age_label(v.get("published", "")), sty["cell"]),
                    Paragraph(_t(v.get("cwe", "—"), 18), sty["cell"]),
                    Paragraph(_t(v.get("exploit", "—"), 30), sty["cell"]),
                ])
            rest = CONTENT_W - ID_W - SEV_W - CVSS_W - AGE_W - CWE_W
            cve_col_widths = [ID_W, SEV_W, CVSS_W, AGE_W, CWE_W, rest]
        elif has_cwe:
            cve_headers = ["CVE ID", "Severity", "CVSS", "Age", "CWE", "Description"]
            cve_rows = [cve_headers]
            for v in g["cve_details"]:
                cve_rows.append([
                    Paragraph(_t(v.get("cveId", v.get("id", "—")), 20), sty["cell"]),
                    _severity_badge(v.get("severity", "unknown"), sty),
                    Paragraph(str(v.get("cvssScore", v.get("riskScore", "—"))), sty["cell"]),
                    Paragraph(_age_label(v.get("published", "")), sty["cell"]),
                    Paragraph(_t(v.get("cwe", "—"), 18), sty["cell"]),
                    Paragraph(_t(v.get("description", "—"), 120), sty["cell_desc"]),
                ])
            rest = CONTENT_W - ID_W - SEV_W - CVSS_W - AGE_W - CWE_W
            cve_col_widths = [ID_W, SEV_W, CVSS_W, AGE_W, CWE_W, rest]
        elif has_exploit:
            cve_headers = ["CVE ID", "Severity", "CVSS", "Age", "Exploit Potential", "Description"]
            cve_rows = [cve_headers]
            for v in g["cve_details"]:
                cve_rows.append([
                    Paragraph(_t(v.get("cveId", v.get("id", "—")), 20), sty["cell"]),
                    _severity_badge(v.get("severity", "unknown"), sty),
                    Paragraph(str(v.get("cvssScore", v.get("riskScore", "—"))), sty["cell"]),
                    Paragraph(_age_label(v.get("published", "")), sty["cell"]),
                    Paragraph(_t(v.get("exploit", "—"), 30), sty["cell"]),
                    Paragraph(_t(v.get("description", "—"), 120), sty["cell_desc"]),
                ])
            rest = CONTENT_W - ID_W - SEV_W - CVSS_W - AGE_W - EXP_W
            cve_col_widths = [ID_W, SEV_W, CVSS_W, AGE_W, EXP_W, rest]
        else:
            cve_headers = ["CVE ID", "Severity", "CVSS", "Age", "Description"]
            cve_rows = [cve_headers]
            for v in g["cve_details"]:
                cve_rows.append([
                    Paragraph(_t(v.get("cveId", v.get("id", "—")), 20), sty["cell"]),
                    _severity_badge(v.get("severity", "unknown"), sty),
                    Paragraph(str(v.get("cvssScore", v.get("riskScore", "—"))), sty["cell"]),
                    Paragraph(_age_label(v.get("published", "")), sty["cell"]),
                    Paragraph(_t(v.get("description", "—"), 160), sty["cell_desc"]),
                ])
            cve_col_widths = [ID_W, SEV_W, CVSS_W, AGE_W, DESC_W]

        cve_tbl = Table(
            cve_rows, colWidths=cve_col_widths, repeatRows=1,
            splitByRow=True,
        )
        cve_tbl.setStyle(TableStyle(_table_style(len(cve_rows[0]), header_bg=TV1_NAVY2)))

        # ── Affected assets table ──
        # Use extended columns when TV1 CSV fields are present
        has_os       = any(isinstance(d, dict) and d.get("os")        for d in g["affected_asset_details"])
        has_lastuser = any(isinstance(d, dict) and d.get("last_user") for d in g["affected_asset_details"])
        has_lastseen = any(isinstance(d, dict) and d.get("last_seen") for d in g["affected_asset_details"])

        if has_os or has_lastuser:
            asset_header = ["Device", "IP Address", "OS / Application", "Last User", "Last Detected"]
            asset_rows = [asset_header]
            for detail in g["affected_asset_details"]:
                if isinstance(detail, dict):
                    asset_rows.append([
                        Paragraph(_t(detail.get("hostname", "—"), 32), sty["cell"]),
                        Paragraph(_t(detail.get("ip", "—"), 18), sty["cell"]),
                        Paragraph(_t(detail.get("os", "—"), 30), sty["cell_desc"]),
                        Paragraph(_t(detail.get("last_user", "—"), 24), sty["cell"]),
                        Paragraph(_t(detail.get("last_seen", "—"), 22), sty["cell"]),
                    ])
                else:
                    asset_rows.append([Paragraph(_t(str(detail), 32), sty["cell"])]
                                      + [Paragraph("—", sty["cell"])] * 4)
            # 5 cols on 17cm: Device 4.2 | IP 2.8 | OS 4.5 | User 3.0 | Date 2.5
            asset_col_widths = [4.2*cm, 2.8*cm, 4.5*cm, 3.0*cm, CONTENT_W - 14.5*cm]
            asset_tbl = Table(asset_rows, colWidths=asset_col_widths, repeatRows=1, splitByRow=True)
            asset_tbl.setStyle(TableStyle(_table_style(5, header_bg=TV1_NAVY2)))
        else:
            asset_rows = [["Affected Asset", "IP Address", "Agent GUID"]]
            for detail in g["affected_asset_details"]:
                if isinstance(detail, dict):
                    asset_rows.append([
                        Paragraph(_t(detail.get("hostname", "—"), 34), sty["cell"]),
                        Paragraph(_t(detail.get("ip", "—"), 18), sty["cell"]),
                        Paragraph(_t(detail.get("agentGuid", "—"), 40), sty["cell_desc"]),
                    ])
                else:
                    asset_rows.append([
                        Paragraph(_t(str(detail), 34), sty["cell"]),
                        Paragraph("—", sty["cell"]),
                        Paragraph("—", sty["cell"]),
                    ])
            # 3 cols on 17cm: Device 5.5 | IP 3.5 | GUID rest
            asset_col_widths = [5.5*cm, 3.5*cm, CONTENT_W - 9.0*cm]
            asset_tbl = Table(asset_rows, colWidths=asset_col_widths, repeatRows=1, splitByRow=True)
            asset_tbl.setStyle(TableStyle(_table_style(3, header_bg=TV1_NAVY2)))

        # Build block: keep the patch header + meta + first CVE header row together
        # so a patch never starts at the very bottom of a page.
        header_block = [header_tbl, meta_tbl]
        if url_tbl:
            header_block.append(url_tbl)
        header_block += [
            Spacer(1, 0.25 * cm),
            Paragraph("CVEs Remediated by This Patch", sty["patch_title"]),
        ]

        body_block = [
            cve_tbl,
            Spacer(1, 0.3 * cm),
            Paragraph("Affected Assets", sty["patch_title"]),
            asset_tbl,
            Spacer(1, 0.8 * cm),
        ]

        elems.append(KeepTogether(header_block))
        elems.extend(body_block)

    return elems


# ── By-device appendix ────────────────────────────────────────────────────────

def _by_device_section(sty: dict, groups: list) -> list:
    """
    Appendix: invert the patch→device map to device→patches.
    For each device, list every patch it needs with priority, CVSS, and CVE count.
    Mirrors the Qualys 'Missing Patch Report by Device' layout.
    """
    # Build {device_name: [(patch_key, patch_type, priority, cvss, cve_count, patch_url), ...]}
    device_map: dict[str, list[dict]] = {}
    for g in groups:
        for detail in g["affected_asset_details"]:
            if isinstance(detail, dict):
                name = detail.get("hostname") or detail.get("ip") or "Unknown Asset"
                ip   = detail.get("ip", "—")
            else:
                name = str(detail)
                ip   = "—"
            entry = {
                "patch_key":       g["patch_key"],
                "patch_type":      PATCH_TYPE_LABELS.get(g["patch_type"], g["patch_type"]),
                "priority":        g["install_priority"],
                "cvss":            g["worst_cvss"],
                "cve_count":       g["cve_count"],
                "patch_url":       g["patch_url"],
                "ip":              ip,
            }
            device_map.setdefault(name, []).append(entry)

    if not device_map:
        return []

    priority_order = {"Immediate": 0, "High": 1, "Medium": 2, "Low": 3}
    elems: list = [
        PageBreak(),
        Paragraph("Appendix — Patches Required by Device", sty["section"]),
        Paragraph(
            "For each device, the table below lists every patch action required, "
            "ordered by priority. Use this view to plan device-level remediation work.",
            sty["body"],
        ),
        Spacer(1, 0.3 * cm),
    ]

    # Sort devices alphabetically
    for device_name in sorted(device_map.keys()):
        patches = sorted(
            device_map[device_name],
            key=lambda p: (priority_order.get(p["priority"], 9), -p["cvss"]),
        )

        # Device header
        ip_str = patches[0]["ip"] if patches else "—"
        total_cves = sum(p["cve_count"] for p in patches)
        dev_header_data = [[
            Paragraph(
                f'<font color="white"><b>{_t(device_name, 50)}</b>'
                f'  <font size="8">IP: {ip_str} · '
                f'{len(patches)} patch action{"s" if len(patches) != 1 else ""} · '
                f'{total_cves} CVE{"s" if total_cves != 1 else ""}</font></font>',
                sty["body"],
            )
        ]]
        dev_header_tbl = Table(dev_header_data, colWidths=[CONTENT_W])
        dev_header_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), TV1_NAVY),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ]))

        # Patch rows
        patch_rows = [["Patch / Identifier", "Type", "Priority", "CVSS", "CVEs Fixed", "Reference URL"]]
        for p in patches:
            prio_col = PRIORITY_COLORS.get(p["priority"], MID_GREY).hexval()
            ref = _t(p["patch_url"], 50) if p["patch_url"] else "—"
            patch_rows.append([
                Paragraph(_t(p["patch_key"], 36), sty["cell"]),
                Paragraph(p["patch_type"], sty["cell"]),
                Paragraph(
                    f'<font color="{prio_col}"><b>{p["priority"].upper()}</b></font>',
                    sty["cell"],
                ),
                Paragraph(f'{p["cvss"]:.1f}', sty["cell"]),
                Paragraph(str(p["cve_count"]), sty["cell"]),
                Paragraph(
                    f'<link href="{p["patch_url"]}">{ref}</link>'
                    if p["patch_url"] else "—",
                    sty["cell_desc"],
                ),
            ])
        # 6 cols on ~17cm: Patch(4.8) | Type(2.6) | Priority(2.0) | CVSS(1.2) | CVEs(1.2) | URL(rest)
        col_w = [4.8*cm, 2.6*cm, 2.0*cm, 1.2*cm, 1.2*cm, CONTENT_W - 11.8*cm]
        patch_tbl = Table(patch_rows, colWidths=col_w, repeatRows=1, splitByRow=True)
        patch_tbl.setStyle(TableStyle(
            _table_style(6, header_bg=TV1_NAVY2)
            + [("ALIGN", (3, 0), (4, -1), "CENTER")]
        ))

        elems.append(KeepTogether([dev_header_tbl, Spacer(1, 0)]))
        elems.append(patch_tbl)
        elems.append(Spacer(1, 0.6 * cm))

    return elems


# ── Footers (orientation-aware) ────────────────────────────────────────────────

def _footer_portrait(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MID_GREY)
    canvas.drawString(MARGIN, 1.2 * cm,
                      "Trend Vision One — Patch Remediation Report — Confidential")
    canvas.drawRightString(PAGE_W - MARGIN, 1.2 * cm, f"Page {doc.page}")
    canvas.restoreState()


def _footer_landscape(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MID_GREY)
    canvas.drawString(MARGIN, 1.2 * cm,
                      "Trend Vision One — Patch Remediation Report — Confidential")
    canvas.drawRightString(PAGE_LAND_W - MARGIN, 1.2 * cm, f"Page {doc.page}")
    canvas.restoreState()


# ── Public entry point ─────────────────────────────────────────────────────────

def generate_patch_report(
    patch_groups: list,   # list of PatchGroup.to_dict() dicts
    customer_name: str = "Customer",
    output_path: str | None = None,
) -> str:
    """
    Build and save the patch remediation PDF.

    Layout:
      • Cover + Executive Summary  — portrait A4
      • Patch Index overview table — landscape A4  (wider columns, impact score)
      • Detailed patch entries     — portrait A4

    Args:
        patch_groups:  List of PatchGroup.to_dict() dicts from collect_patch_groups().
        customer_name: Customer name shown on the cover page.
        output_path:   File path to write. Auto-generated if None.

    Returns:
        Absolute path to the written PDF.
    """
    output_dir = os.getenv("REPORT_OUTPUT_DIR", "./output")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    if output_path is None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = str(Path(output_dir) / f"patch_remediation_{ts}.pdf")

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sty = _styles()

    # ── Page templates ────────────────────────────────────────────────────────
    portrait_frame = Frame(
        MARGIN, BOTTOM_MARGIN,
        PAGE_W - 2 * MARGIN,
        PAGE_H - MARGIN - BOTTOM_MARGIN,
        id="portrait",
    )
    landscape_frame = Frame(
        MARGIN, BOTTOM_MARGIN,
        PAGE_LAND_W - 2 * MARGIN,
        PAGE_LAND_H - MARGIN - BOTTOM_MARGIN,
        id="landscape",
    )
    port_tmpl = PageTemplate(
        id="Portrait",
        frames=[portrait_frame],
        pagesize=A4,
        onPage=_footer_portrait,
    )
    land_tmpl = PageTemplate(
        id="Landscape",
        frames=[landscape_frame],
        pagesize=landscape(A4),
        onPage=_footer_landscape,
    )

    doc = BaseDocTemplate(
        output_path,
        pageTemplates=[port_tmpl, land_tmpl],
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=BOTTOM_MARGIN,
        title=f"Patch Remediation Report — {customer_name}",
        author="Trend Vision One Reporter",
    )

    # Serialise PatchGroup objects if needed
    groups = [
        g.to_dict() if hasattr(g, "to_dict") else g
        for g in patch_groups
    ]

    story: list = []

    # ── Portrait: cover + executive summary ───────────────────────────────────
    story += _cover(sty, customer_name, generated_at)
    story += _summary(sty, groups)

    if groups:
        # ── Landscape: patch index overview ───────────────────────────────────
        story.append(NextPageTemplate("Landscape"))
        story.append(PageBreak())
        story += _patch_index(sty, groups)

        # ── Portrait: detailed patch entries ──────────────────────────────────
        story.append(NextPageTemplate("Portrait"))
        story.append(PageBreak())
        story += _patch_detail_section(sty, groups)

        # ── Portrait: by-device appendix ──────────────────────────────────────
        story += _by_device_section(sty, groups)
    else:
        story.append(Spacer(1, 1 * cm))
        story.append(Paragraph(
            "No vulnerabilities with available patch data were found for the selected filters.",
            sty["body"],
        ))

    doc.build(story)
    return os.path.abspath(output_path)
