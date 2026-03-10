"""
Threat Behaviour Analysis PDF Report Generator for Trend Vision One.

Organises OAT detections into behaviour categories with per-category detail,
affected entities, MITRE technique mappings, and plain-English interpretations.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ── Colour palette ────────────────────────────────────────────────────────────
TV1_RED    = colors.HexColor("#D71920")
TV1_NAVY   = colors.HexColor("#172239")
TV1_NAVY2  = colors.HexColor("#1e2d4a")
MID_GREY   = colors.HexColor("#6B6B6B")
LIGHT_GREY = colors.HexColor("#F4F6FA")
WHITE      = colors.white

RISK_COLORS = {
    "critical": colors.HexColor("#D71920"),
    "high":     colors.HexColor("#E8610A"),
    "medium":   colors.HexColor("#D4A017"),
    "low":      colors.HexColor("#2E7D32"),
    "info":     colors.HexColor("#1565C0"),
    "unknown":  MID_GREY,
}

CATEGORY_BG_COLORS = [
    colors.HexColor("#172239"),
    colors.HexColor("#1e2d4a"),
    colors.HexColor("#2a3d5e"),
    colors.HexColor("#374f6a"),
    colors.HexColor("#1a3a52"),
    colors.HexColor("#0d2b40"),
    colors.HexColor("#223344"),
    colors.HexColor("#2c3e50"),
]

CATEGORY_INTERPRETATIONS: dict[str, str] = {
    "Credential Access & Logon Failures": (
        "Repeated logon failures and credential-related detections indicate that threat actors may be "
        "attempting brute-force attacks, password spraying, or Kerberos ticket abuse. Review privileged "
        "account activity, enforce multi-factor authentication, and investigate any accounts that have "
        "experienced multiple authentication failures within a short window."
    ),
    "Reconnaissance & Discovery": (
        "Discovery activity suggests adversaries are mapping the internal network, enumerating accounts, "
        "and gathering information about system configurations. This is commonly an early-stage activity "
        "preceding lateral movement or data theft. Monitor for unusual enumeration commands or PowerShell "
        "activity outside of normal administrative windows."
    ),
    "Persistence & Service Manipulation": (
        "Detections in this category indicate attempts to maintain access to compromised systems by "
        "modifying services, scheduled tasks, or startup entries. Review all recently created or modified "
        "services, and confirm any changes were authorised by the operations team."
    ),
    "Data Exfiltration Signals": (
        "HTTP, DNS, and exfiltration detections point to potential data leaving the environment. This may "
        "indicate data staging, command-and-control communication, or active exfiltration. Inspect outbound "
        "traffic patterns, review DLP policies, and investigate any large or unusual transfers."
    ),
    "Remote Access Tools": (
        "Detections of remote management tools such as AnyDesk, SuperOps, or other RMM platforms may "
        "indicate unauthorised remote access. Confirm that all detected tools are approved and in use by "
        "legitimate staff. Unauthorised RMM tools are a common indicator of business email compromise and "
        "ransomware pre-deployment activity."
    ),
    "Suspicious Network Activity": (
        "Domain, URL, and web reputation detections suggest communication with suspicious or known-malicious "
        "infrastructure. Verify whether the flagged domains or URLs are legitimate business resources. "
        "Implement DNS filtering and ensure web proxies are configured to block high-risk categories."
    ),
    "Email-Based Threats": (
        "Email-based threat detections indicate phishing attempts or malicious email delivery. Review mail "
        "flow logs for the flagged entities, confirm whether any malicious attachments or links were "
        "interacted with, and re-train affected users on phishing awareness."
    ),
    "Other Behavioural Signals": (
        "These detections did not match a specific behaviour category but may still represent meaningful "
        "security signals. Review each detection in the Trend Vision One console to determine whether "
        "further investigation or response action is required."
    ),
}

PAGE_W, PAGE_H = A4
CONTENT_W = PAGE_W - 4 * cm


# ── Styles ────────────────────────────────────────────────────────────────────

def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "TBCoverTitle", parent=base["Title"],
            fontSize=24, textColor=WHITE, alignment=TA_CENTER, spaceAfter=4,
        ),
        "cover_sub": ParagraphStyle(
            "TBCoverSub", parent=base["Normal"],
            fontSize=12, textColor=colors.HexColor("#BBCCDD"),
            alignment=TA_CENTER, spaceAfter=2,
        ),
        "section": ParagraphStyle(
            "TBSection", parent=base["Heading1"],
            fontSize=13, textColor=TV1_RED, spaceBefore=14, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "TBBody", parent=base["Normal"],
            fontSize=9, textColor=colors.HexColor("#2C2C2C"), leading=13,
        ),
        "interpretation": ParagraphStyle(
            "TBInterp", parent=base["Normal"],
            fontSize=8.5, textColor=colors.HexColor("#2C2C2C"), leading=13,
            backColor=colors.HexColor("#EEF2FA"), borderPad=6,
        ),
        "small": ParagraphStyle(
            "TBSmall", parent=base["Normal"],
            fontSize=7.5, textColor=MID_GREY, leading=11,
        ),
        "cell": ParagraphStyle(
            "TBCell", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#2C2C2C"),
            leading=11, wordWrap="CJK",
        ),
        "caption": ParagraphStyle(
            "TBCaption", parent=base["Normal"],
            fontSize=8, textColor=MID_GREY, alignment=TA_CENTER,
        ),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _t(value: Any, max_len: int = 60) -> str:
    s = str(value) if value is not None else "—"
    return s[:max_len] + "…" if len(s) > max_len else s


def _risk_badge(risk: str, sty: dict) -> Paragraph:
    col = RISK_COLORS.get(risk.lower(), MID_GREY).hexval()
    return Paragraph(f'<font color="{col}"><b>{risk.upper()}</b></font>', sty["cell"])


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


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MID_GREY)
    canvas.drawString(2 * cm, 1.2 * cm, "Trend Vision One — Threat Behaviour Analysis — Confidential")
    canvas.drawRightString(PAGE_W - 2 * cm, 1.2 * cm, f"Page {doc.page}")
    canvas.restoreState()


# ── Cover ─────────────────────────────────────────────────────────────────────

def _cover(sty: dict, customer_name: str, period_days: int, generated_at: str) -> list:
    elems = []
    header_data = [[Paragraph("Trend Vision One", sty["cover_title"])]]
    header_tbl = Table(header_data, colWidths=[CONTENT_W])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), TV1_NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 36),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elems.append(header_tbl)

    sub_data = [[Paragraph("Threat Behaviour Analysis", sty["cover_sub"])]]
    sub_tbl = Table(sub_data, colWidths=[CONTENT_W])
    sub_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), TV1_RED),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    elems.append(sub_tbl)
    elems.append(Spacer(1, 0.5 * cm))
    elems.append(Paragraph(f"Customer: <b>{customer_name}</b>", sty["body"]))
    elems.append(Paragraph(f"Period: {period_days} days  |  Generated: {generated_at}", sty["caption"]))
    elems.append(Spacer(1, 0.5 * cm))
    elems.append(HRFlowable(width="100%", thickness=1, color=TV1_RED))
    return elems


# ── Behaviour overview table ──────────────────────────────────────────────────

def _overview_table(sty: dict, data: dict) -> list:
    elems = [
        PageBreak(),
        Paragraph("Behaviour Category Overview", sty["section"]),
    ]

    categories = data.get("categories") or []
    total = data.get("total_detections") or 1
    unique_filters = data.get("unique_filters_seen") or 0

    elems.append(Paragraph(
        f"Total OAT detections: <b>{data.get('total_detections', 0)}</b>  |  "
        f"Unique behaviour filters seen: <b>{unique_filters}</b>",
        sty["body"],
    ))
    elems.append(Spacer(1, 0.3 * cm))

    if not categories:
        elems.append(Paragraph("No behaviour data available for the selected period.", sty["body"]))
        return elems

    max_count = max(c["total_count"] for c in categories) or 1
    bar_width = 25

    rows = [["Behaviour Category", "Detections", "% of Total", "Risk Bar"]]
    for cat in categories:
        cnt = cat.get("total_count", 0)
        pct = f"{cnt / total * 100:.1f}%"
        bar_len = int((cnt / max_count) * bar_width)
        bar = "\u2588" * bar_len
        rows.append([
            Paragraph(_t(cat.get("name", "—"), 40), sty["cell"]),
            Paragraph(str(cnt), sty["cell"]),
            Paragraph(pct, sty["cell"]),
            Paragraph(f'<font color="#D71920">{bar}</font>', sty["cell"]),
        ])

    tbl = Table(
        rows,
        colWidths=[6.5 * cm, 2 * cm, 2 * cm, CONTENT_W - 10.5 * cm],
        repeatRows=1,
    )
    tbl.setStyle(TableStyle(_table_style(4)))
    elems.append(tbl)
    return elems


# ── Per-category detail sections ──────────────────────────────────────────────

def _category_sections(sty: dict, data: dict) -> list:
    elems = [
        PageBreak(),
        Paragraph("Category Detail Sections", sty["section"]),
    ]

    categories = data.get("categories") or []
    if not categories:
        elems.append(Paragraph("No category data available.", sty["body"]))
        return elems

    for cat_idx, cat in enumerate(categories):
        cat_name = cat.get("name", "Unknown")
        total_count = cat.get("total_count", 0)
        detections = cat.get("detections") or []
        top_entities = cat.get("top_entities") or []

        bg_col = CATEGORY_BG_COLORS[cat_idx % len(CATEGORY_BG_COLORS)]

        header_data = [[
            Paragraph(
                f'<font color="white"><b>{_t(cat_name, 50)}</b>  '
                f'<font size="8">{total_count} detections</font></font>',
                sty["body"],
            )
        ]]
        header_tbl = Table(header_data, colWidths=[CONTENT_W])
        header_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), bg_col),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))

        # Behaviour detections table
        det_rows = [["Filter / Behaviour", "Count", "Risk Level", "MITRE Techniques", "Example Entities"]]
        for det in detections:
            techs = ", ".join(det.get("mitre_techniques") or []) or "—"
            entities = ", ".join(det.get("example_entities") or []) or "—"
            det_rows.append([
                Paragraph(_t(det.get("filter_name", "—"), 30), sty["cell"]),
                Paragraph(str(det.get("count", 0)), sty["cell"]),
                _risk_badge(det.get("risk_level", "unknown"), sty),
                Paragraph(_t(techs, 25), sty["cell"]),
                Paragraph(_t(entities, 25), sty["cell"]),
            ])

        if not detections:
            det_rows.append([
                Paragraph("No specific behaviours", sty["cell"]),
                Paragraph("0", sty["cell"]),
                Paragraph("—", sty["cell"]),
                Paragraph("—", sty["cell"]),
                Paragraph("—", sty["cell"]),
            ])

        det_tbl = Table(
            det_rows,
            colWidths=[4.5 * cm, 1.5 * cm, 2 * cm, 4 * cm, CONTENT_W - 12 * cm],
            repeatRows=1,
        )
        det_tbl.setStyle(TableStyle(_table_style(5, header_bg=TV1_NAVY2)))

        # Top entities
        entities_text = ", ".join(top_entities) if top_entities else "None identified"
        entities_para = Paragraph(
            f"<b>Most affected entities:</b> {_t(entities_text, 120)}",
            sty["small"],
        )

        # Interpretation paragraph
        interp_text = CATEGORY_INTERPRETATIONS.get(
            cat_name,
            "Review these detections in the Trend Vision One console to determine "
            "whether further investigation or response action is required.",
        )
        interp_para = Paragraph(
            f"<b>What this means:</b> {interp_text}",
            sty["interpretation"],
        )

        block = [
            header_tbl,
            Spacer(1, 0.1 * cm),
            det_tbl,
            Spacer(1, 0.15 * cm),
            entities_para,
            Spacer(1, 0.15 * cm),
            interp_para,
            Spacer(1, 0.5 * cm),
        ]
        elems.append(KeepTogether(block[:3]))
        elems.extend(block[3:])

    return elems


# ── Public entry point ────────────────────────────────────────────────────────

def generate_threat_behaviour_report(
    data: dict,
    customer_name: str = "Customer",
    period_days: int = 30,
    output_path: str | None = None,
) -> str:
    """
    Build and save the Threat Behaviour Analysis PDF report.

    Args:
        data:          Dict returned by collect_threat_behaviours().
        customer_name: Customer name for the cover page.
        period_days:   Number of days the report covers.
        output_path:   File path to write. Auto-generated if None.

    Returns:
        Absolute path to the written PDF.
    """
    output_dir = os.getenv("REPORT_OUTPUT_DIR", "./output")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    if output_path is None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = str(Path(output_dir) / f"threat_behaviour_{ts}.pdf")

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sty = _styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2.5 * cm,
        title=f"Threat Behaviour Analysis — {customer_name}",
        author="Trend Vision One Reporter",
    )

    story: list = []
    story += _cover(sty, customer_name, period_days, generated_at)
    story += _overview_table(sty, data)
    story += _category_sections(sty, data)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return os.path.abspath(output_path)
