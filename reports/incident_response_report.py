"""
Incident Response Summary PDF Report Generator for Trend Vision One.

Produces an overview of investigations, status and severity breakdowns,
open investigations, response actions taken, and stale investigations.
"""

from __future__ import annotations

import html
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
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
TV1_LIGHT  = colors.HexColor("#F4F6FA")
MID_GREY   = colors.HexColor("#6B6B6B")
LIGHT_GREY = colors.HexColor("#F4F6FA")
WHITE      = colors.white

SEVERITY_COLORS = {
    "critical": colors.HexColor("#D71920"),
    "high":     colors.HexColor("#E8610A"),
    "medium":   colors.HexColor("#D4A017"),
    "low":      colors.HexColor("#2E7D32"),
    "info":     colors.HexColor("#1565C0"),
}

PAGE_W, PAGE_H = A4
CONTENT_W = PAGE_W - 4 * cm


# ── Styles ────────────────────────────────────────────────────────────────────

def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "IRCoverTitle", parent=base["Title"],
            fontSize=26, textColor=WHITE, alignment=TA_CENTER, spaceAfter=4,
        ),
        "cover_sub": ParagraphStyle(
            "IRCoverSub", parent=base["Normal"],
            fontSize=13, textColor=colors.HexColor("#BBCCDD"),
            alignment=TA_CENTER, spaceAfter=2,
        ),
        "cover_customer": ParagraphStyle(
            "IRCoverCustomer", parent=base["Normal"],
            fontSize=15, textColor=WHITE,
            alignment=TA_CENTER, spaceAfter=2, fontName="Helvetica-Bold",
        ),
        "section": ParagraphStyle(
            "IRSection", parent=base["Heading1"],
            fontSize=13, textColor=TV1_RED, spaceBefore=14, spaceAfter=6,
        ),
        "subsection": ParagraphStyle(
            "IRSubSection", parent=base["Heading2"],
            fontSize=11, textColor=TV1_NAVY, spaceBefore=8, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "IRBody", parent=base["Normal"],
            fontSize=9, textColor=colors.HexColor("#2C2C2C"), leading=13,
        ),
        "small": ParagraphStyle(
            "IRSmall", parent=base["Normal"],
            fontSize=7.5, textColor=MID_GREY, leading=11,
        ),
        "cell": ParagraphStyle(
            "IRCell", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#2C2C2C"),
            leading=11, wordWrap="CJK",
        ),
        "caption": ParagraphStyle(
            "IRCaption", parent=base["Normal"],
            fontSize=8, textColor=MID_GREY, alignment=TA_CENTER,
        ),
        "stat_value": ParagraphStyle(
            "IRStatValue", parent=base["Normal"],
            fontSize=22, textColor=WHITE, alignment=TA_CENTER,
            fontName="Helvetica-Bold", spaceAfter=2,
        ),
        "stat_label": ParagraphStyle(
            "IRStatLabel", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#DDDDDD"),
            alignment=TA_CENTER, leading=10,
        ),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _t(value: Any, max_len: int = 60) -> str:
    s = str(value) if value is not None else "—"
    s = html.escape(s)
    return s[:max_len] + "…" if len(s) > max_len else s


def _sev_badge(sev: str, sty: dict) -> Paragraph:
    col = SEVERITY_COLORS.get(sev.lower(), MID_GREY).hexval()
    return Paragraph(f'<font color="{col}"><b>{html.escape(sev.upper())}</b></font>', sty["cell"])


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
    canvas.drawString(2 * cm, 1.2 * cm, "Trend Vision One — Incident Response Summary — Confidential")
    canvas.drawRightString(PAGE_W - 2 * cm, 1.2 * cm, f"Page {doc.page}")
    canvas.restoreState()


# ── Cover page ────────────────────────────────────────────────────────────────

def _cover(sty: dict, customer_name: str, period_days: int, generated_at: str) -> list:
    elems = []

    header_data = [[Paragraph("Trend Vision One", sty["cover_title"])]]
    header_tbl = Table(header_data, colWidths=[CONTENT_W])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), TV1_NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 36),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
    ]))
    elems.append(header_tbl)

    sub_data = [[Paragraph("Incident Response Summary", sty["cover_sub"])]]
    sub_tbl = Table(sub_data, colWidths=[CONTENT_W])
    sub_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), TV1_RED),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    elems.append(sub_tbl)
    elems.append(Spacer(1, 0.8 * cm))

    cust_data = [[Paragraph(html.escape(customer_name), sty["cover_customer"])]]
    cust_tbl = Table(cust_data, colWidths=[CONTENT_W])
    cust_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), TV1_NAVY2),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    elems.append(cust_tbl)
    elems.append(Spacer(1, 0.4 * cm))
    elems.append(Paragraph(f"Reporting Period: {period_days} days", sty["caption"]))
    elems.append(Paragraph(f"Generated: {generated_at}", sty["caption"]))
    elems.append(Spacer(1, 0.5 * cm))
    elems.append(HRFlowable(width="100%", thickness=1, color=TV1_RED))
    return elems


# ── Summary stat cards ────────────────────────────────────────────────────────

def _stat_cards(sty: dict, data: dict) -> list:
    elems = [
        PageBreak(),
        Paragraph("Incident Response Overview", sty["section"]),
    ]

    total_investigations = data.get("total_investigations", 0)
    open_count           = data.get("open_count", 0)
    avg_resolution_days  = data.get("avg_resolution_days", 0.0)
    total_actions_taken  = data.get("total_actions_taken", 0)

    card_bg_colors = [TV1_NAVY, TV1_RED, colors.HexColor("#E8610A"), colors.HexColor("#2E7D32")]
    card_labels    = ["Total Investigations", "Open", "Avg Resolution Days", "Total Actions Taken"]
    card_values    = [
        str(total_investigations),
        str(open_count),
        str(avg_resolution_days),
        str(total_actions_taken),
    ]

    cards_row = [[
        Table(
            [[Paragraph(card_values[i], sty["stat_value"])],
             [Paragraph(card_labels[i], sty["stat_label"])]],
            colWidths=[(CONTENT_W / 4) - 0.2 * cm],
            style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), card_bg_colors[i]),
                ("TOPPADDING",    (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]),
        )
        for i in range(4)
    ]]

    outer_tbl = Table(cards_row, colWidths=[(CONTENT_W / 4)] * 4)
    outer_tbl.setStyle(TableStyle([
        ("LEFTPADDING",  (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(outer_tbl)
    elems.append(Spacer(1, 0.4 * cm))
    return elems


# ── Status Breakdown ──────────────────────────────────────────────────────────

def _status_breakdown_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Investigation Status Breakdown", sty["section"])]

    by_status = data.get("by_status") or {}

    rows = [["Status", "Count"]]
    if by_status:
        for status, count in sorted(by_status.items(), key=lambda x: x[1], reverse=True):
            rows.append([
                Paragraph(_t(status, 40), sty["cell"]),
                Paragraph(str(count), sty["cell"]),
            ])
    else:
        rows.append([Paragraph("N/A", sty["cell"]), Paragraph("0", sty["cell"])])

    tbl = Table(rows, colWidths=[CONTENT_W - 4 * cm, 4 * cm], repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(2)))
    elems.append(tbl)
    return elems


# ── Severity Breakdown ────────────────────────────────────────────────────────

def _severity_breakdown_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Investigation Severity Breakdown", sty["section"])]

    by_severity = data.get("by_severity") or {}

    rows = [["Severity", "Count"]]
    if by_severity:
        for sev in ("critical", "high", "medium", "low", "info"):
            count = by_severity.get(sev)
            if count is None:
                continue
            rows.append([
                _sev_badge(sev, sty),
                Paragraph(str(count), sty["cell"]),
            ])
        # any extra keys not in standard order
        for sev, count in by_severity.items():
            if sev not in ("critical", "high", "medium", "low", "info"):
                rows.append([
                    Paragraph(_t(sev, 30), sty["cell"]),
                    Paragraph(str(count), sty["cell"]),
                ])
    else:
        rows.append([Paragraph("N/A", sty["cell"]), Paragraph("0", sty["cell"])])

    if len(rows) == 1:
        rows.append([Paragraph("N/A", sty["cell"]), Paragraph("0", sty["cell"])])

    tbl = Table(rows, colWidths=[CONTENT_W - 4 * cm, 4 * cm], repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(2)))
    elems.append(tbl)
    return elems


# ── Open Investigations ───────────────────────────────────────────────────────

def _open_investigations_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Open Investigations", sty["section"])]

    open_invs = data.get("open_investigations") or []

    rows = [["Title", "Severity", "Days Open", "Assigned To"]]
    if open_invs:
        for inv in open_invs:
            rows.append([
                Paragraph(_t(inv.get("title", "—"), 35), sty["cell"]),
                _sev_badge(str(inv.get("severity", "unknown")), sty),
                Paragraph(str(inv.get("days_open", "—")), sty["cell"]),
                Paragraph(_t(inv.get("assigned_to", "—"), 25), sty["cell"]),
            ])
    else:
        rows.append([
            Paragraph("N/A", sty["cell"]),
            Paragraph("—", sty["cell"]),
            Paragraph("—", sty["cell"]),
            Paragraph("—", sty["cell"]),
        ])

    col_widths = [
        CONTENT_W * 0.38,
        CONTENT_W * 0.18,
        CONTENT_W * 0.16,
        CONTENT_W * 0.28,
    ]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(4)))
    elems.append(tbl)
    return elems


# ── Response Actions Taken ────────────────────────────────────────────────────

def _actions_taken_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Response Actions Taken", sty["section"])]

    actions = data.get("actions_taken") or {}

    rows = [["Action Type", "Count"]]
    if actions:
        for action_type, count in sorted(actions.items(), key=lambda x: x[1], reverse=True):
            rows.append([
                Paragraph(_t(action_type, 50), sty["cell"]),
                Paragraph(str(count), sty["cell"]),
            ])
    else:
        rows.append([Paragraph("N/A", sty["cell"]), Paragraph("0", sty["cell"])])

    tbl = Table(rows, colWidths=[CONTENT_W - 4 * cm, 4 * cm], repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(2)))
    elems.append(tbl)
    return elems


# ── Stale Investigations ──────────────────────────────────────────────────────

def _stale_investigations_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Stale Investigations", sty["section"])]

    stale = data.get("stale_investigations") or []

    rows = [["Title", "Days Open", "Severity"]]
    if stale:
        for inv in stale:
            rows.append([
                Paragraph(_t(inv.get("title", "—"), 45), sty["cell"]),
                Paragraph(str(inv.get("days_open", "—")), sty["cell"]),
                _sev_badge(str(inv.get("severity", "unknown")), sty),
            ])
    else:
        rows.append([
            Paragraph("N/A", sty["cell"]),
            Paragraph("—", sty["cell"]),
            Paragraph("—", sty["cell"]),
        ])

    col_widths = [CONTENT_W * 0.60, CONTENT_W * 0.18, CONTENT_W * 0.22]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(3)))
    elems.append(tbl)
    return elems


# ── Public entry point ────────────────────────────────────────────────────────

def generate_incident_response_report(
    data: dict,
    customer_name: str = "Customer",
    period_days: int = 30,
    output_path: str | None = None,
) -> str:
    """
    Build and save the Incident Response Summary PDF report.

    Args:
        data:          Dict containing incident response metrics.
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
        output_path = str(Path(output_dir) / f"incident_response_{ts}.pdf")

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sty = _styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2.5 * cm,
        title=f"Incident Response Summary — {customer_name}",
        author="Trend Vision One Reporter",
    )

    story: list = []
    story += _cover(sty, customer_name, period_days, generated_at)
    story += _stat_cards(sty, data)
    story += _status_breakdown_section(sty, data)
    story += _severity_breakdown_section(sty, data)
    story += [PageBreak()]
    story += _open_investigations_section(sty, data)
    story += _actions_taken_section(sty, data)
    story += [PageBreak()]
    story += _stale_investigations_section(sty, data)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return os.path.abspath(output_path)
