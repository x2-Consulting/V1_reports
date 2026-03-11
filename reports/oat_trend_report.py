"""
OAT Detection Trend PDF Report Generator for Trend Vision One.

Produces a detailed overview of Object-Based Advanced Threat (OAT) detections
by day, top attack techniques, filter names, and most targeted entities.
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
            "OATCoverTitle", parent=base["Title"],
            fontSize=26, textColor=WHITE, alignment=TA_CENTER, spaceAfter=4,
        ),
        "cover_sub": ParagraphStyle(
            "OATCoverSub", parent=base["Normal"],
            fontSize=13, textColor=colors.HexColor("#BBCCDD"),
            alignment=TA_CENTER, spaceAfter=2,
        ),
        "cover_customer": ParagraphStyle(
            "OATCoverCustomer", parent=base["Normal"],
            fontSize=15, textColor=WHITE,
            alignment=TA_CENTER, spaceAfter=2, fontName="Helvetica-Bold",
        ),
        "section": ParagraphStyle(
            "OATSection", parent=base["Heading1"],
            fontSize=13, textColor=TV1_RED, spaceBefore=14, spaceAfter=6,
        ),
        "subsection": ParagraphStyle(
            "OATSubSection", parent=base["Heading2"],
            fontSize=11, textColor=TV1_NAVY, spaceBefore=8, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "OATBody", parent=base["Normal"],
            fontSize=9, textColor=colors.HexColor("#2C2C2C"), leading=13,
        ),
        "small": ParagraphStyle(
            "OATSmall", parent=base["Normal"],
            fontSize=7.5, textColor=MID_GREY, leading=11,
        ),
        "cell": ParagraphStyle(
            "OATCell", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#2C2C2C"),
            leading=11, wordWrap="CJK",
        ),
        "caption": ParagraphStyle(
            "OATCaption", parent=base["Normal"],
            fontSize=8, textColor=MID_GREY, alignment=TA_CENTER,
        ),
        "stat_value": ParagraphStyle(
            "OATStatValue", parent=base["Normal"],
            fontSize=22, textColor=WHITE, alignment=TA_CENTER,
            fontName="Helvetica-Bold", spaceAfter=2,
        ),
        "stat_label": ParagraphStyle(
            "OATStatLabel", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#DDDDDD"),
            alignment=TA_CENTER, leading=10,
        ),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _t(value: Any, max_len: int = 60) -> str:
    s = str(value) if value is not None else "—"
    s = html.escape(s)
    return s[:max_len] + "…" if len(s) > max_len else s


def _risk_badge(risk: str, sty: dict) -> Paragraph:
    col = SEVERITY_COLORS.get(risk.lower(), MID_GREY).hexval()
    return Paragraph(f'<font color="{col}"><b>{html.escape(risk.upper())}</b></font>', sty["cell"])


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
    canvas.drawString(2 * cm, 1.2 * cm, "Trend Vision One — OAT Detection Trend Report — Confidential")
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

    sub_data = [[Paragraph("OAT Detection Trend Report", sty["cover_sub"])]]
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
        Paragraph("OAT Detection Overview", sty["section"]),
    ]

    total_detections = data.get("total_detections", 0)
    critical_count   = data.get("critical_count", 0)
    high_count       = data.get("high_count", 0)
    entity_breakdown = data.get("by_entity_type") or {}
    entity_summary   = ", ".join(
        f"{html.escape(str(k))}: {v}" for k, v in list(entity_breakdown.items())[:3]
    ) or "—"

    card_bg_colors = [TV1_NAVY, TV1_RED, colors.HexColor("#E8610A"), colors.HexColor("#1e2d4a")]
    card_labels    = ["Total Detections", "Critical", "High", "Entity Types"]
    card_values    = [str(total_detections), str(critical_count), str(high_count), str(len(entity_breakdown))]

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
    elems.append(Spacer(1, 0.3 * cm))

    if entity_breakdown:
        elems.append(Paragraph(
            f"Entity Type Breakdown: <b>{entity_summary}</b>",
            sty["body"],
        ))
    elems.append(Spacer(1, 0.2 * cm))
    return elems


# ── Detections by Day ─────────────────────────────────────────────────────────

def _detections_by_day_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Detections by Day", sty["section"])]

    detections_by_day = data.get("detections_by_day") or []
    recent_days = detections_by_day[-30:] if len(detections_by_day) > 30 else detections_by_day

    rows = [["Date", "Total", "High Risk"]]
    if recent_days:
        for entry in recent_days:
            rows.append([
                Paragraph(_t(entry.get("date", "—"), 20), sty["cell"]),
                Paragraph(str(entry.get("total", 0)), sty["cell"]),
                Paragraph(str(entry.get("high_risk", 0)), sty["cell"]),
            ])
    else:
        rows.append([
            Paragraph("N/A", sty["cell"]),
            Paragraph("0", sty["cell"]),
            Paragraph("0", sty["cell"]),
        ])

    col_widths = [CONTENT_W * 0.40, CONTENT_W * 0.30, CONTENT_W * 0.30]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(3)))
    elems.append(tbl)
    return elems


# ── Top Attack Techniques ─────────────────────────────────────────────────────

def _top_techniques_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Top Attack Techniques", sty["section"])]

    techniques = data.get("top_techniques") or []

    rows = [["Technique ID", "Count", "Risk Level"]]
    if techniques:
        for tech in techniques:
            rows.append([
                Paragraph(_t(tech.get("technique_id", "—"), 30), sty["cell"]),
                Paragraph(str(tech.get("count", 0)), sty["cell"]),
                _risk_badge(str(tech.get("risk_level", "unknown")), sty),
            ])
    else:
        rows.append([
            Paragraph("N/A", sty["cell"]),
            Paragraph("0", sty["cell"]),
            Paragraph("—", sty["cell"]),
        ])

    col_widths = [CONTENT_W * 0.45, CONTENT_W * 0.20, CONTENT_W * 0.35]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(3)))
    elems.append(tbl)
    return elems


# ── Top OAT Filters ───────────────────────────────────────────────────────────

def _top_filter_names_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Top OAT Filters", sty["section"])]

    filters = data.get("top_filter_names") or []

    rows = [["Filter Name", "Count", "Risk Level"]]
    if filters:
        for f in filters:
            rows.append([
                Paragraph(_t(f.get("filter_name", "—"), 50), sty["cell"]),
                Paragraph(str(f.get("count", 0)), sty["cell"]),
                _risk_badge(str(f.get("risk_level", "unknown")), sty),
            ])
    else:
        rows.append([
            Paragraph("N/A", sty["cell"]),
            Paragraph("0", sty["cell"]),
            Paragraph("—", sty["cell"]),
        ])

    col_widths = [CONTENT_W * 0.55, CONTENT_W * 0.15, CONTENT_W * 0.30]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(3)))
    elems.append(tbl)
    return elems


# ── Most Targeted Entities ────────────────────────────────────────────────────

def _most_targeted_entities_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Most Targeted Entities", sty["section"])]

    entities = data.get("most_targeted_entities") or []

    rows = [["Entity Name", "Type", "Detection Count"]]
    if entities:
        for ent in entities:
            rows.append([
                Paragraph(_t(ent.get("entity_name", "—"), 40), sty["cell"]),
                Paragraph(_t(ent.get("type", "—"), 20), sty["cell"]),
                Paragraph(str(ent.get("detection_count", 0)), sty["cell"]),
            ])
    else:
        rows.append([
            Paragraph("N/A", sty["cell"]),
            Paragraph("—", sty["cell"]),
            Paragraph("0", sty["cell"]),
        ])

    col_widths = [CONTENT_W * 0.50, CONTENT_W * 0.25, CONTENT_W * 0.25]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(3)))
    elems.append(tbl)
    return elems


# ── Public entry point ────────────────────────────────────────────────────────

def generate_oat_trend_report(
    data: dict,
    customer_name: str = "Customer",
    period_days: int = 30,
    output_path: str | None = None,
) -> str:
    """
    Build and save the OAT Detection Trend PDF report.

    Args:
        data:          Dict containing OAT detection metrics.
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
        output_path = str(Path(output_dir) / f"oat_trend_{ts}.pdf")

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sty = _styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2.5 * cm,
        title=f"OAT Detection Trend Report — {customer_name}",
        author="Trend Vision One Reporter",
    )

    story: list = []
    story += _cover(sty, customer_name, period_days, generated_at)
    story += _stat_cards(sty, data)
    story += _detections_by_day_section(sty, data)
    story += [PageBreak()]
    story += _top_techniques_section(sty, data)
    story += _top_filter_names_section(sty, data)
    story += [PageBreak()]
    story += _most_targeted_entities_section(sty, data)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return os.path.abspath(output_path)
