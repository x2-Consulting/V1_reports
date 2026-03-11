"""
Risk Index PDF Report Generator for Trend Vision One.

Produces a detailed overview of asset risk scores, risk distribution,
top risk assets, and risk by component type.
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
            "RICoverTitle", parent=base["Title"],
            fontSize=26, textColor=WHITE, alignment=TA_CENTER, spaceAfter=4,
        ),
        "cover_sub": ParagraphStyle(
            "RICoverSub", parent=base["Normal"],
            fontSize=13, textColor=colors.HexColor("#BBCCDD"),
            alignment=TA_CENTER, spaceAfter=2,
        ),
        "cover_customer": ParagraphStyle(
            "RICoverCustomer", parent=base["Normal"],
            fontSize=15, textColor=WHITE,
            alignment=TA_CENTER, spaceAfter=2, fontName="Helvetica-Bold",
        ),
        "section": ParagraphStyle(
            "RISection", parent=base["Heading1"],
            fontSize=13, textColor=TV1_RED, spaceBefore=14, spaceAfter=6,
        ),
        "subsection": ParagraphStyle(
            "RISubSection", parent=base["Heading2"],
            fontSize=11, textColor=TV1_NAVY, spaceBefore=8, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "RIBody", parent=base["Normal"],
            fontSize=9, textColor=colors.HexColor("#2C2C2C"), leading=13,
        ),
        "small": ParagraphStyle(
            "RISmall", parent=base["Normal"],
            fontSize=7.5, textColor=MID_GREY, leading=11,
        ),
        "cell": ParagraphStyle(
            "RICell", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#2C2C2C"),
            leading=11, wordWrap="CJK",
        ),
        "caption": ParagraphStyle(
            "RICaption", parent=base["Normal"],
            fontSize=8, textColor=MID_GREY, alignment=TA_CENTER,
        ),
        "stat_value": ParagraphStyle(
            "RIStatValue", parent=base["Normal"],
            fontSize=22, textColor=WHITE, alignment=TA_CENTER,
            fontName="Helvetica-Bold", spaceAfter=2,
        ),
        "stat_label": ParagraphStyle(
            "RIStatLabel", parent=base["Normal"],
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
    canvas.drawString(2 * cm, 1.2 * cm, "Trend Vision One — Risk Index Report — Confidential")
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

    sub_data = [[Paragraph("Risk Index Report", sty["cover_sub"])]]
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
        Paragraph("Risk Index Overview", sty["section"]),
    ]

    total_assets   = data.get("total_assets", 0)
    avg_risk_score = data.get("avg_risk_score", 0.0)
    risk_dist      = data.get("risk_distribution") or {}
    critical_assets = risk_dist.get("critical", 0)
    high_risk_assets = risk_dist.get("high", 0)

    card_bg_colors = [TV1_NAVY, colors.HexColor("#1565C0"), TV1_RED, colors.HexColor("#E8610A")]
    card_labels    = ["Total Assets", "Avg Risk Score", "Critical Assets", "High Risk Assets"]
    card_values    = [str(total_assets), str(avg_risk_score), str(critical_assets), str(high_risk_assets)]

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


# ── Risk Distribution ─────────────────────────────────────────────────────────

def _risk_distribution_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Risk Distribution", sty["section"])]

    risk_dist = data.get("risk_distribution") or {}

    rows = [["Level", "Count"]]
    if risk_dist:
        for level, count in sorted(risk_dist.items(), key=lambda x: x[1], reverse=True):
            rows.append([
                _risk_badge(level, sty),
                Paragraph(str(count), sty["cell"]),
            ])
    else:
        rows.append([Paragraph("N/A", sty["cell"]), Paragraph("0", sty["cell"])])

    tbl = Table(rows, colWidths=[CONTENT_W - 4 * cm, 4 * cm], repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(2)))
    elems.append(tbl)
    return elems


# ── Assets by Type ────────────────────────────────────────────────────────────

def _assets_by_type_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Assets by Type", sty["section"])]

    by_asset_type = data.get("by_asset_type") or {}

    rows = [["Type", "Count"]]
    if by_asset_type:
        for asset_type, count in sorted(by_asset_type.items(), key=lambda x: x[1], reverse=True):
            rows.append([
                Paragraph(_t(asset_type, 50), sty["cell"]),
                Paragraph(str(count), sty["cell"]),
            ])
    else:
        rows.append([Paragraph("N/A", sty["cell"]), Paragraph("0", sty["cell"])])

    tbl = Table(rows, colWidths=[CONTENT_W - 4 * cm, 4 * cm], repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(2)))
    elems.append(tbl)
    return elems


# ── Top Risk Assets ───────────────────────────────────────────────────────────

def _top_risk_assets_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Top Risk Assets", sty["section"])]

    top_assets = data.get("top_risk_assets") or []

    rows = [["Asset Name", "Type", "Score", "Risk Level", "Top Risk Component"]]
    if top_assets:
        for asset in top_assets[:20]:
            rows.append([
                Paragraph(_t(asset.get("asset_name", "—"), 25), sty["cell"]),
                Paragraph(_t(asset.get("type", "—"), 15), sty["cell"]),
                Paragraph(str(asset.get("score", "—")), sty["cell"]),
                _risk_badge(str(asset.get("risk_level", "unknown")), sty),
                Paragraph(_t(asset.get("top_risk_component", "—"), 30), sty["cell"]),
            ])
    else:
        rows.append([
            Paragraph("N/A", sty["cell"]),
            Paragraph("—", sty["cell"]),
            Paragraph("—", sty["cell"]),
            Paragraph("—", sty["cell"]),
            Paragraph("—", sty["cell"]),
        ])

    col_widths = [
        CONTENT_W * 0.26,
        CONTENT_W * 0.14,
        CONTENT_W * 0.10,
        CONTENT_W * 0.16,
        CONTENT_W * 0.34,
    ]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(5)))
    elems.append(tbl)
    return elems


# ── Risk by Component Type ────────────────────────────────────────────────────

def _risk_by_component_type_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Risk by Component Type", sty["section"])]

    by_component = data.get("risk_by_component_type") or {}

    rows = [["Component Type", "Avg Score"]]
    if by_component:
        for comp_type, avg_score in sorted(by_component.items(), key=lambda x: x[1], reverse=True):
            rows.append([
                Paragraph(_t(comp_type, 50), sty["cell"]),
                Paragraph(str(avg_score), sty["cell"]),
            ])
    else:
        rows.append([Paragraph("N/A", sty["cell"]), Paragraph("0", sty["cell"])])

    tbl = Table(rows, colWidths=[CONTENT_W - 4 * cm, 4 * cm], repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(2)))
    elems.append(tbl)
    return elems


# ── Public entry point ────────────────────────────────────────────────────────

def generate_risk_index_report(
    data: dict,
    customer_name: str = "Customer",
    period_days: int = 30,
    output_path: str | None = None,
) -> str:
    """
    Build and save the Risk Index PDF report.

    Args:
        data:          Dict containing risk index metrics.
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
        output_path = str(Path(output_dir) / f"risk_index_{ts}.pdf")

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sty = _styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2.5 * cm,
        title=f"Risk Index Report — {customer_name}",
        author="Trend Vision One Reporter",
    )

    story: list = []
    story += _cover(sty, customer_name, period_days, generated_at)
    story += _stat_cards(sty, data)
    story += _risk_distribution_section(sty, data)
    story += _assets_by_type_section(sty, data)
    story += [PageBreak()]
    story += _top_risk_assets_section(sty, data)
    story += [PageBreak()]
    story += _risk_by_component_type_section(sty, data)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return os.path.abspath(output_path)
