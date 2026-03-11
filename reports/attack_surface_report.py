"""
Attack Surface Posture PDF Report Generator for Trend Vision One.

Produces a posture score overview, risk by category, assessment results,
critical findings, and top recommendations.
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
            "ASCoverTitle", parent=base["Title"],
            fontSize=26, textColor=WHITE, alignment=TA_CENTER, spaceAfter=4,
        ),
        "cover_sub": ParagraphStyle(
            "ASCoverSub", parent=base["Normal"],
            fontSize=13, textColor=colors.HexColor("#BBCCDD"),
            alignment=TA_CENTER, spaceAfter=2,
        ),
        "cover_customer": ParagraphStyle(
            "ASCoverCustomer", parent=base["Normal"],
            fontSize=15, textColor=WHITE,
            alignment=TA_CENTER, spaceAfter=2, fontName="Helvetica-Bold",
        ),
        "section": ParagraphStyle(
            "ASSection", parent=base["Heading1"],
            fontSize=13, textColor=TV1_RED, spaceBefore=14, spaceAfter=6,
        ),
        "subsection": ParagraphStyle(
            "ASSubSection", parent=base["Heading2"],
            fontSize=11, textColor=TV1_NAVY, spaceBefore=8, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "ASBody", parent=base["Normal"],
            fontSize=9, textColor=colors.HexColor("#2C2C2C"), leading=13,
        ),
        "small": ParagraphStyle(
            "ASSmall", parent=base["Normal"],
            fontSize=7.5, textColor=MID_GREY, leading=11,
        ),
        "cell": ParagraphStyle(
            "ASCell", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#2C2C2C"),
            leading=11, wordWrap="CJK",
        ),
        "caption": ParagraphStyle(
            "ASCaption", parent=base["Normal"],
            fontSize=8, textColor=MID_GREY, alignment=TA_CENTER,
        ),
        "stat_value": ParagraphStyle(
            "ASStatValue", parent=base["Normal"],
            fontSize=22, textColor=WHITE, alignment=TA_CENTER,
            fontName="Helvetica-Bold", spaceAfter=2,
        ),
        "stat_label": ParagraphStyle(
            "ASStatLabel", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#DDDDDD"),
            alignment=TA_CENTER, leading=10,
        ),
        "score_big": ParagraphStyle(
            "ASScoreBig", parent=base["Normal"],
            fontSize=52, textColor=WHITE, alignment=TA_CENTER,
            fontName="Helvetica-Bold", spaceAfter=4,
        ),
        "score_grade": ParagraphStyle(
            "ASScoreGrade", parent=base["Normal"],
            fontSize=28, textColor=WHITE, alignment=TA_CENTER,
            fontName="Helvetica-Bold", spaceAfter=2,
        ),
        "score_label": ParagraphStyle(
            "ASScoreLabel", parent=base["Normal"],
            fontSize=10, textColor=colors.HexColor("#DDDDDD"),
            alignment=TA_CENTER, leading=12,
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


def _grade_from_score(score: float) -> tuple[str, colors.HexColor]:
    """Return (letter_grade, colour) based on posture score."""
    if score >= 90:
        return "A", colors.HexColor("#2E7D32")
    elif score >= 75:
        return "B", colors.HexColor("#558B2F")
    elif score >= 60:
        return "C", colors.HexColor("#D4A017")
    elif score >= 45:
        return "D", colors.HexColor("#E8610A")
    else:
        return "F", colors.HexColor("#D71920")


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
    canvas.drawString(2 * cm, 1.2 * cm, "Trend Vision One — Attack Surface Posture Report — Confidential")
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

    sub_data = [[Paragraph("Attack Surface Posture Report", sty["cover_sub"])]]
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


# ── Posture Score Display ─────────────────────────────────────────────────────

def _posture_score_section(sty: dict, data: dict) -> list:
    elems = [
        PageBreak(),
        Paragraph("Overall Security Posture Score", sty["section"]),
    ]

    overall_score = data.get("overall_score", 0)
    try:
        score_num = float(overall_score)
    except (TypeError, ValueError):
        score_num = 0.0

    grade, grade_color = _grade_from_score(score_num)
    grade_hex = grade_color.hexval()

    score_display_data = [
        [
            Paragraph(str(int(score_num)), sty["score_big"]),
        ],
        [
            Paragraph(
                f'Grade: <font color="{grade_hex}"><b>{grade}</b></font>',
                sty["score_grade"],
            ),
        ],
        [
            Paragraph("Overall Posture Score (0–100)", sty["score_label"]),
        ],
    ]

    score_tbl = Table(score_display_data, colWidths=[CONTENT_W])
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), TV1_NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 18),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elems.append(score_tbl)
    elems.append(Spacer(1, 0.4 * cm))
    return elems


# ── Risk by Category ──────────────────────────────────────────────────────────

def _risk_by_category_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Risk by Category", sty["section"])]

    by_risk_category = data.get("by_risk_category") or []

    rows = [["Category", "Score", "Risk Level"]]
    if by_risk_category:
        for entry in by_risk_category:
            rows.append([
                Paragraph(_t(entry.get("category", "—"), 40), sty["cell"]),
                Paragraph(str(entry.get("score", "—")), sty["cell"]),
                _risk_badge(str(entry.get("risk_level", "unknown")), sty),
            ])
    else:
        rows.append([
            Paragraph("N/A", sty["cell"]),
            Paragraph("—", sty["cell"]),
            Paragraph("—", sty["cell"]),
        ])

    col_widths = [CONTENT_W * 0.50, CONTENT_W * 0.20, CONTENT_W * 0.30]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(3)))
    elems.append(tbl)
    return elems


# ── Assessment Results stat cards ─────────────────────────────────────────────

def _assessment_results_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Assessment Results", sty["section"])]

    total_checks  = data.get("total_checks", 0)
    passed_checks = data.get("passed_checks", 0)
    failed_checks = data.get("failed_checks", 0)

    card_bg_colors = [TV1_NAVY, colors.HexColor("#2E7D32"), TV1_RED]
    card_labels    = ["Total Checks", "Passed", "Failed"]
    card_values    = [str(total_checks), str(passed_checks), str(failed_checks)]

    cards_row = [[
        Table(
            [[Paragraph(card_values[i], sty["stat_value"])],
             [Paragraph(card_labels[i], sty["stat_label"])]],
            colWidths=[(CONTENT_W / 3) - 0.2 * cm],
            style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), card_bg_colors[i]),
                ("TOPPADDING",    (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]),
        )
        for i in range(3)
    ]]

    outer_tbl = Table(cards_row, colWidths=[(CONTENT_W / 3)] * 3)
    outer_tbl.setStyle(TableStyle([
        ("LEFTPADDING",  (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(outer_tbl)
    elems.append(Spacer(1, 0.4 * cm))
    return elems


# ── Critical Findings ─────────────────────────────────────────────────────────

def _critical_findings_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Critical Findings", sty["section"])]

    findings = data.get("critical_findings") or []

    rows = [["Title", "Category", "Impact", "Recommendation"]]
    if findings:
        for finding in findings[:10]:
            rows.append([
                Paragraph(_t(finding.get("title", "—"), 28), sty["cell"]),
                Paragraph(_t(finding.get("category", "—"), 18), sty["cell"]),
                Paragraph(_t(finding.get("impact", "—"), 25), sty["cell"]),
                Paragraph(_t(finding.get("recommendation", "—"), 35), sty["cell"]),
            ])
    else:
        rows.append([
            Paragraph("N/A", sty["cell"]),
            Paragraph("—", sty["cell"]),
            Paragraph("—", sty["cell"]),
            Paragraph("—", sty["cell"]),
        ])

    col_widths = [
        CONTENT_W * 0.26,
        CONTENT_W * 0.18,
        CONTENT_W * 0.22,
        CONTENT_W * 0.34,
    ]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(4)))
    elems.append(tbl)
    return elems


# ── Top Recommendations ───────────────────────────────────────────────────────

def _top_recommendations_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Top Recommendations", sty["section"])]

    recommendations = data.get("top_recommendations") or []

    if recommendations:
        for idx, rec in enumerate(recommendations, 1):
            rec_text = _t(rec, 200) if isinstance(rec, str) else _t(rec.get("recommendation", "—"), 200)
            elems.append(Paragraph(f"{idx}. {rec_text}", sty["body"]))
            elems.append(Spacer(1, 0.15 * cm))
    else:
        elems.append(Paragraph("No recommendations available.", sty["body"]))

    return elems


# ── Public entry point ────────────────────────────────────────────────────────

def generate_attack_surface_report(
    data: dict,
    customer_name: str = "Customer",
    period_days: int = 30,
    output_path: str | None = None,
) -> str:
    """
    Build and save the Attack Surface Posture PDF report.

    Args:
        data:          Dict containing attack surface posture metrics.
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
        output_path = str(Path(output_dir) / f"attack_surface_{ts}.pdf")

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sty = _styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2.5 * cm,
        title=f"Attack Surface Posture Report — {customer_name}",
        author="Trend Vision One Reporter",
    )

    story: list = []
    story += _cover(sty, customer_name, period_days, generated_at)
    story += _posture_score_section(sty, data)
    story += _risk_by_category_section(sty, data)
    story += _assessment_results_section(sty, data)
    story += [PageBreak()]
    story += _critical_findings_section(sty, data)
    story += [PageBreak()]
    story += _top_recommendations_section(sty, data)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return os.path.abspath(output_path)
