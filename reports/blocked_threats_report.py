"""
Blocked Threats & IoCs PDF Report Generator for Trend Vision One.

Documents all active suspicious objects (IoCs) currently blocked by the platform,
highlighting those expiring soon and providing a full inventory table.
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
LIGHT_AMBER = colors.HexColor("#FFF8E1")
DEEP_AMBER  = colors.HexColor("#FFE082")
LIGHT_RED  = colors.HexColor("#FDECEA")
WHITE      = colors.white

RISK_COLORS = {
    "critical": colors.HexColor("#D71920"),
    "high":     colors.HexColor("#E8610A"),
    "medium":   colors.HexColor("#D4A017"),
    "low":      colors.HexColor("#2E7D32"),
    "info":     colors.HexColor("#1565C0"),
    "unknown":  MID_GREY,
}

TYPE_LABELS = {
    "url":       "URL",
    "domain":    "Domain",
    "ip":        "IP Address",
    "filehash":  "File Hash",
    "file_hash": "File Hash",
    "hash":      "File Hash",
    "email":     "Email Address",
    "unknown":   "Unknown",
}

PAGE_W, PAGE_H = A4
CONTENT_W = PAGE_W - 4 * cm


# ── Styles ────────────────────────────────────────────────────────────────────

def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "BTCoverTitle", parent=base["Title"],
            fontSize=24, textColor=WHITE, alignment=TA_CENTER, spaceAfter=4,
        ),
        "cover_sub": ParagraphStyle(
            "BTCoverSub", parent=base["Normal"],
            fontSize=12, textColor=colors.HexColor("#BBCCDD"),
            alignment=TA_CENTER, spaceAfter=2,
        ),
        "section": ParagraphStyle(
            "BTSection", parent=base["Heading1"],
            fontSize=13, textColor=TV1_RED, spaceBefore=14, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "BTBody", parent=base["Normal"],
            fontSize=9, textColor=colors.HexColor("#2C2C2C"), leading=13,
        ),
        "note": ParagraphStyle(
            "BTNote", parent=base["Normal"],
            fontSize=8.5, textColor=colors.HexColor("#2C2C2C"), leading=13,
            backColor=colors.HexColor("#EEF2FA"), borderPad=6,
        ),
        "small": ParagraphStyle(
            "BTSmall", parent=base["Normal"],
            fontSize=7.5, textColor=MID_GREY, leading=11,
        ),
        "cell": ParagraphStyle(
            "BTCell", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#2C2C2C"),
            leading=11, wordWrap="CJK",
        ),
        "caption": ParagraphStyle(
            "BTCaption", parent=base["Normal"],
            fontSize=8, textColor=MID_GREY, alignment=TA_CENTER,
        ),
        "stat_value": ParagraphStyle(
            "BTStatValue", parent=base["Normal"],
            fontSize=20, textColor=WHITE, alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        ),
        "stat_label": ParagraphStyle(
            "BTStatLabel", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#DDDDDD"), alignment=TA_CENTER,
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
    canvas.drawString(2 * cm, 1.2 * cm, "Trend Vision One — Blocked Threats & IoCs Report — Confidential")
    canvas.drawRightString(PAGE_W - 2 * cm, 1.2 * cm, f"Page {doc.page}")
    canvas.restoreState()


# ── Cover ─────────────────────────────────────────────────────────────────────

def _cover(sty: dict, customer_name: str, generated_at: str) -> list:
    elems = []
    header_data = [[Paragraph("Trend Vision One", sty["cover_title"])]]
    header_tbl = Table(header_data, colWidths=[CONTENT_W])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), TV1_NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 36),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elems.append(header_tbl)

    sub_data = [[Paragraph("Blocked Threats &amp; IoCs Report", sty["cover_sub"])]]
    sub_tbl = Table(sub_data, colWidths=[CONTENT_W])
    sub_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), TV1_RED),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    elems.append(sub_tbl)
    elems.append(Spacer(1, 0.5 * cm))
    elems.append(Paragraph(f"Customer: <b>{customer_name}</b>", sty["body"]))
    elems.append(Paragraph(f"Generated: {generated_at}", sty["caption"]))
    elems.append(Spacer(1, 0.5 * cm))
    elems.append(HRFlowable(width="100%", thickness=1, color=TV1_RED))
    return elems


# ── Summary stat cards ────────────────────────────────────────────────────────

def _summary_stats(sty: dict, data: dict) -> list:
    elems = [
        PageBreak(),
        Paragraph("Blocked Threats Summary", sty["section"]),
    ]

    total = data.get("total", 0)
    by_type = data.get("by_type") or {}
    by_risk = data.get("by_risk") or {}
    expiring = data.get("expiring_soon") or []

    card_bg = [TV1_NAVY, TV1_RED, colors.HexColor("#E8610A"), colors.HexColor("#D4A017")]
    labels = ["Total Blocked IoCs", "Expiring Within 30d", "High/Critical Risk", "In Exception List"]
    high_crit = (by_risk.get("high", 0) + by_risk.get("critical", 0))
    in_exc = sum(
        1 for obj in (data.get("suspicious_objects") or [])
        if obj.get("in_exception_list")
    )
    values = [str(total), str(len(expiring)), str(high_crit), str(in_exc)]

    cards_row = [[
        Table(
            [[Paragraph(values[i], sty["stat_value"])],
             [Paragraph(labels[i], sty["stat_label"])]],
            colWidths=[(CONTENT_W / 4) - 0.2 * cm],
            style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), card_bg[i]),
                ("TOPPADDING",    (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]),
        )
        for i in range(4)
    ]]

    outer = Table(cards_row, colWidths=[(CONTENT_W / 4)] * 4)
    outer.setStyle(TableStyle([
        ("LEFTPADDING",  (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(outer)
    elems.append(Spacer(1, 0.4 * cm))

    # By-type breakdown
    elems.append(Paragraph("Breakdown by Type", sty["section"]))
    type_rows = [["IoC Type", "Count"]]
    for ioc_type, cnt in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
        label = TYPE_LABELS.get(ioc_type.lower(), ioc_type.upper())
        type_rows.append([
            Paragraph(label, sty["cell"]),
            Paragraph(str(cnt), sty["cell"]),
        ])
    if not by_type:
        type_rows.append([Paragraph("No data", sty["cell"]), Paragraph("0", sty["cell"])])

    risk_rows = [["Risk Level", "Count"]]
    for risk, cnt in sorted(by_risk.items(), key=lambda x: x[1], reverse=True):
        risk_rows.append([
            _risk_badge(risk, sty),
            Paragraph(str(cnt), sty["cell"]),
        ])
    if not by_risk:
        risk_rows.append([Paragraph("No data", sty["cell"]), Paragraph("0", sty["cell"])])

    type_tbl = Table(type_rows, colWidths=[4 * cm, 3 * cm], repeatRows=1)
    type_tbl.setStyle(TableStyle(_table_style(2)))

    risk_tbl = Table(risk_rows, colWidths=[4 * cm, 3 * cm], repeatRows=1)
    risk_tbl.setStyle(TableStyle(_table_style(2)))

    combined = Table([[type_tbl, risk_tbl]], colWidths=[CONTENT_W * 0.5, CONTENT_W * 0.5])
    combined.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, 0), 6),
    ]))
    elems.append(combined)
    return elems


# ── Expiring soon table ───────────────────────────────────────────────────────

def _expiring_soon_table(sty: dict, data: dict) -> list:
    elems = [Paragraph("Expiring Soon — Action Required", sty["section"])]

    expiring = data.get("expiring_soon") or []
    if not expiring:
        elems.append(Paragraph(
            "No IoCs are expiring within the next 30 days.", sty["body"]
        ))
        return elems

    critical_count = sum(1 for obj in expiring if obj.get("critical_expiry"))
    elems.append(Paragraph(
        f"<b>{len(expiring)}</b> IoCs expire within 30 days. "
        f"<b>{critical_count}</b> expire within 7 days and are highlighted in orange.",
        sty["body"],
    ))
    elems.append(Spacer(1, 0.2 * cm))

    rows = [["Type", "Value", "Risk Level", "Scan Action", "Expires"]]
    style_cmds = list(_table_style(5))

    for row_idx, obj in enumerate(expiring, 1):
        if obj.get("critical_expiry"):
            style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), DEEP_AMBER))
        rows.append([
            Paragraph(TYPE_LABELS.get(obj.get("type", "").lower(), (obj.get("type") or "—").upper()), sty["cell"]),
            Paragraph(_t(obj.get("value", "—"), 32), sty["cell"]),
            _risk_badge(obj.get("risk_level", "unknown"), sty),
            Paragraph(_t(obj.get("scan_action", "—"), 15), sty["cell"]),
            Paragraph(_t(obj.get("expires", "—"), 19), sty["cell"]),
        ])

    tbl = Table(
        rows,
        colWidths=[2.5 * cm, 6 * cm, 2.2 * cm, 2.5 * cm, CONTENT_W - 13.2 * cm],
        repeatRows=1,
    )
    tbl.setStyle(TableStyle(style_cmds))
    elems.append(tbl)
    return elems


# ── Full IoC inventory ────────────────────────────────────────────────────────

def _full_ioc_table(sty: dict, data: dict) -> list:
    elems = [
        PageBreak(),
        Paragraph("Full Blocked IoC Inventory", sty["section"]),
    ]

    objects = data.get("suspicious_objects") or []
    if not objects:
        elems.append(Paragraph("No suspicious objects found.", sty["body"]))
        return elems

    elems.append(Paragraph(
        f"Total of <b>{len(objects)}</b> suspicious objects are currently tracked and blocked.",
        sty["body"],
    ))
    elems.append(Spacer(1, 0.2 * cm))

    # Sort by risk level (critical first), then by type
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    sorted_objects = sorted(
        objects,
        key=lambda x: (risk_order.get(x.get("risk_level", "unknown").lower(), 5), x.get("type", "")),
    )

    rows = [["Type", "Value", "Risk", "Scan Action", "In Exception", "Expiry"]]
    for obj in sorted_objects:
        type_label = TYPE_LABELS.get(obj.get("type", "").lower(), (obj.get("type") or "—").upper())
        in_exc = "Yes" if obj.get("in_exception_list") else "No"
        rows.append([
            Paragraph(type_label, sty["cell"]),
            Paragraph(_t(obj.get("value", "—"), 32), sty["cell"]),
            _risk_badge(obj.get("risk_level", "unknown"), sty),
            Paragraph(_t(obj.get("scan_action", "—"), 12), sty["cell"]),
            Paragraph(in_exc, sty["cell"]),
            Paragraph(_t(obj.get("expires", "—"), 19), sty["cell"]),
        ])

    tbl = Table(
        rows,
        colWidths=[2.2 * cm, 6 * cm, 1.8 * cm, 2 * cm, 1.8 * cm, CONTENT_W - 13.8 * cm],
        repeatRows=1,
    )
    tbl.setStyle(TableStyle(_table_style(6)))
    elems.append(tbl)
    return elems


# ── Note section ──────────────────────────────────────────────────────────────

def _note_section(sty: dict) -> list:
    elems = [Paragraph("Important Notes", sty["section"])]
    elems.append(Paragraph(
        "These objects are actively blocked by Trend Vision One across all connected sensors and endpoints. "
        "Any matching URLs, domains, IP addresses, or file hashes encountered during scanning will be "
        "automatically blocked or flagged according to the configured scan action. "
        "Objects with a scan action of 'Block' will prevent access entirely, while 'Log' objects "
        "will generate a detection event without blocking. "
        "Objects in the exception list are excluded from scanning and will not trigger detections. "
        "Review exception-listed objects periodically to ensure they remain appropriate. "
        "Expiring objects should be renewed before expiry to maintain continuous threat coverage.",
        sty["note"],
    ))
    return elems


# ── Public entry point ────────────────────────────────────────────────────────

def generate_blocked_threats_report(
    data: dict,
    customer_name: str = "Customer",
    output_path: str | None = None,
) -> str:
    """
    Build and save the Blocked Threats & IoCs PDF report.

    Args:
        data:          Dict returned by collect_blocked_threats().
        customer_name: Customer name for the cover page.
        output_path:   File path to write. Auto-generated if None.

    Returns:
        Absolute path to the written PDF.
    """
    output_dir = os.getenv("REPORT_OUTPUT_DIR", "./output")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    if output_path is None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = str(Path(output_dir) / f"blocked_threats_{ts}.pdf")

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sty = _styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2.5 * cm,
        title=f"Blocked Threats & IoCs — {customer_name}",
        author="Trend Vision One Reporter",
    )

    story: list = []
    story += _cover(sty, customer_name, generated_at)
    story += _summary_stats(sty, data)
    story += _expiring_soon_table(sty, data)
    story += _full_ioc_table(sty, data)
    story += _note_section(sty)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return os.path.abspath(output_path)
