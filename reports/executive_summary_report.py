"""
Executive Summary PDF Report Generator for Trend Vision One.

Produces a high-level management overview covering alerts, OAT detections,
IoCs, impacted assets, and trend data.
"""

from __future__ import annotations

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

RISK_COLORS = {
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
            "ExecCoverTitle", parent=base["Title"],
            fontSize=26, textColor=WHITE, alignment=TA_CENTER, spaceAfter=4,
        ),
        "cover_sub": ParagraphStyle(
            "ExecCoverSub", parent=base["Normal"],
            fontSize=13, textColor=colors.HexColor("#BBCCDD"),
            alignment=TA_CENTER, spaceAfter=2,
        ),
        "cover_customer": ParagraphStyle(
            "ExecCoverCustomer", parent=base["Normal"],
            fontSize=15, textColor=WHITE,
            alignment=TA_CENTER, spaceAfter=2, fontName="Helvetica-Bold",
        ),
        "section": ParagraphStyle(
            "ExecSection", parent=base["Heading1"],
            fontSize=13, textColor=TV1_RED, spaceBefore=14, spaceAfter=6,
        ),
        "subsection": ParagraphStyle(
            "ExecSubSection", parent=base["Heading2"],
            fontSize=11, textColor=TV1_NAVY, spaceBefore=8, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "ExecBody", parent=base["Normal"],
            fontSize=9, textColor=colors.HexColor("#2C2C2C"), leading=13,
        ),
        "small": ParagraphStyle(
            "ExecSmall", parent=base["Normal"],
            fontSize=7.5, textColor=MID_GREY, leading=11,
        ),
        "cell": ParagraphStyle(
            "ExecCell", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#2C2C2C"),
            leading=11, wordWrap="CJK",
        ),
        "caption": ParagraphStyle(
            "ExecCaption", parent=base["Normal"],
            fontSize=8, textColor=MID_GREY, alignment=TA_CENTER,
        ),
        "stat_value": ParagraphStyle(
            "ExecStatValue", parent=base["Normal"],
            fontSize=22, textColor=WHITE, alignment=TA_CENTER,
            fontName="Helvetica-Bold", spaceAfter=2,
        ),
        "stat_label": ParagraphStyle(
            "ExecStatLabel", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#DDDDDD"),
            alignment=TA_CENTER, leading=10,
        ),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _t(value: Any, max_len: int = 60) -> str:
    s = str(value) if value is not None else "—"
    return s[:max_len] + "…" if len(s) > max_len else s


def _sev_badge(sev: str, sty: dict) -> Paragraph:
    col = SEVERITY_COLORS.get(sev.lower(), MID_GREY).hexval()
    return Paragraph(f'<font color="{col}"><b>{sev.upper()}</b></font>', sty["cell"])


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
    canvas.drawString(2 * cm, 1.2 * cm, "Trend Vision One — Executive Security Summary — Confidential")
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

    sub_data = [[Paragraph("Executive Security Summary", sty["cover_sub"])]]
    sub_tbl = Table(sub_data, colWidths=[CONTENT_W])
    sub_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), TV1_RED),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    elems.append(sub_tbl)
    elems.append(Spacer(1, 0.8 * cm))

    cust_data = [[Paragraph(customer_name, sty["cover_customer"])]]
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


# ── Key metrics stat cards ────────────────────────────────────────────────────

def _stat_cards(sty: dict, data: dict) -> list:
    elems = [
        PageBreak(),
        Paragraph("Key Security Metrics", sty["section"]),
    ]

    total_alerts = data.get("total_alerts", 0)
    open_unowned = data.get("open_unowned", 0)
    total_oat = data.get("total_oat_detections", 0)
    total_iocs = data.get("total_iocs", 0)

    card_bg_colors = [TV1_RED, TV1_NAVY, colors.HexColor("#E8610A"), colors.HexColor("#2E7D32")]
    card_labels = ["Total Alerts", "Open / Unowned", "OAT Detections", "Blocked IoCs"]
    card_values = [str(total_alerts), str(open_unowned), str(total_oat), str(total_iocs)]

    card_cells = [
        [
            Table(
                [
                    [Paragraph(card_values[i], sty["stat_value"])],
                    [Paragraph(card_labels[i], sty["stat_label"])],
                ],
                colWidths=[(CONTENT_W / 4) - 0.2 * cm],
            )
        ]
        for i in range(4)
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

    # Additional metrics row
    avg_score = data.get("avg_risk_score", 0.0)
    incidents = data.get("incident_count", 0)
    elems.append(Paragraph(
        f"Average Risk Score: <b>{avg_score}</b> &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Distinct Incidents: <b>{incidents}</b>",
        sty["body"],
    ))
    return elems


# ── Alert severity breakdown ──────────────────────────────────────────────────

def _alert_severity_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Alert Severity & Status Breakdown", sty["section"])]

    by_sev = data.get("alerts_by_severity") or {}
    by_status = data.get("alerts_by_status") or {}

    sev_rows = [["Severity", "Count", "% of Total"]]
    total = sum(by_sev.values()) or 1
    for sev in ("critical", "high", "medium", "low", "info", "unknown"):
        cnt = by_sev.get(sev, 0)
        if cnt == 0 and sev == "unknown":
            continue
        pct = f"{cnt / total * 100:.1f}%"
        sev_rows.append([
            _sev_badge(sev, sty),
            Paragraph(str(cnt), sty["cell"]),
            Paragraph(pct, sty["cell"]),
        ])

    sev_tbl = Table(sev_rows, colWidths=[5 * cm, 3 * cm, 3 * cm], repeatRows=1)
    sev_tbl.setStyle(TableStyle(_table_style(3)))

    status_rows = [["Investigation Status", "Count"]]
    for status, cnt in sorted(by_status.items(), key=lambda x: x[1], reverse=True):
        status_rows.append([
            Paragraph(str(status), sty["cell"]),
            Paragraph(str(cnt), sty["cell"]),
        ])

    status_tbl = Table(status_rows, colWidths=[6 * cm, 3 * cm], repeatRows=1)
    status_tbl.setStyle(TableStyle(_table_style(2)))

    combined = Table(
        [[sev_tbl, status_tbl]],
        colWidths=[CONTENT_W * 0.5, CONTENT_W * 0.5],
    )
    combined.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    elems.append(combined)
    return elems


# ── Alert trend by day ────────────────────────────────────────────────────────

def _alert_trend_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Alert Trend by Day", sty["section"])]
    alerts_by_day = data.get("alerts_by_day") or []

    if not alerts_by_day:
        elems.append(Paragraph("No daily trend data available.", sty["body"]))
        return elems

    max_count = max((d["count"] for d in alerts_by_day), default=1)
    bar_width = 30

    rows = [["Date", "Count", "Volume"]]
    for entry in alerts_by_day:
        day = entry.get("date", "")
        count = entry.get("count", 0)
        bar_len = int((count / max_count) * bar_width) if max_count else 0
        bar = "\u2588" * bar_len
        rows.append([
            Paragraph(day, sty["cell"]),
            Paragraph(str(count), sty["cell"]),
            Paragraph(f'<font color="#D71920">{bar}</font>', sty["cell"]),
        ])

    tbl = Table(rows, colWidths=[3 * cm, 2.5 * cm, CONTENT_W - 5.5 * cm], repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(3)))
    elems.append(tbl)
    return elems


# ── Top threat models ─────────────────────────────────────────────────────────

def _top_threat_models_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Top 10 Threat Models", sty["section"])]
    models = data.get("top_threat_models") or []

    if not models:
        elems.append(Paragraph("No threat model data available.", sty["body"]))
        return elems

    rows = [["#", "Model Name", "Detections", "Severity"]]
    for idx, m in enumerate(models[:10], 1):
        rows.append([
            Paragraph(str(idx), sty["cell"]),
            Paragraph(_t(m.get("name", "—"), 55), sty["cell"]),
            Paragraph(str(m.get("count", 0)), sty["cell"]),
            _sev_badge(m.get("severity", "unknown"), sty),
        ])

    tbl = Table(rows, colWidths=[1 * cm, 10 * cm, 2.5 * cm, 2.5 * cm], repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(4)))
    elems.append(tbl)
    return elems


# ── Top OAT behaviours ────────────────────────────────────────────────────────

def _top_oat_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Top 10 OAT Behaviours", sty["section"])]
    behaviours = data.get("top_oat_behaviours") or []

    if not behaviours:
        elems.append(Paragraph("No OAT behaviour data available.", sty["body"]))
        return elems

    rows = [["#", "Behaviour / Filter Name", "Detections", "Risk Level"]]
    for idx, b in enumerate(behaviours[:10], 1):
        rows.append([
            Paragraph(str(idx), sty["cell"]),
            Paragraph(_t(b.get("name", "—"), 55), sty["cell"]),
            Paragraph(str(b.get("count", 0)), sty["cell"]),
            _risk_badge(b.get("risk_level", "unknown"), sty),
        ])

    tbl = Table(rows, colWidths=[1 * cm, 10 * cm, 2.5 * cm, 2.5 * cm], repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(4)))
    elems.append(tbl)
    return elems


# ── Most impacted assets ──────────────────────────────────────────────────────

def _impacted_assets_section(sty: dict, data: dict) -> list:
    elems = [Paragraph("Most Impacted Assets", sty["section"])]

    hosts = data.get("most_impacted_hosts") or []
    accounts = data.get("most_impacted_accounts") or []

    host_rows = [["Hostname", "Alerts", "OAT Hits", "Total"]]
    for h in hosts[:10]:
        host_rows.append([
            Paragraph(_t(h.get("name", "—"), 25), sty["cell"]),
            Paragraph(str(h.get("alert_count", 0)), sty["cell"]),
            Paragraph(str(h.get("oat_count", 0)), sty["cell"]),
            Paragraph(str(h.get("total_hits", 0)), sty["cell"]),
        ])
    if not hosts:
        host_rows.append([Paragraph("No host data", sty["cell"]), Paragraph("", sty["cell"]),
                          Paragraph("", sty["cell"]), Paragraph("", sty["cell"])])

    host_tbl = Table(host_rows, colWidths=[5 * cm, 1.8 * cm, 2 * cm, 1.6 * cm], repeatRows=1)
    host_tbl.setStyle(TableStyle(_table_style(4)))

    acc_rows = [["Account", "Alert Count"]]
    for a in accounts[:5]:
        acc_rows.append([
            Paragraph(_t(a.get("name", "—"), 30), sty["cell"]),
            Paragraph(str(a.get("count", 0)), sty["cell"]),
        ])
    if not accounts:
        acc_rows.append([Paragraph("No account data", sty["cell"]), Paragraph("", sty["cell"])])

    acc_tbl = Table(acc_rows, colWidths=[5 * cm, 2.5 * cm], repeatRows=1)
    acc_tbl.setStyle(TableStyle(_table_style(2)))

    elems.append(Paragraph("Most Targeted Hosts", sty["subsection"]))
    elems.append(host_tbl)
    elems.append(Spacer(1, 0.3 * cm))
    elems.append(Paragraph("Most Targeted Accounts", sty["subsection"]))
    elems.append(acc_tbl)
    return elems


# ── Summary paragraph ─────────────────────────────────────────────────────────

def _summary_paragraph(sty: dict, data: dict, customer_name: str, period_days: int) -> list:
    elems = [Paragraph("Period Summary", sty["section"])]

    total_alerts = data.get("total_alerts", 0)
    total_oat = data.get("total_oat_detections", 0)
    total_iocs = data.get("total_iocs", 0)
    total_hosts = len(data.get("most_impacted_hosts") or [])
    incidents = data.get("incident_count", 0)
    open_unowned = data.get("open_unowned", 0)
    avg_score = data.get("avg_risk_score", 0.0)

    sev = data.get("alerts_by_severity") or {}
    critical_cnt = sev.get("critical", 0)
    high_cnt = sev.get("high", 0)

    para = (
        f"During this {period_days}-day reporting period, <b>{total_alerts}</b> workbench alerts "
        f"were detected across <b>{total_hosts}</b> endpoints for <b>{customer_name}</b>. "
        f"Of these, <b>{critical_cnt}</b> were classified as Critical and <b>{high_cnt}</b> as High severity, "
        f"with an average risk score of <b>{avg_score}</b>. "
        f"In addition, <b>{total_oat}</b> Object-Based Advanced Threat (OAT) detections were observed, "
        f"and <b>{total_iocs}</b> suspicious objects are currently tracked as Indicators of Compromise. "
        f"A total of <b>{incidents}</b> distinct incidents were recorded during this period. "
        f"<b>{open_unowned}</b> alerts remain open with no assigned owner and require immediate attention. "
        "The most active threat models and behaviour patterns are detailed in the sections above. "
        "It is recommended to review all high and critical severity alerts, assign ownership to open items, "
        "and validate that detection coverage aligns with the MITRE ATT&CK techniques observed."
    )
    elems.append(Paragraph(para, sty["body"]))
    return elems


# ── Public entry point ────────────────────────────────────────────────────────

def generate_executive_summary(
    data: dict,
    customer_name: str = "Customer",
    period_days: int = 30,
    output_path: str | None = None,
) -> str:
    """
    Build and save the Executive Summary PDF report.

    Args:
        data:          Dict returned by collect_executive_summary().
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
        output_path = str(Path(output_dir) / f"executive_summary_{ts}.pdf")

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sty = _styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2.5 * cm,
        title=f"Executive Security Summary — {customer_name}",
        author="Trend Vision One Reporter",
    )

    story: list = []
    story += _cover(sty, customer_name, period_days, generated_at)
    story += _stat_cards(sty, data)
    story += _alert_severity_section(sty, data)
    story += [PageBreak()]
    story += _alert_trend_section(sty, data)
    story += _top_threat_models_section(sty, data)
    story += [PageBreak()]
    story += _top_oat_section(sty, data)
    story += _impacted_assets_section(sty, data)
    story += [PageBreak()]
    story += _summary_paragraph(sty, data, customer_name, period_days)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return os.path.abspath(output_path)
