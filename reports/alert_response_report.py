"""
Alert Response Status PDF Report Generator for Trend Vision One.

Analyses investigation status, resolution times, unowned/stale alerts,
and provides actionable response recommendations.
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
LIGHT_RED  = colors.HexColor("#FDECEA")
LIGHT_AMBER = colors.HexColor("#FFF8E1")
WHITE      = colors.white

SEVERITY_COLORS = {
    "critical": colors.HexColor("#D71920"),
    "high":     colors.HexColor("#E8610A"),
    "medium":   colors.HexColor("#D4A017"),
    "low":      colors.HexColor("#2E7D32"),
    "info":     colors.HexColor("#1565C0"),
    "unknown":  MID_GREY,
}

INV_STATUS_COLORS = {
    "true positive":        colors.HexColor("#D71920"),
    "false positive":       colors.HexColor("#2E7D32"),
    "benign true positive": colors.HexColor("#D4A017"),
    "in progress":          colors.HexColor("#1565C0"),
    "new":                  MID_GREY,
}

PAGE_W, PAGE_H = A4
CONTENT_W = PAGE_W - 4 * cm


# ── Styles ────────────────────────────────────────────────────────────────────

def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "ARCoverTitle", parent=base["Title"],
            fontSize=24, textColor=WHITE, alignment=TA_CENTER, spaceAfter=4,
        ),
        "cover_sub": ParagraphStyle(
            "ARCoverSub", parent=base["Normal"],
            fontSize=12, textColor=colors.HexColor("#BBCCDD"),
            alignment=TA_CENTER, spaceAfter=2,
        ),
        "section": ParagraphStyle(
            "ARSection", parent=base["Heading1"],
            fontSize=13, textColor=TV1_RED, spaceBefore=14, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "ARBody", parent=base["Normal"],
            fontSize=9, textColor=colors.HexColor("#2C2C2C"), leading=13,
        ),
        "small": ParagraphStyle(
            "ARSmall", parent=base["Normal"],
            fontSize=7.5, textColor=MID_GREY, leading=11,
        ),
        "cell": ParagraphStyle(
            "ARCell", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#2C2C2C"),
            leading=11, wordWrap="CJK",
        ),
        "caption": ParagraphStyle(
            "ARCaption", parent=base["Normal"],
            fontSize=8, textColor=MID_GREY, alignment=TA_CENTER,
        ),
        "stat_value": ParagraphStyle(
            "ARStatValue", parent=base["Normal"],
            fontSize=20, textColor=WHITE, alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        ),
        "stat_label": ParagraphStyle(
            "ARStatLabel", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#DDDDDD"), alignment=TA_CENTER,
        ),
        "rec_item": ParagraphStyle(
            "ARRecItem", parent=base["Normal"],
            fontSize=9, textColor=colors.HexColor("#2C2C2C"), leading=13,
            leftIndent=12, spaceAfter=4,
        ),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _t(value: Any, max_len: int = 60) -> str:
    s = str(value) if value is not None else "—"
    return s[:max_len] + "…" if len(s) > max_len else s


def _sev_badge(sev: str, sty: dict) -> Paragraph:
    col = SEVERITY_COLORS.get(sev.lower(), MID_GREY).hexval()
    return Paragraph(f'<font color="{col}"><b>{sev.upper()}</b></font>', sty["cell"])


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
    canvas.drawString(2 * cm, 1.2 * cm, "Trend Vision One — Alert Response Status Report — Confidential")
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

    sub_data = [[Paragraph("Alert Response Status Report", sty["cover_sub"])]]
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


# ── KPI stat cards ────────────────────────────────────────────────────────────

def _kpi_cards(sty: dict, data: dict) -> list:
    elems = [
        PageBreak(),
        Paragraph("Response Key Performance Indicators", sty["section"]),
    ]

    total = data.get("total_alerts", 0)
    by_status = data.get("by_status") or {}
    by_inv = data.get("by_investigation_status") or {}
    avg_res = data.get("avg_resolution_hours", 0.0)

    closed = by_status.get("Closed", 0)
    pct_closed = f"{closed / total * 100:.0f}%" if total else "0%"

    investigated = sum(
        c for s, c in by_inv.items()
        if s.lower() not in ("new", "unknown", "in progress", "")
    )
    pct_investigated = f"{investigated / total * 100:.0f}%" if total else "0%"

    avg_res_str = f"{avg_res:.1f}h" if avg_res else "N/A"

    card_bg = [TV1_NAVY, TV1_RED, colors.HexColor("#2E7D32"), colors.HexColor("#E8610A")]
    labels = ["Total Alerts", "Investigated (%)", "Closed (%)", "Avg Resolution"]
    values = [str(total), pct_investigated, pct_closed, avg_res_str]

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
    elems.append(Spacer(1, 0.3 * cm))
    elems.append(Paragraph(
        f"Cases: <b>{data.get('case_count', 0)}</b>  |  "
        f"Incidents: <b>{data.get('incident_count', 0)}</b>  |  "
        f"Open / Unowned: <b>{len(data.get('open_unowned') or [])}</b>  |  "
        f"Open >7 days: <b>{len(data.get('stale_alerts') or [])}</b>",
        sty["body"],
    ))
    return elems


# ── Investigation status table ────────────────────────────────────────────────

def _investigation_status_table(sty: dict, data: dict) -> list:
    elems = [Paragraph("Investigation Status Breakdown", sty["section"])]

    by_inv = data.get("by_investigation_status") or {}
    total = sum(by_inv.values()) or 1

    rows = [["Investigation Status", "Count", "% of Total"]]
    style_cmds = list(_table_style(3))

    for row_idx, (status, cnt) in enumerate(
        sorted(by_inv.items(), key=lambda x: x[1], reverse=True), 1
    ):
        pct = f"{cnt / total * 100:.1f}%"
        col = INV_STATUS_COLORS.get(status.lower(), MID_GREY)
        hex_col = col.hexval()
        rows.append([
            Paragraph(f'<font color="{hex_col}"><b>{status}</b></font>', sty["cell"]),
            Paragraph(str(cnt), sty["cell"]),
            Paragraph(pct, sty["cell"]),
        ])

    tbl = Table(rows, colWidths=[6 * cm, 3 * cm, 3 * cm], repeatRows=1)
    tbl.setStyle(TableStyle(style_cmds))
    elems.append(tbl)
    return elems


# ── Open unowned alerts table ─────────────────────────────────────────────────

def _open_unowned_table(sty: dict, data: dict) -> list:
    elems = [Paragraph("Open Alerts — No Assigned Owner", sty["section"])]

    unowned = data.get("open_unowned") or []
    if not unowned:
        elems.append(Paragraph(
            "All open alerts have assigned owners. Good hygiene maintained.", sty["body"]
        ))
        return elems

    elems.append(Paragraph(
        f"<b>{len(unowned)}</b> open alerts have no assigned owner and require triage assignment.",
        sty["body"],
    ))
    elems.append(Spacer(1, 0.2 * cm))

    rows = [["Alert ID", "Severity", "Model / Rule", "Created", "Risk Score"]]
    style_cmds = list(_table_style(5))

    for row_idx, alert in enumerate(unowned[:50], 1):
        sev = alert.get("severity", "unknown")
        if sev.lower() in ("critical", "high"):
            style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), LIGHT_RED))
        rows.append([
            Paragraph(_t(alert.get("id", "—"), 18), sty["cell"]),
            _sev_badge(sev, sty),
            Paragraph(_t(alert.get("model", "—"), 35), sty["cell"]),
            Paragraph(_t(alert.get("created", "—"), 19), sty["cell"]),
            Paragraph(str(alert.get("score") or "—"), sty["cell"]),
        ])

    tbl = Table(
        rows,
        colWidths=[3 * cm, 2.2 * cm, 6 * cm, 3.5 * cm, 1.3 * cm],
        repeatRows=1,
    )
    tbl.setStyle(TableStyle(style_cmds))
    elems.append(tbl)

    if len(unowned) > 50:
        elems.append(Paragraph(
            f"Showing first 50 of {len(unowned)} open unowned alerts.", sty["caption"]
        ))
    return elems


# ── Stale alerts table ────────────────────────────────────────────────────────

def _stale_alerts_table(sty: dict, data: dict) -> list:
    elems = [Paragraph("Stale Alerts — Open More Than 7 Days", sty["section"])]

    stale = data.get("stale_alerts") or []
    if not stale:
        elems.append(Paragraph(
            "No alerts have been open for more than 7 days.", sty["body"]
        ))
        return elems

    elems.append(Paragraph(
        f"<b>{len(stale)}</b> alerts have been open for more than 7 days without resolution.",
        sty["body"],
    ))
    elems.append(Spacer(1, 0.2 * cm))

    rows = [["Alert ID", "Severity", "Model / Rule", "Created", "Days Open"]]
    style_cmds = list(_table_style(5))

    for row_idx, alert in enumerate(stale[:50], 1):
        days_open = alert.get("days_open", 0)
        if days_open > 30:
            style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), LIGHT_RED))
        elif days_open > 14:
            style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), LIGHT_AMBER))
        rows.append([
            Paragraph(_t(alert.get("id", "—"), 18), sty["cell"]),
            _sev_badge(alert.get("severity", "unknown"), sty),
            Paragraph(_t(alert.get("model", "—"), 35), sty["cell"]),
            Paragraph(_t(alert.get("created", "—"), 19), sty["cell"]),
            Paragraph(f"<b>{days_open}d</b>", sty["cell"]),
        ])

    tbl = Table(
        rows,
        colWidths=[3 * cm, 2.2 * cm, 6 * cm, 3.5 * cm, 1.3 * cm],
        repeatRows=1,
    )
    tbl.setStyle(TableStyle(style_cmds))
    elems.append(tbl)

    if len(stale) > 50:
        elems.append(Paragraph(
            f"Showing first 50 of {len(stale)} stale alerts.", sty["caption"]
        ))
    return elems


# ── Resolution time analysis ──────────────────────────────────────────────────

def _resolution_analysis(sty: dict, data: dict) -> list:
    elems = [Paragraph("Resolution Time Analysis", sty["section"])]

    times = data.get("resolution_times") or []
    avg = data.get("avg_resolution_hours", 0.0)

    if not times:
        elems.append(Paragraph(
            "No closed alerts with resolution time data found in the selected period.", sty["body"]
        ))
        return elems

    fastest = min(times)
    slowest = max(times)
    median = sorted(times)[len(times) // 2]

    rows = [["Metric", "Value"]]
    rows.append([Paragraph("Alerts with resolution data", sty["cell"]),
                 Paragraph(str(len(times)), sty["cell"])])
    rows.append([Paragraph("Fastest resolution", sty["cell"]),
                 Paragraph(f"{fastest:.1f} hours", sty["cell"])])
    rows.append([Paragraph("Median resolution", sty["cell"]),
                 Paragraph(f"{median:.1f} hours", sty["cell"])])
    rows.append([Paragraph("Average resolution", sty["cell"]),
                 Paragraph(f"<b>{avg:.1f} hours</b>", sty["cell"])])
    rows.append([Paragraph("Slowest resolution", sty["cell"]),
                 Paragraph(f"{slowest:.1f} hours  ({slowest / 24:.1f} days)", sty["cell"])])

    tbl = Table(rows, colWidths=[5 * cm, 5 * cm], repeatRows=1)
    tbl.setStyle(TableStyle(_table_style(2)))
    elems.append(tbl)
    return elems


# ── Recommendations ───────────────────────────────────────────────────────────

def _recommendations(sty: dict, data: dict) -> list:
    elems = [
        PageBreak(),
        Paragraph("Response Recommendations", sty["section"]),
    ]

    stale = data.get("stale_alerts") or []
    unowned = data.get("open_unowned") or []
    avg = data.get("avg_resolution_hours", 0.0)
    no_findings = data.get("open_with_no_findings", 0)
    total = data.get("total_alerts", 0)
    by_inv = data.get("by_investigation_status") or {}

    critical_unowned = sum(1 for a in unowned if a.get("severity", "").lower() == "critical")
    high_unowned = sum(1 for a in unowned if a.get("severity", "").lower() == "high")

    recs: list[str] = []

    if stale:
        recs.append(
            f"<b>{len(stale)} alerts have been open for more than 7 days</b> without resolution. "
            "Each stale alert should be reviewed and either escalated, resolved, or closed with a "
            "documented justification. Stale alerts increase operational risk and reduce SOC effectiveness."
        )

    if critical_unowned > 0:
        recs.append(
            f"<b>{critical_unowned} Critical-severity alerts have no assigned owner.</b> "
            "Critical alerts require immediate triage and should be assigned within 1 hour of detection. "
            "Establish an on-call rotation or escalation path to ensure coverage."
        )

    if high_unowned > 0:
        recs.append(
            f"<b>{high_unowned} High-severity alerts have no assigned owner.</b> "
            "High-severity alerts should be triaged within 4 hours. Review workload distribution "
            "and ensure the alert queue is being actively monitored."
        )

    if no_findings > 0:
        recs.append(
            f"<b>{no_findings} open alerts have an investigation result of 'No Findings'</b> but remain "
            "in an open state. These should be closed to keep the alert queue accurate and reduce noise."
        )

    if avg > 48:
        recs.append(
            f"<b>Average alert resolution time is {avg:.1f} hours ({avg / 24:.1f} days).</b> "
            "This exceeds best-practice thresholds for critical environments. Review the investigation "
            "workflow for bottlenecks and consider automating triage steps for common alert types."
        )

    new_count = by_inv.get("New", 0) + by_inv.get("new", 0)
    if new_count > 0 and total > 0:
        pct_new = new_count / total * 100
        if pct_new > 30:
            recs.append(
                f"<b>{new_count} alerts ({pct_new:.0f}% of total) are still in 'New' status.</b> "
                "A high proportion of uninvestigated alerts indicates that the SOC team may be "
                "under-resourced or that alert volume exceeds current capacity. Consider tuning "
                "detection rules to reduce noise or adding analyst capacity."
            )

    if not recs:
        recs.append(
            "Alert response metrics are within acceptable ranges. Continue to monitor KPIs weekly "
            "and review any spikes in unowned or stale alerts promptly."
        )

    for rec in recs:
        elems.append(Paragraph(f"\u2022 {rec}", sty["rec_item"]))

    return elems


# ── Public entry point ────────────────────────────────────────────────────────

def generate_alert_response_report(
    data: dict,
    customer_name: str = "Customer",
    period_days: int = 30,
    output_path: str | None = None,
) -> str:
    """
    Build and save the Alert Response Status PDF report.

    Args:
        data:          Dict returned by collect_alert_response().
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
        output_path = str(Path(output_dir) / f"alert_response_{ts}.pdf")

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sty = _styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2.5 * cm,
        title=f"Alert Response Status — {customer_name}",
        author="Trend Vision One Reporter",
    )

    story: list = []
    story += _cover(sty, customer_name, period_days, generated_at)
    story += _kpi_cards(sty, data)
    story += _investigation_status_table(sty, data)
    story += [PageBreak()]
    story += _open_unowned_table(sty, data)
    story += _stale_alerts_table(sty, data)
    story += _resolution_analysis(sty, data)
    story += _recommendations(sty, data)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return os.path.abspath(output_path)
