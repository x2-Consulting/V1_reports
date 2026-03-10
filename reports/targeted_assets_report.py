"""
Most Targeted Assets PDF Report Generator for Trend Vision One.

Ranks hosts and accounts by alert and OAT detection volume,
with per-host detail sections for the top 10 most targeted endpoints.
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
WHITE      = colors.white

SEVERITY_COLORS = {
    "critical": colors.HexColor("#D71920"),
    "high":     colors.HexColor("#E8610A"),
    "medium":   colors.HexColor("#D4A017"),
    "low":      colors.HexColor("#2E7D32"),
    "info":     colors.HexColor("#1565C0"),
    "unknown":  MID_GREY,
}

PAGE_W, PAGE_H = A4
CONTENT_W = PAGE_W - 4 * cm


# ── Styles ────────────────────────────────────────────────────────────────────

def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "TACoverTitle", parent=base["Title"],
            fontSize=24, textColor=WHITE, alignment=TA_CENTER, spaceAfter=4,
        ),
        "cover_sub": ParagraphStyle(
            "TACoverSub", parent=base["Normal"],
            fontSize=12, textColor=colors.HexColor("#BBCCDD"),
            alignment=TA_CENTER, spaceAfter=2,
        ),
        "section": ParagraphStyle(
            "TASection", parent=base["Heading1"],
            fontSize=13, textColor=TV1_RED, spaceBefore=14, spaceAfter=6,
        ),
        "host_header": ParagraphStyle(
            "TAHostHeader", parent=base["Normal"],
            fontSize=11, textColor=TV1_NAVY, fontName="Helvetica-Bold",
            spaceBefore=6, spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "TABody", parent=base["Normal"],
            fontSize=9, textColor=colors.HexColor("#2C2C2C"), leading=13,
        ),
        "small": ParagraphStyle(
            "TASmall", parent=base["Normal"],
            fontSize=7.5, textColor=MID_GREY, leading=11,
        ),
        "cell": ParagraphStyle(
            "TACell", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#2C2C2C"),
            leading=11, wordWrap="CJK",
        ),
        "caption": ParagraphStyle(
            "TACaption", parent=base["Normal"],
            fontSize=8, textColor=MID_GREY, alignment=TA_CENTER,
        ),
        "stat_value": ParagraphStyle(
            "TAStatValue", parent=base["Normal"],
            fontSize=20, textColor=WHITE, alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        ),
        "stat_label": ParagraphStyle(
            "TAStatLabel", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#DDDDDD"), alignment=TA_CENTER,
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
    canvas.drawString(2 * cm, 1.2 * cm, "Trend Vision One — Most Targeted Assets Report — Confidential")
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

    sub_data = [[Paragraph("Most Targeted Assets Report", sty["cover_sub"])]]
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


# ── Summary stat cards ────────────────────────────────────────────────────────

def _summary_cards(sty: dict, data: dict) -> list:
    elems = [
        PageBreak(),
        Paragraph("Asset Risk Summary", sty["section"]),
    ]

    total_hosts = data.get("total_unique_hosts", 0)
    total_accounts = data.get("total_unique_accounts", 0)
    high_risk = data.get("high_risk_hosts", 0)

    card_bg = [TV1_RED, TV1_NAVY, colors.HexColor("#E8610A")]
    labels = ["Unique Hosts Seen", "Unique Accounts Seen", "High-Risk Hosts (>5 alerts)"]
    values = [str(total_hosts), str(total_accounts), str(high_risk)]

    cards_row = [[
        Table(
            [[Paragraph(values[i], sty["stat_value"])],
             [Paragraph(labels[i], sty["stat_label"])]],
            colWidths=[(CONTENT_W / 3) - 0.3 * cm],
            style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), card_bg[i]),
                ("TOPPADDING",    (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]),
        )
        for i in range(3)
    ]]

    outer = Table(cards_row, colWidths=[(CONTENT_W / 3)] * 3)
    outer.setStyle(TableStyle([
        ("LEFTPADDING",  (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(outer)
    return elems


# ── Host risk ranking table ───────────────────────────────────────────────────

def _host_ranking_table(sty: dict, data: dict) -> list:
    elems = [Paragraph("Host Risk Ranking", sty["section"])]

    hosts = data.get("hosts") or []
    if not hosts:
        elems.append(Paragraph("No host data available.", sty["body"]))
        return elems

    rows = [["#", "Hostname", "IP Address", "Alerts", "OAT Hits", "Total Hits", "Top Threat"]]
    style_cmds = list(_table_style(7))

    for idx, h in enumerate(hosts, 1):
        top_threat = (h.get("top_threat_types") or ["—"])[0]
        row = [
            Paragraph(str(idx), sty["cell"]),
            Paragraph(_t(h.get("name", "—"), 22), sty["cell"]),
            Paragraph(_t(h.get("ip", "—"), 15), sty["cell"]),
            Paragraph(str(h.get("alert_count", 0)), sty["cell"]),
            Paragraph(str(h.get("oat_count", 0)), sty["cell"]),
            Paragraph(str(h.get("total_hits", 0)), sty["cell"]),
            Paragraph(_t(top_threat, 25), sty["cell"]),
        ]
        rows.append(row)
        # Highlight top 3 in light red
        if idx <= 3:
            style_cmds.append(("BACKGROUND", (0, idx), (-1, idx), LIGHT_RED))

    tbl = Table(
        rows,
        colWidths=[0.8 * cm, 4 * cm, 2.8 * cm, 1.6 * cm, 2 * cm, 2 * cm, CONTENT_W - 13.2 * cm],
        repeatRows=1,
    )
    tbl.setStyle(TableStyle(style_cmds))
    elems.append(tbl)
    return elems


# ── Per-host detail sections for top 10 ──────────────────────────────────────

def _host_detail_sections(sty: dict, data: dict) -> list:
    elems = [
        PageBreak(),
        Paragraph("Top 10 Host Detail Sections", sty["section"]),
    ]

    hosts = (data.get("hosts") or [])[:10]
    if not hosts:
        elems.append(Paragraph("No host data to detail.", sty["body"]))
        return elems

    for idx, h in enumerate(hosts, 1):
        name = h.get("name", "Unknown")
        ip = h.get("ip", "")
        alert_count = h.get("alert_count", 0)
        oat_count = h.get("oat_count", 0)
        total_hits = h.get("total_hits", 0)
        last_seen = h.get("last_seen", "—")
        sev_dict = h.get("alert_severities") or {}
        threats = h.get("top_threat_types") or []

        header_data = [[
            Paragraph(
                f'<font color="white"><b>#{idx} — {_t(name, 40)}</b>  '
                f'<font size="8">IP: {ip or "unknown"} · {alert_count} alerts · {oat_count} OAT hits</font></font>',
                sty["body"],
            )
        ]]
        header_tbl = Table(header_data, colWidths=[CONTENT_W])
        header_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), TV1_NAVY),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))

        # Severity breakdown mini-table
        sev_items = [(sev, cnt) for sev, cnt in sev_dict.items() if cnt > 0]
        sev_items.sort(key=lambda x: ["critical", "high", "medium", "low", "info", "unknown"].index(x[0])
                       if x[0] in ["critical", "high", "medium", "low", "info", "unknown"] else 99)

        sev_rows = [["Severity", "Count"]]
        for sev_name, cnt in sev_items:
            sev_rows.append([_sev_badge(sev_name, sty), Paragraph(str(cnt), sty["cell"])])
        if not sev_items:
            sev_rows.append([Paragraph("—", sty["cell"]), Paragraph("0", sty["cell"])])

        sev_tbl = Table(sev_rows, colWidths=[3 * cm, 2.5 * cm], repeatRows=1)
        sev_tbl.setStyle(TableStyle(_table_style(2, header_bg=TV1_NAVY2)))

        # Threat types list
        threats_text = ", ".join(threats) if threats else "None identified"

        meta_rows = [["Attribute", "Value"]]
        meta_rows.append([Paragraph("Last Seen", sty["cell"]), Paragraph(_t(last_seen, 25), sty["cell"])])
        meta_rows.append([Paragraph("Total Hits", sty["cell"]), Paragraph(str(total_hits), sty["cell"])])
        meta_rows.append([Paragraph("Threat Types Seen", sty["cell"]), Paragraph(_t(threats_text, 55), sty["cell"])])

        meta_tbl = Table(meta_rows, colWidths=[4 * cm, CONTENT_W - 4 * cm - 5.5 * cm - 0.5 * cm], repeatRows=1)
        meta_tbl.setStyle(TableStyle(_table_style(2, header_bg=TV1_NAVY2)))

        detail_row = [[sev_tbl, meta_tbl]]
        detail_tbl = Table(detail_row, colWidths=[5.5 * cm, CONTENT_W - 5.5 * cm])
        detail_tbl.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (0, 0), 4),
        ]))

        block = [
            header_tbl,
            Spacer(1, 0.1 * cm),
            detail_tbl,
            Spacer(1, 0.5 * cm),
        ]
        elems.append(KeepTogether(block[:2]))
        elems.extend(block[2:])

    return elems


# ── Account risk table ────────────────────────────────────────────────────────

def _account_risk_table(sty: dict, data: dict) -> list:
    elems = [Paragraph("Account Risk Ranking", sty["section"])]

    accounts = data.get("accounts") or []
    if not accounts:
        elems.append(Paragraph("No account data available.", sty["body"]))
        return elems

    rows = [["#", "Account Name", "Alert Count", "Threat Types Seen", "Last Seen"]]
    for idx, a in enumerate(accounts, 1):
        threat_types = ", ".join(a.get("alert_types") or []) or "—"
        rows.append([
            Paragraph(str(idx), sty["cell"]),
            Paragraph(_t(a.get("name", "—"), 28), sty["cell"]),
            Paragraph(str(a.get("alert_count", 0)), sty["cell"]),
            Paragraph(_t(threat_types, 35), sty["cell"]),
            Paragraph(_t(a.get("last_seen", "—"), 20), sty["cell"]),
        ])

    tbl = Table(
        rows,
        colWidths=[0.8 * cm, 5 * cm, 2 * cm, 6 * cm, CONTENT_W - 13.8 * cm],
        repeatRows=1,
    )
    tbl.setStyle(TableStyle(_table_style(5)))
    elems.append(tbl)
    return elems


# ── Public entry point ────────────────────────────────────────────────────────

def generate_targeted_assets_report(
    data: dict,
    customer_name: str = "Customer",
    period_days: int = 30,
    output_path: str | None = None,
) -> str:
    """
    Build and save the Most Targeted Assets PDF report.

    Args:
        data:          Dict returned by collect_targeted_assets().
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
        output_path = str(Path(output_dir) / f"targeted_assets_{ts}.pdf")

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sty = _styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2.5 * cm,
        title=f"Most Targeted Assets — {customer_name}",
        author="Trend Vision One Reporter",
    )

    story: list = []
    story += _cover(sty, customer_name, period_days, generated_at)
    story += _summary_cards(sty, data)
    story += _host_ranking_table(sty, data)
    story += _host_detail_sections(sty, data)
    story += [PageBreak()]
    story += _account_risk_table(sty, data)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return os.path.abspath(output_path)
