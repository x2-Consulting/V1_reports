"""
PDF report generator for Trend Vision One data.
Uses ReportLab to produce a structured, multi-section report.
"""

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
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ── Colour palette ────────────────────────────────────────────────────────────
TREND_RED = colors.HexColor("#D71920")
DARK_GREY = colors.HexColor("#2C2C2C")
MID_GREY = colors.HexColor("#6B6B6B")
LIGHT_GREY = colors.HexColor("#F5F5F5")
WHITE = colors.white

SEVERITY_COLORS = {
    "critical": colors.HexColor("#D71920"),
    "high": colors.HexColor("#FF6B35"),
    "medium": colors.HexColor("#FFB347"),
    "low": colors.HexColor("#4CAF50"),
    "info": colors.HexColor("#2196F3"),
}

# ── Styles ────────────────────────────────────────────────────────────────────

def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontSize=26,
            textColor=WHITE,
            alignment=TA_CENTER,
            spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            parent=base["Normal"],
            fontSize=11,
            textColor=colors.HexColor("#CCCCCC"),
            alignment=TA_CENTER,
            spaceAfter=2,
        ),
        "section": ParagraphStyle(
            "SectionHeader",
            parent=base["Heading1"],
            fontSize=14,
            textColor=TREND_RED,
            spaceBefore=14,
            spaceAfter=6,
            borderPad=4,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontSize=9,
            textColor=DARK_GREY,
            leading=13,
        ),
        "caption": ParagraphStyle(
            "Caption",
            parent=base["Normal"],
            fontSize=8,
            textColor=MID_GREY,
            alignment=TA_CENTER,
        ),
        "cell": ParagraphStyle(
            "Cell",
            parent=base["Normal"],
            fontSize=8,
            textColor=DARK_GREY,
            leading=11,
            wordWrap="CJK",
        ),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _severity_badge(severity: str, styles: dict) -> Paragraph:
    sev = severity.lower()
    colour = SEVERITY_COLORS.get(sev, MID_GREY).hexval()
    text = f'<font color="{colour}"><b>{severity.upper()}</b></font>'
    return Paragraph(text, styles["cell"])


def _truncate(value: Any, max_len: int = 60) -> str:
    s = str(value) if value is not None else "—"
    return s[:max_len] + "…" if len(s) > max_len else s


def _header_row_style(col_count: int) -> list:
    return [
        ("BACKGROUND", (0, 0), (col_count - 1, 0), TREND_RED),
        ("TEXTCOLOR", (0, 0), (col_count - 1, 0), WHITE),
        ("FONTNAME", (0, 0), (col_count - 1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (col_count - 1, 0), 9),
        ("BOTTOMPADDING", (0, 0), (col_count - 1, 0), 6),
        ("TOPPADDING", (0, 0), (col_count - 1, 0), 6),
        ("ROWBACKGROUNDS", (0, 1), (col_count - 1, -1), [WHITE, LIGHT_GREY]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#DDDDDD")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
    ]


# ── Cover page ────────────────────────────────────────────────────────────────

def _cover_page(styles: dict, generated_at: str) -> list:
    elements = []
    # Coloured header band via a 1-cell table
    cover_data = [[Paragraph("Trend Vision One", styles["title"])]]
    cover_table = Table(cover_data, colWidths=[17 * cm])
    cover_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), TREND_RED),
            ("TOPPADDING", (0, 0), (-1, -1), 30),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 30),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ])
    )
    elements.append(cover_table)
    elements.append(Spacer(1, 0.4 * cm))

    sub_data = [[Paragraph("Security Intelligence Report", styles["subtitle"])]]
    sub_table = Table(sub_data, colWidths=[17 * cm])
    sub_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), DARK_GREY),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ])
    )
    elements.append(sub_table)
    elements.append(Spacer(1, 1 * cm))
    elements.append(
        Paragraph(f"Generated: {generated_at}", styles["caption"])
    )
    elements.append(Spacer(1, 0.5 * cm))
    elements.append(HRFlowable(width="100%", thickness=1, color=TREND_RED))
    return elements


# ── Summary stats ─────────────────────────────────────────────────────────────

def _summary_section(
    styles: dict,
    alerts: list,
    endpoints: list,
    iocs: list,
    vulns: list,
) -> list:
    elements = [Paragraph("Executive Summary", styles["section"])]

    def count_by_severity(items: list) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in items:
            sev = item.get("severity", "unknown").lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    alert_counts = count_by_severity(alerts)
    vuln_counts = count_by_severity(vulns)

    rows = [
        ["Metric", "Total", "Critical", "High", "Medium", "Low"],
        [
            "Workbench Alerts",
            str(len(alerts)),
            str(alert_counts.get("critical", 0)),
            str(alert_counts.get("high", 0)),
            str(alert_counts.get("medium", 0)),
            str(alert_counts.get("low", 0)),
        ],
        ["Endpoints Monitored", str(len(endpoints)), "—", "—", "—", "—"],
        [
            "Threat IoCs",
            str(len(iocs)),
            "—", "—", "—", "—",
        ],
        [
            "Vulnerabilities",
            str(len(vulns)),
            str(vuln_counts.get("critical", 0)),
            str(vuln_counts.get("high", 0)),
            str(vuln_counts.get("medium", 0)),
            str(vuln_counts.get("low", 0)),
        ],
    ]

    col_widths = [5 * cm, 2.5 * cm, 2.5 * cm, 2.5 * cm, 2.5 * cm, 2 * cm]
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle(_header_row_style(6)))
    elements.append(table)
    return elements


# ── Alerts section ────────────────────────────────────────────────────────────

def _alerts_section(styles: dict, alerts: list) -> list:
    elements: list = [
        PageBreak(),
        Paragraph("Workbench Alerts", styles["section"]),
        Paragraph(
            f"Total alerts retrieved: <b>{len(alerts)}</b>", styles["body"]
        ),
        Spacer(1, 0.3 * cm),
    ]
    if not alerts:
        elements.append(Paragraph("No alerts found for the selected period.", styles["body"]))
        return elements

    headers = ["Alert ID", "Severity", "Description", "Status", "Created"]
    rows = [headers]
    for a in alerts:
        rows.append([
            Paragraph(_truncate(a.get("id", "—"), 20), styles["cell"]),
            _severity_badge(a.get("severity", "unknown"), styles),
            Paragraph(_truncate(a.get("description", a.get("title", "—")), 55), styles["cell"]),
            Paragraph(str(a.get("investigationStatus", "—")), styles["cell"]),
            Paragraph(_truncate(a.get("createdDateTime", "—"), 19), styles["cell"]),
        ])

    col_widths = [2.8 * cm, 1.8 * cm, 6.5 * cm, 2.5 * cm, 3.4 * cm]
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle(_header_row_style(5)))
    elements.append(table)
    return elements


# ── Endpoints section ─────────────────────────────────────────────────────────

def _endpoints_section(styles: dict, endpoints: list) -> list:
    elements: list = [
        PageBreak(),
        Paragraph("Endpoint Sensors", styles["section"]),
        Paragraph(
            f"Total endpoints: <b>{len(endpoints)}</b>", styles["body"]
        ),
        Spacer(1, 0.3 * cm),
    ]
    if not endpoints:
        elements.append(Paragraph("No endpoint data available.", styles["body"]))
        return elements

    headers = ["Hostname", "OS", "Agent Version", "Status", "Last Seen"]
    rows = [headers]
    for ep in endpoints:
        rows.append([
            Paragraph(_truncate(ep.get("displayName", ep.get("hostname", "—")), 25), styles["cell"]),
            Paragraph(_truncate(ep.get("osName", "—"), 20), styles["cell"]),
            Paragraph(_truncate(ep.get("agentVersion", "—"), 15), styles["cell"]),
            Paragraph(str(ep.get("agentStatus", ep.get("status", "—"))), styles["cell"]),
            Paragraph(_truncate(ep.get("lastUsedIp", ep.get("lastSeen", "—")), 20), styles["cell"]),
        ])

    col_widths = [4 * cm, 3.5 * cm, 2.8 * cm, 2.5 * cm, 4.2 * cm]
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle(_header_row_style(5)))
    elements.append(table)
    return elements


# ── Threat intel section ──────────────────────────────────────────────────────

def _threat_intel_section(styles: dict, iocs: list) -> list:
    elements: list = [
        PageBreak(),
        Paragraph("Threat Intelligence — Suspicious Objects (IoCs)", styles["section"]),
        Paragraph(
            f"Total IoCs retrieved: <b>{len(iocs)}</b>", styles["body"]
        ),
        Spacer(1, 0.3 * cm),
    ]
    if not iocs:
        elements.append(Paragraph("No suspicious objects found.", styles["body"]))
        return elements

    headers = ["Type", "Value", "Risk Level", "Expiry", "Description"]
    rows = [headers]
    for ioc in iocs:
        rows.append([
            Paragraph(str(ioc.get("objectType", ioc.get("type", "—"))), styles["cell"]),
            Paragraph(_truncate(ioc.get("objectValue", ioc.get("value", "—")), 30), styles["cell"]),
            _severity_badge(ioc.get("riskLevel", ioc.get("severity", "unknown")), styles),
            Paragraph(_truncate(ioc.get("expiredDateTime", "—"), 19), styles["cell"]),
            Paragraph(_truncate(ioc.get("description", "—"), 40), styles["cell"]),
        ])

    col_widths = [2.2 * cm, 4.5 * cm, 2.2 * cm, 3 * cm, 5.1 * cm]
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle(_header_row_style(5)))
    elements.append(table)
    return elements


# ── Vulnerabilities section ───────────────────────────────────────────────────

def _vulnerabilities_section(styles: dict, vulns: list) -> list:
    elements: list = [
        PageBreak(),
        Paragraph("Vulnerability Assessment", styles["section"]),
        Paragraph(
            f"Total vulnerabilities: <b>{len(vulns)}</b>", styles["body"]
        ),
        Spacer(1, 0.3 * cm),
    ]
    if not vulns:
        elements.append(Paragraph("No vulnerabilities found.", styles["body"]))
        return elements

    headers = ["CVE / ID", "Severity", "CVSS", "Affected Asset", "Description"]
    rows = [headers]
    for v in vulns:
        rows.append([
            Paragraph(_truncate(v.get("cveId", v.get("id", "—")), 18), styles["cell"]),
            _severity_badge(v.get("severity", "unknown"), styles),
            Paragraph(str(v.get("cvssScore", v.get("riskScore", "—"))), styles["cell"]),
            Paragraph(_truncate(v.get("affectedAsset", v.get("assetName", "—")), 25), styles["cell"]),
            Paragraph(_truncate(v.get("description", "—"), 45), styles["cell"]),
        ])

    col_widths = [2.8 * cm, 2 * cm, 1.5 * cm, 4 * cm, 6.7 * cm]
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle(_header_row_style(5)))
    elements.append(table)
    return elements


# ── Footer callback ───────────────────────────────────────────────────────────

def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MID_GREY)
    canvas.drawString(2 * cm, 1.2 * cm, "Trend Vision One — Confidential Security Report")
    canvas.drawRightString(
        A4[0] - 2 * cm,
        1.2 * cm,
        f"Page {doc.page}",
    )
    canvas.restoreState()


# ── Public entry point ────────────────────────────────────────────────────────

def generate_report(
    alerts: list[dict],
    endpoints: list[dict],
    iocs: list[dict],
    vulns: list[dict],
    output_path: str | None = None,
) -> str:
    """
    Build and save a PDF report.

    Args:
        alerts:      Workbench alert records.
        endpoints:   Endpoint sensor records.
        iocs:        Threat intel / suspicious object records.
        vulns:       Vulnerability assessment records.
        output_path: File path to write. Auto-generated if None.

    Returns:
        Absolute path to the written PDF file.
    """
    output_dir = os.getenv("REPORT_OUTPUT_DIR", "./output")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    if output_path is None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = str(Path(output_dir) / f"tv1_report_{ts}.pdf")

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    styles = _build_styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2.5 * cm,
        title="Trend Vision One Security Report",
        author="Trend Vision One Reporter",
    )

    story: list = []
    story += _cover_page(styles, generated_at)
    story += _summary_section(styles, alerts, endpoints, iocs, vulns)
    story += _alerts_section(styles, alerts)
    story += _endpoints_section(styles, endpoints)
    story += _threat_intel_section(styles, iocs)
    story += _vulnerabilities_section(styles, vulns)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return os.path.abspath(output_path)
