"""
MITRE ATT&CK Heatmap PDF Report Generator for Trend Vision One.

Visualises technique and tactic coverage derived from alerts and OAT detections,
with colour-coded activity levels and per-tactic detail sections.
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

ACTIVITY_HIGH   = colors.HexColor("#D71920")
ACTIVITY_MEDIUM = colors.HexColor("#E8610A")
ACTIVITY_LOW    = colors.HexColor("#D4A017")
ACTIVITY_NONE   = colors.HexColor("#CCCCCC")

PAGE_W, PAGE_H = A4
CONTENT_W = PAGE_W - 4 * cm

# Tactic display order
TACTIC_ORDER = [
    "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
    "TA0006", "TA0007", "TA0008", "TA0009", "TA0010",
    "TA0011", "TA0040",
]

TACTIC_NAMES = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}

RECOMMENDATIONS = {
    "TA0001": "Review perimeter controls and phishing protections. Ensure MFA is enforced on external-facing systems.",
    "TA0002": "Restrict script interpreter access (PowerShell, WMI). Enable script block logging and application whitelisting.",
    "TA0003": "Audit scheduled tasks, startup entries, and installed services regularly. Monitor for new or modified service binaries.",
    "TA0004": "Monitor for privilege escalation attempts. Enforce least privilege and audit local administrator accounts.",
    "TA0005": "Review log and AV tampering detections. Ensure endpoint protection cannot be disabled without admin approval.",
    "TA0006": "Enforce strong password policies, MFA, and monitor for credential dumping tools. Review privileged account activity.",
    "TA0007": "Baseline normal discovery activity. Investigate bursts of enumeration commands from unexpected hosts.",
    "TA0008": "Limit lateral movement paths. Segment networks, monitor SMB/RDP usage, and enforce credential hygiene.",
    "TA0009": "Monitor for bulk file access or archive creation. Review data access patterns on sensitive shares.",
    "TA0010": "Inspect unusual outbound connections, especially on non-standard ports. Review DLP controls.",
    "TA0011": "Block known C2 infrastructure. Enforce DNS filtering and review encrypted outbound traffic.",
    "TA0040": "Ensure backups are offline and tested. Monitor for ransomware indicators such as mass file renaming.",
}


# ── Styles ────────────────────────────────────────────────────────────────────

def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "MitreCoverTitle", parent=base["Title"],
            fontSize=24, textColor=WHITE, alignment=TA_CENTER, spaceAfter=4,
        ),
        "cover_sub": ParagraphStyle(
            "MitreCoverSub", parent=base["Normal"],
            fontSize=12, textColor=colors.HexColor("#BBCCDD"),
            alignment=TA_CENTER, spaceAfter=2,
        ),
        "section": ParagraphStyle(
            "MitreSection", parent=base["Heading1"],
            fontSize=13, textColor=TV1_RED, spaceBefore=14, spaceAfter=6,
        ),
        "tactic_header": ParagraphStyle(
            "MitreTactic", parent=base["Normal"],
            fontSize=10, textColor=WHITE, fontName="Helvetica-Bold",
        ),
        "body": ParagraphStyle(
            "MitreBody", parent=base["Normal"],
            fontSize=9, textColor=colors.HexColor("#2C2C2C"), leading=13,
        ),
        "small": ParagraphStyle(
            "MitreSmall", parent=base["Normal"],
            fontSize=7.5, textColor=MID_GREY, leading=11,
        ),
        "cell": ParagraphStyle(
            "MitreCell", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#2C2C2C"),
            leading=11, wordWrap="CJK",
        ),
        "caption": ParagraphStyle(
            "MitreCaption", parent=base["Normal"],
            fontSize=8, textColor=MID_GREY, alignment=TA_CENTER,
        ),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _t(value: Any, max_len: int = 60) -> str:
    s = str(value) if value is not None else "—"
    return s[:max_len] + "…" if len(s) > max_len else s


def _activity_color(count: int) -> colors.Color:
    if count == 0:
        return ACTIVITY_NONE
    if count < 10:
        return ACTIVITY_LOW
    if count < 50:
        return ACTIVITY_MEDIUM
    return ACTIVITY_HIGH


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
    canvas.drawString(2 * cm, 1.2 * cm, "Trend Vision One — MITRE ATT&CK Heatmap Report — Confidential")
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

    sub_data = [[Paragraph("MITRE ATT&CK Heatmap Report", sty["cover_sub"])]]
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


# ── ATT&CK Coverage summary ───────────────────────────────────────────────────

def _coverage_summary(sty: dict, data: dict) -> list:
    elems = [
        PageBreak(),
        Paragraph("ATT&CK Tactic Coverage Summary", sty["section"]),
        Paragraph(
            "Tactics are colour-coded by detection volume: "
            '<font color="#D71920"><b>High (&ge;50)</b></font>  '
            '<font color="#E8610A"><b>Medium (10-49)</b></font>  '
            '<font color="#D4A017"><b>Low (1-9)</b></font>  '
            '<font color="#AAAAAA">None</font>',
            sty["body"],
        ),
        Spacer(1, 0.3 * cm),
    ]

    coverage = data.get("coverage_by_tactic") or {}
    tactic_counts = data.get("tactic_counts") or {}

    rows = [["Tactic ID", "Tactic Name", "Techniques Seen", "Total Detections", "Activity Level"]]
    style_cmds = list(_table_style(5))

    for row_idx, taid in enumerate(TACTIC_ORDER, 1):
        cov = coverage.get(taid) or {}
        name = cov.get("name") or TACTIC_NAMES.get(taid, taid)
        tech_count = cov.get("technique_count", 0)
        total_dets = cov.get("total_detections", 0) or tactic_counts.get(taid, 0)

        act_col = _activity_color(total_dets)
        if total_dets >= 50:
            level_str = "High"
        elif total_dets >= 10:
            level_str = "Medium"
        elif total_dets > 0:
            level_str = "Low"
        else:
            level_str = "None"

        hex_col = act_col.hexval()
        rows.append([
            Paragraph(taid, sty["cell"]),
            Paragraph(name, sty["cell"]),
            Paragraph(str(tech_count), sty["cell"]),
            Paragraph(str(total_dets), sty["cell"]),
            Paragraph(f'<font color="{hex_col}"><b>{level_str}</b></font>', sty["cell"]),
        ])

        if total_dets > 0:
            style_cmds.append(
                ("BACKGROUND", (0, row_idx), (0, row_idx), act_col)
            )
            style_cmds.append(
                ("TEXTCOLOR", (0, row_idx), (0, row_idx), WHITE)
            )

    tbl = Table(rows, colWidths=[2.2 * cm, 4.5 * cm, 3 * cm, 3.5 * cm, 2.8 * cm], repeatRows=1)
    tbl.setStyle(TableStyle(style_cmds))
    elems.append(tbl)
    return elems


# ── Top 20 techniques ─────────────────────────────────────────────────────────

def _top_techniques_section(sty: dict, data: dict) -> list:
    elems = [
        PageBreak(),
        Paragraph("Top 20 Detected Techniques", sty["section"]),
    ]

    techniques = data.get("top_techniques") or []
    if not techniques:
        elems.append(Paragraph("No technique data available.", sty["body"]))
        return elems

    max_count = max((t["count"] for t in techniques), default=1)
    bar_width = 20

    rows = [["Technique ID", "Name", "Tactic", "Detections", "Volume"]]
    for t in techniques[:20]:
        bar_len = int((t["count"] / max_count) * bar_width)
        bar = "\u2588" * bar_len
        rows.append([
            Paragraph(t.get("id", "—"), sty["cell"]),
            Paragraph(_t(t.get("name", "—"), 30), sty["cell"]),
            Paragraph(_t(t.get("tactic", "—"), 22), sty["cell"]),
            Paragraph(str(t.get("count", 0)), sty["cell"]),
            Paragraph(f'<font color="#D71920">{bar}</font>', sty["cell"]),
        ])

    tbl = Table(
        rows,
        colWidths=[2.5 * cm, 5.5 * cm, 4 * cm, 2 * cm, CONTENT_W - 14 * cm],
        repeatRows=1,
    )
    tbl.setStyle(TableStyle(_table_style(5)))
    elems.append(tbl)
    return elems


# ── Tactic detail sections ────────────────────────────────────────────────────

def _tactic_details(sty: dict, data: dict) -> list:
    elems = [
        PageBreak(),
        Paragraph("Tactic Detail Sections", sty["section"]),
    ]

    technique_counts = data.get("technique_counts") or {}
    technique_to_tactics = data.get("technique_to_tactics") or {}
    coverage = data.get("coverage_by_tactic") or {}

    # Build tactic -> techniques mapping
    tactic_to_techniques: dict[str, list[str]] = {}
    for tid, taclist in technique_to_tactics.items():
        for taid in taclist:
            if taid not in tactic_to_techniques:
                tactic_to_techniques[taid] = []
            tactic_to_techniques[taid].append(tid)

    # Import name map from collector module or use local fallback
    try:
        import sys
        from pathlib import Path as _Path
        _parent = str(_Path(__file__).resolve().parents[1])
        if _parent not in sys.path:
            sys.path.insert(0, _parent)
        from collectors.mitre_heatmap import TECHNIQUE_NAMES
    except Exception:
        TECHNIQUE_NAMES = {}

    for taid in TACTIC_ORDER:
        cov = coverage.get(taid) or {}
        total_dets = cov.get("total_detections", 0)
        if total_dets == 0:
            continue

        tname = cov.get("name") or TACTIC_NAMES.get(taid, taid)
        act_col = _activity_color(total_dets)

        # Tactic header bar
        header_data = [[
            Paragraph(
                f'<font color="white"><b>{taid} — {tname}</b>  '
                f'<font size="8">{total_dets} detections</font></font>',
                sty["body"],
            )
        ]]
        header_tbl = Table(header_data, colWidths=[CONTENT_W])
        header_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), act_col),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))

        tech_list = sorted(
            tactic_to_techniques.get(taid, []),
            key=lambda x: technique_counts.get(x, 0),
            reverse=True,
        )

        tech_rows = [["Technique ID", "Name", "Detections"]]
        for tid in tech_list:
            cnt = technique_counts.get(tid, 0)
            tname_val = TECHNIQUE_NAMES.get(tid, tid)
            tech_rows.append([
                Paragraph(tid, sty["cell"]),
                Paragraph(_t(tname_val, 50), sty["cell"]),
                Paragraph(str(cnt), sty["cell"]),
            ])

        tech_tbl = Table(tech_rows, colWidths=[2.5 * cm, 11 * cm, 2.5 * cm], repeatRows=1)
        tech_tbl.setStyle(TableStyle(_table_style(3, header_bg=TV1_NAVY2)))

        rec_text = RECOMMENDATIONS.get(taid, "Review detections for this tactic and apply relevant mitigations.")

        block = [
            header_tbl,
            Spacer(1, 0.15 * cm),
            tech_tbl,
            Spacer(1, 0.15 * cm),
            Paragraph(f"<b>Recommendation:</b> {rec_text}", sty["body"]),
            Spacer(1, 0.5 * cm),
        ]
        elems.append(KeepTogether(block[:3]))
        elems.extend(block[3:])

    if len(elems) == 2:
        elems.append(Paragraph("No tactic detections found in the selected period.", sty["body"]))

    return elems


# ── Recommendations ───────────────────────────────────────────────────────────

def _recommendations_section(sty: dict, data: dict) -> list:
    elems = [
        PageBreak(),
        Paragraph("Strategic Recommendations", sty["section"]),
    ]

    coverage = data.get("coverage_by_tactic") or {}
    tactic_counts = data.get("tactic_counts") or {}

    active_tactics = sorted(
        [(taid, (coverage.get(taid) or {}).get("total_detections", 0) or tactic_counts.get(taid, 0))
         for taid in TACTIC_ORDER],
        key=lambda x: x[1], reverse=True,
    )

    top_active = [(taid, cnt) for taid, cnt in active_tactics if cnt > 0][:5]

    if not top_active:
        elems.append(Paragraph(
            "No MITRE ATT&CK techniques were detected during the reporting period. "
            "This may indicate limited telemetry coverage or a quiet threat environment. "
            "Ensure all sensors are active and reporting correctly.",
            sty["body"],
        ))
        return elems

    most_active_names = ", ".join(
        TACTIC_NAMES.get(taid, taid) for taid, _ in top_active
    )

    intro = (
        f"The most active MITRE ATT&CK tactics during this period were: <b>{most_active_names}</b>. "
        "The following recommendations are prioritised based on observed activity:"
    )
    elems.append(Paragraph(intro, sty["body"]))
    elems.append(Spacer(1, 0.3 * cm))

    for taid, cnt in top_active:
        tname = TACTIC_NAMES.get(taid, taid)
        rec = RECOMMENDATIONS.get(taid, "Review detections and apply relevant mitigations.")
        elems.append(Paragraph(f"<b>{tname} ({taid}) — {cnt} detections:</b>", sty["body"]))
        elems.append(Paragraph(rec, sty["body"]))
        elems.append(Spacer(1, 0.2 * cm))

    return elems


# ── Public entry point ────────────────────────────────────────────────────────

def generate_mitre_report(
    data: dict,
    customer_name: str = "Customer",
    period_days: int = 30,
    output_path: str | None = None,
) -> str:
    """
    Build and save the MITRE ATT&CK Heatmap PDF report.

    Args:
        data:          Dict returned by collect_mitre_data().
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
        output_path = str(Path(output_dir) / f"mitre_heatmap_{ts}.pdf")

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sty = _styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2.5 * cm,
        title=f"MITRE ATT&CK Heatmap — {customer_name}",
        author="Trend Vision One Reporter",
    )

    story: list = []
    story += _cover(sty, customer_name, period_days, generated_at)
    story += _coverage_summary(sty, data)
    story += _top_techniques_section(sty, data)
    story += _tactic_details(sty, data)
    story += _recommendations_section(sty, data)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return os.path.abspath(output_path)
