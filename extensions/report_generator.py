"""
extensions/report_generator.py
TIP — Threat Intelligence Report Generator
Generates a downloadable PDF report from MongoDB IOC data
"""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from datetime import datetime, timezone
from pymongo import MongoClient
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, PageBreak)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# ── DB ────────────────────────────────────────
client = MongoClient("mongodb://localhost:27017/")
col    = client["tip_database"]["raw_threats"]

# ── Colors ────────────────────────────────────
DARK    = colors.HexColor("#0d1117")
SURFACE = colors.HexColor("#161b22")
ACCENT  = colors.HexColor("#58a6ff")
RED     = colors.HexColor("#f85149")
ORANGE  = colors.HexColor("#d29922")
GREEN   = colors.HexColor("#3fb950")
MUTED   = colors.HexColor("#8b949e")
WHITE   = colors.white
PURPLE  = colors.HexColor("#bc8cff")

def risk_color(score):
    if score >= 0.7: return RED
    if score >= 0.4: return ORANGE
    return GREEN

def build_report(output_path="tip_threat_report.pdf"):
    # ── Fetch data ────────────────────────────
    all_iocs   = list(col.find().sort("risk_score", -1))
    total      = len(all_iocs)
    critical   = sum(1 for d in all_iocs if (d.get("risk_score") or 0) >= 0.8)
    high       = sum(1 for d in all_iocs if 0.5 <= (d.get("risk_score") or 0) < 0.8)
    medium     = sum(1 for d in all_iocs if (d.get("risk_score") or 0) < 0.5)
    with_mitre = sum(1 for d in all_iocs if d.get("mitre"))

    by_type   = {}
    by_source = {}
    for d in all_iocs:
        t = d.get("type", "Unknown")
        s = d.get("source", "Unknown")
        by_type[t]   = by_type.get(t, 0) + 1
        by_source[s] = by_source.get(s, 0) + 1

    # top tactics
    tactic_count = {}
    for d in all_iocs:
        for tactic in (d.get("mitre") or {}).get("tactics", []):
            tactic_count[tactic] = tactic_count.get(tactic, 0) + 1
    top_tactics = sorted(tactic_count.items(), key=lambda x: x[1], reverse=True)[:5]

    # ── Styles ────────────────────────────────
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle("title",
        fontSize=24, fontName="Helvetica-Bold",
        textColor=ACCENT, alignment=TA_CENTER, spaceAfter=12)

    subtitle_style = ParagraphStyle("subtitle",
        fontSize=11, fontName="Helvetica",
        textColor=MUTED, alignment=TA_CENTER, spaceAfter=20)

    h1_style = ParagraphStyle("h1",
        fontSize=14, fontName="Helvetica-Bold",
        textColor=ACCENT, spaceBefore=16, spaceAfter=8)

    h2_style = ParagraphStyle("h2",
        fontSize=11, fontName="Helvetica-Bold",
        textColor=WHITE, spaceBefore=10, spaceAfter=6)

    body_style = ParagraphStyle("body",
        fontSize=9, fontName="Helvetica",
        textColor=MUTED, spaceAfter=4, leading=14)

    label_style = ParagraphStyle("label",
        fontSize=8, fontName="Helvetica-Bold",
        textColor=MUTED, spaceAfter=2)

    # ── Document ──────────────────────────────
    pdf_doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm
    )

    story = []
    now   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    W     = A4[0] - 40*mm  # usable width

    # ── Header ────────────────────────────────
    story.append(Spacer(1, 10))
    story.append(Paragraph("THREAT INTELLIGENCE REPORT", title_style))
    story.append(Paragraph("Finance &amp; Banking SOC — Infotact Solutions", subtitle_style))
    story.append(Paragraph(f"Generated: {now}", subtitle_style))
    story.append(HRFlowable(width=W, color=ACCENT, thickness=1, spaceAfter=16))

    # ── Executive Summary ─────────────────────
    story.append(Paragraph("Executive Summary", h1_style))
    story.append(Paragraph(
        f"This report summarizes threat intelligence collected by the TIP platform for the "
        f"Finance &amp; Banking SOC environment. A total of <b>{total}</b> Indicators of Compromise (IOCs) "
        f"were collected from AlienVault OTX and VirusTotal. Of these, <b>{critical}</b> are classified as "
        f"critical severity, <b>{high}</b> as high, and <b>{medium}</b> as medium. "
        f"<b>{with_mitre}</b> IOCs have been mapped to the MITRE ATT&amp;CK framework.",
        body_style))

    story.append(Spacer(1, 12))

    # ── Stats Table ───────────────────────────
    stats_data = [
        ["Metric", "Value"],
        ["Total IOCs Collected",     str(total)],
        ["Critical Severity (≥0.8)", str(critical)],
        ["High Severity (0.5-0.8)",  str(high)],
        ["Medium Severity (<0.5)",   str(medium)],
        ["MITRE ATT&CK Mapped",      str(with_mitre)],
        ["Intelligence Sources",     ", ".join(by_source.keys())],
    ]

    stats_table = Table(stats_data, colWidths=[W*0.6, W*0.4])
    stats_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0),  ACCENT),
        ("TEXTCOLOR",   (0,0), (-1,0),  DARK),
        ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,0),  9),
        ("BACKGROUND",  (0,1), (-1,-1), SURFACE),
        ("TEXTCOLOR",   (0,1), (-1,-1), WHITE),
        ("FONTNAME",    (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",    (0,1), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [SURFACE, DARK]),
        ("GRID",        (0,0), (-1,-1), 0.5, colors.HexColor("#30363d")),
        ("PADDING",     (0,0), (-1,-1), 8),
        ("ALIGN",       (1,0), (1,-1),  "CENTER"),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 16))

    # ── IOC Breakdown ─────────────────────────
    story.append(Paragraph("IOC Breakdown by Type", h1_style))
    type_data = [["Type", "Count", "Percentage"]]
    for t, c in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
        pct = f"{(c/total*100):.1f}%" if total else "0%"
        type_data.append([t, str(c), pct])

    type_table = Table(type_data, colWidths=[W*0.5, W*0.25, W*0.25])
    type_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0),  PURPLE),
        ("TEXTCOLOR",   (0,0), (-1,0),  DARK),
        ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("BACKGROUND",  (0,1), (-1,-1), SURFACE),
        ("TEXTCOLOR",   (0,1), (-1,-1), WHITE),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [SURFACE, DARK]),
        ("GRID",        (0,0), (-1,-1), 0.5, colors.HexColor("#30363d")),
        ("PADDING",     (0,0), (-1,-1), 8),
        ("ALIGN",       (1,0), (-1,-1), "CENTER"),
    ]))
    story.append(type_table)
    story.append(Spacer(1, 16))

    # ── MITRE Tactics ─────────────────────────
    if top_tactics:
        story.append(Paragraph("Top MITRE ATT&CK Tactics Observed", h1_style))
        tactic_data = [["Tactic", "IOC Count"]]
        for tactic, count in top_tactics:
            tactic_data.append([tactic, str(count)])

        tactic_table = Table(tactic_data, colWidths=[W*0.7, W*0.3])
        tactic_table.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0),  RED),
            ("TEXTCOLOR",   (0,0), (-1,0),  WHITE),
            ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 9),
            ("BACKGROUND",  (0,1), (-1,-1), SURFACE),
            ("TEXTCOLOR",   (0,1), (-1,-1), WHITE),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [SURFACE, DARK]),
            ("GRID",        (0,0), (-1,-1), 0.5, colors.HexColor("#30363d")),
            ("PADDING",     (0,0), (-1,-1), 8),
            ("ALIGN",       (1,0), (1,-1),  "CENTER"),
        ]))
        story.append(tactic_table)
        story.append(Spacer(1, 16))

    # ── IOC Table ─────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Indicator of Compromise Details", h1_style))
    story.append(Paragraph(
        "The following table lists all collected IOCs sorted by risk score (highest first).",
        body_style))
    story.append(Spacer(1, 8))

    ioc_data = [["Indicator", "Type", "Source", "Score", "Tactics", "Confidence"]]

    for doc in all_iocs[:50]:  # max 50 rows
        indicator = doc.get("indicator", "")
        if len(indicator) > 35:
            indicator = indicator[:32] + "..."
        itype     = doc.get("type", "—")
        source    = doc.get("source", "—")
        score     = f"{float(doc.get('risk_score') or 0):.2f}"
        mitre     = doc.get("mitre", {})
        tactics   = ", ".join((mitre.get("tactics") or [])[:2]) or "—"
        if len(tactics) > 30:
            tactics = tactics[:27] + "..."
        confidence = (mitre.get("confidence") or "—").upper()
        ioc_data.append([indicator, itype, source, score, tactics, confidence])

    col_widths = [W*0.30, W*0.12, W*0.13, W*0.08, W*0.25, W*0.12]
    ioc_table  = Table(ioc_data, colWidths=col_widths, repeatRows=1)

    row_colors = []
    for i in range(1, len(ioc_data)):
        score_val = float(ioc_data[i][3])
        if score_val >= 0.7:
            row_colors.append(("TEXTCOLOR", (3,i), (3,i), RED))
        elif score_val >= 0.4:
            row_colors.append(("TEXTCOLOR", (3,i), (3,i), ORANGE))
        else:
            row_colors.append(("TEXTCOLOR", (3,i), (3,i), GREEN))

    ioc_table.setStyle(TableStyle([
        ("BACKGROUND",     (0,0), (-1,0),  DARK),
        ("TEXTCOLOR",      (0,0), (-1,0),  ACCENT),
        ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0,0), (-1,-1), 7),
        ("BACKGROUND",     (0,1), (-1,-1), SURFACE),
        ("TEXTCOLOR",      (0,1), (-1,-1), WHITE),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [SURFACE, DARK]),
        ("GRID",           (0,0), (-1,-1), 0.3, colors.HexColor("#30363d")),
        ("PADDING",        (0,0), (-1,-1), 5),
        ("FONTNAME",       (0,1), (0,-1),  "Courier"),
        ("ALIGN",          (3,0), (3,-1),  "CENTER"),
        ("ALIGN",          (5,0), (5,-1),  "CENTER"),
        *row_colors
    ]))
    story.append(ioc_table)

    # ── Footer note ───────────────────────────
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width=W, color=MUTED, thickness=0.5))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report was auto-generated by the TIP (Threat Intelligence Platform) — "
        "Infotact Solutions Internship Project. Data sourced from AlienVault OTX and VirusTotal. "
        "MITRE ATT&amp;CK mapping performed by custom enrichment engine.",
        ParagraphStyle("footer", fontSize=7, textColor=MUTED, alignment=TA_CENTER)
    ))

    # ── Build ─────────────────────────────────
    pdf_doc.build(story)
    print(f"[✓] Report saved: {output_path}")
    return output_path


if __name__ == "__main__":
    build_report("tip_threat_report.pdf")
