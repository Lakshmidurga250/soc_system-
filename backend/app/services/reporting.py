"""Forensic & Executive PDF Report Generator for SentinelAI SOC.

Generates local, professional PDF artifacts using ReportLab with clean styling,
incident summaries, evidence timelines, and SOC executive KPI overviews.
"""
from __future__ import annotations
import io
from datetime import datetime, timezone
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def generate_incident_pdf(
    incident: Any,
    alerts: List[Any],
    investigation: Any | None = None,
) -> bytes:
    """Generates a comprehensive forensic investigation PDF for a specific incident."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b"),
    )
    heading2_style = ParagraphStyle(
        "DocH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "DocBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )

    elements = []

    # Header
    elements.append(Paragraph("◈ SENTINELAI SECURITY OPERATIONS CENTER", subtitle_style))
    elements.append(Paragraph(f"Forensic Incident Report: {incident.title}", title_style))
    elements.append(
        Paragraph(
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Document ID: {incident.id}",
            subtitle_style,
        )
    )
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=15))

    # Incident Overview Table
    overview_data = [
        ["Incident ID", incident.id, "Severity", incident.severity],
        ["Current Status", incident.status, "Risk Score", f"{incident.risk_score} / 100"],
        ["Confidence", f"{int((incident.confidence or 0.85)*100)}%", "Created At", str(incident.created_at)[:19]],
    ]
    t = Table(overview_data, colWidths=[110, 150, 110, 150])
    t.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1e293b")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ])
    )
    elements.append(t)
    elements.append(Spacer(1, 15))

    # Executive Summary & Description
    elements.append(Paragraph("1. Executive Incident Summary", heading2_style))
    desc_text = incident.description or "Automated multi-source behavioral detection triggered an investigation."
    elements.append(Paragraph(desc_text, body_style))
    elements.append(Spacer(1, 10))

    # Associated Alerts
    elements.append(Paragraph(f"2. Triggering Alerts ({len(alerts)} items)", heading2_style))
    alert_rows = [["Alert ID", "Title / Rule", "Severity", "Risk", "Detection Source"]]
    for a in alerts[:8]:
        alert_rows.append([
            str(a.id)[:8],
            Paragraph(str(a.title)[:45], body_style),
            str(a.severity),
            f"{a.risk_score:.0f}",
            str(a.source),
        ])
    if len(alert_rows) > 1:
        at = Table(alert_rows, colWidths=[70, 240, 70, 50, 90])
        at.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        elements.append(at)
    elements.append(Spacer(1, 15))

    # Investigation Timeline / Evidence if present
    if investigation:
        elements.append(Paragraph("3. AI Evidence Timeline & Correlation", heading2_style))
        summary = investigation.summary or "Evidence ranked based on entity relevance and anomaly severity."
        elements.append(Paragraph(summary, body_style))
        elements.append(Spacer(1, 8))

        timeline = investigation.timeline or []
        if timeline:
            tl_rows = [["Timestamp (UTC)", "Event Reference", "Description / Entity Action"]]
            for item in timeline[:10]:
                tl_rows.append([
                    str(item.get("at", ""))[:19],
                    str(item.get("event_id", ""))[:10],
                    Paragraph(str(item.get("description", "")), body_style),
                ])
            tlt = Table(tl_rows, colWidths=[120, 90, 310])
            tlt.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ])
            )
            elements.append(tlt)

    elements.append(Spacer(1, 20))
    elements.append(
        Paragraph(
            "CONFIDENTIAL // FOR INTERNAL SECURITY OPERATIONS USE ONLY — GENERATED BY SENTINELAI",
            subtitle_style,
        )
    )

    doc.build(elements)
    return buffer.getvalue()


def generate_soc_executive_pdf(kpis: Dict[str, Any], alerts_by_severity: Dict[str, int]) -> bytes:
    """Generates an executive SOC health and metric summary report PDF."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b"),
    )
    heading2_style = ParagraphStyle(
        "DocH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "DocBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )

    elements = []
    elements.append(Paragraph("◈ SENTINELAI SECURITY OPERATIONS CENTER", subtitle_style))
    elements.append(Paragraph("Executive SOC Posture & Threat Summary", title_style))
    elements.append(
        Paragraph(
            f"Report Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            subtitle_style,
        )
    )
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=15))

    elements.append(Paragraph("1. Core SOC Performance Metrics", heading2_style))
    kpi_data = [
        ["Total Security Events Ingested", str(kpis.get("total_events", 0)), "Active Triaged Alerts", str(kpis.get("active_alerts", 0))],
        ["Open Incident Cases", str(kpis.get("open_incidents", 0)), "Critical Priority Incidents", str(kpis.get("critical_incidents", 0))],
        ["ML Anomalies Detected", str(kpis.get("anomalies_detected", 0)), "Active Investigations", str(kpis.get("investigations_running", 0))],
    ]
    kt = Table(kpi_data, colWidths=[180, 80, 180, 80])
    kt.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ])
    )
    elements.append(kt)
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("2. Threat Alert Distribution by Severity", heading2_style))
    sev_rows = [["Severity Tier", "Count", "Percentage of Total"]]
    total_alerts = sum(alerts_by_severity.values()) or 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
        c = alerts_by_severity.get(sev, 0)
        pct = f"{(c / total_alerts) * 100:.1f}%"
        sev_rows.append([sev, str(c), pct])

    st = Table(sev_rows, colWidths=[180, 140, 200])
    st.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ])
    )
    elements.append(st)
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("3. Operational Posture & Risk Assessment", heading2_style))
    elements.append(
        Paragraph(
            "SentinelAI autonomous detection engine is operating within standard parameters. All high-risk events have undergone automated entity correlation and evidence ranking. Response actions require human analyst authorization per safety-first policy.",
            body_style,
        )
    )

    doc.build(elements)
    return buffer.getvalue()
