import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


class FolderReportAgent:
    """Creates a consolidated forensic report for a whole evidence folder."""

    def __init__(self):
        backend_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.report_folder = os.path.join(backend_root, "reports")
        os.makedirs(self.report_folder, exist_ok=True)

    def generate(self, folder_name, investigation):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(
            self.report_folder,
            f"Forensic_Folder_Report_{timestamp}.pdf"
        )

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name="SmallGray",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#64748B"),
            leading=11,
        ))
        styles.add(ParagraphStyle(
            name="Section",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#0F4C81"),
            spaceBefore=12,
            spaceAfter=7,
        ))
        styles.add(ParagraphStyle(
            name="CenterTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            textColor=colors.HexColor("#0F4C81"),
        ))

        story = []
        story.append(Paragraph("FORENSIC AGENT", styles["CenterTitle"]))
        story.append(Paragraph(
            "AI-POWERED AUTOMATED DIGITAL FORENSICS INVESTIGATION",
            styles["SmallGray"]
        ))
        story.append(Spacer(1, 10))

        story.append(Paragraph("Investigation Overview", styles["Section"]))
        stats = investigation.get("statistics", {})
        corr = investigation.get("correlation", {})
        log = investigation.get("log_analysis", {})

        overview = [
            ["Case ID", investigation.get("case_id", "—")],
            ["Evidence Folder", folder_name],
            ["Collected At", investigation.get("collected_at", "—")],
            ["Files Collected", str(stats.get("total_files", 0))],
            ["Logs Analyzed", str(stats.get("logs_analyzed", 0))],
            ["Text Files Analyzed", str(stats.get("text_files_analyzed", 0))],
            ["Unsupported/Binary Files", str(stats.get("unsupported_files", 0))],
            ["Total Events", str(stats.get("total_events", 0))],
            ["Total Findings", str(stats.get("total_findings", 0))],
            ["Overall Threat Score", str(corr.get("overall_score", 0)) + "/100"],
            ["Overall Risk", corr.get("overall_risk", "LOW")],
        ]
        table = Table(overview, colWidths=[55 * mm, 125 * mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF2F8")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1E293B")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(table)

        story.append(Paragraph("Evidence Inventory & Integrity", styles["Section"]))
        inventory = [["Path", "Type", "Size", "SHA-256"]]
        for item in investigation.get("evidence", []):
            inventory.append([
                Paragraph(str(item.get("relative_path", "—")), styles["SmallGray"]),
                item.get("category", "—"),
                str(item.get("size", "—")),
                Paragraph(str(item.get("sha256", "—")), styles["SmallGray"]),
            ])

        table = Table(inventory, colWidths=[62 * mm, 28 * mm, 20 * mm, 70 * mm], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F4C81")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(table)

        story.append(Paragraph("Threat Findings", styles["Section"]))
        findings = log.get("findings", [])
        if findings:
            for finding in findings:
                story.append(Paragraph(
                    f"<b>{finding.get('severity', 'LOW')}</b> — "
                    f"{finding.get('description', 'Unknown finding')}",
                    styles["Normal"]
                ))
                story.append(Spacer(1, 3))
        else:
            story.append(Paragraph("No rule-based threat findings detected.", styles["Normal"]))

        story.append(Paragraph("Machine Learning Analysis", styles["Section"]))
        ml = log.get("ml_analysis", {})
        story.append(Paragraph(
            f"Prediction: <b>{ml.get('prediction', '—')}</b><br/>"
            f"Confidence: {ml.get('confidence', '—')}",
            styles["Normal"]
        ))

        story.append(Paragraph("NLP Analysis", styles["Section"]))
        nlp_results = investigation.get("nlp_analysis", [])
        if nlp_results:
            nlp_table = [["File", "Risk", "Score", "Keywords"]]
            for result in nlp_results:
                nlp_table.append([
                    result.get("file", "—"),
                    result.get("risk", "—"),
                    str(result.get("score", 0)),
                    ", ".join(result.get("keywords", [])) or "None"
                ])
            table = Table(nlp_table, colWidths=[65 * mm, 25 * mm, 20 * mm, 70 * mm], repeatRows=1)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F4C81")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(table)
        else:
            story.append(Paragraph("No supported text content was available for NLP analysis.", styles["Normal"]))

        story.append(Paragraph("Correlated Attack Timeline", styles["Section"]))
        timeline = corr.get("timeline", [])
        if timeline:
            timeline_table = [["Timestamp", "Event", "User", "Details"]]
            for event in timeline:
                timeline_table.append([
                    event.get("timestamp", "—"),
                    event.get("event", "—"),
                    event.get("user", "—"),
                    event.get("details", "—"),
                ])
            table = Table(timeline_table, colWidths=[38 * mm, 35 * mm, 28 * mm, 79 * mm], repeatRows=1)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F4C81")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(table)
        else:
            story.append(Paragraph("No timeline events detected.", styles["Normal"]))

        story.append(Paragraph("AI Investigation Summary", styles["Section"]))
        for summary in corr.get("summary", []):
            story.append(Paragraph(f"• {summary}", styles["Normal"]))

        story.append(Paragraph("Recommendations", styles["Section"]))
        recommendations = [
            "Preserve the original evidence folder and its SHA-256 inventory.",
            "Investigate all high and critical findings before closing the case.",
            "Review suspicious source IP addresses and affected accounts.",
            "Reset compromised credentials and enable multi-factor authentication where appropriate.",
            "Restore or preserve deleted logs from trusted backups.",
            "Retain the generated report and evidence hashes for audit or legal review."
        ]
        for recommendation in recommendations:
            story.append(Paragraph(f"• {recommendation}", styles["Normal"]))

        story.append(Spacer(1, 15))
        story.append(Paragraph(
            "Generated automatically by ForensicAgent. Unsupported/binary files are collected and hashed but are not executed.",
            styles["SmallGray"]
        ))

        doc = SimpleDocTemplate(
            path,
            pagesize=A4,
            rightMargin=15 * mm,
            leftMargin=15 * mm,
            topMargin=15 * mm,
            bottomMargin=15 * mm,
        )
        doc.build(story)
        return os.path.abspath(path)
