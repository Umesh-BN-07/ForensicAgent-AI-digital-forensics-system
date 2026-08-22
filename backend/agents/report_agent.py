import os
from datetime import datetime

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)


class ReportAgent:

    def __init__(self):

        self.report_folder = "reports"

        os.makedirs(
            self.report_folder,
            exist_ok=True
        )

    def generate_report(
        self,
        filename,
        investigation
    ):

        report_name = (
            "Forensic_Report_"
            + datetime.now().strftime("%Y%m%d_%H%M%S")
            + ".pdf"
        )

        report_path = os.path.join(
            self.report_folder,
            report_name
        )

        doc = SimpleDocTemplate(report_path)

        styles = getSampleStyleSheet()

        story = []

        # Title
        story.append(
            Paragraph(
                "<b>FORENSIC INVESTIGATION REPORT</b>",
                styles["Title"]
            )
        )

        story.append(Spacer(1, 20))

        # Case Information
        story.append(
            Paragraph(
                f"<b>Evidence File:</b> {filename}",
                styles["Normal"]
            )
        )

        story.append(
            Paragraph(
                f"<b>Date:</b> {datetime.now()}",
                styles["Normal"]
            )
        )

        story.append(Spacer(1, 15))

        # Threat Score
        log = investigation["log_analysis"]

        story.append(
            Paragraph(
                f"<b>Threat Score:</b> {log['threat_score']}",
                styles["Normal"]
            )
        )

        story.append(
            Paragraph(
                f"<b>Risk Level:</b> {log['risk_level']}",
                styles["Normal"]
            )
        )

        story.append(Spacer(1, 15))

        # Findings
        story.append(
            Paragraph(
                "<b>Threat Findings</b>",
                styles["Heading2"]
            )
        )

        for finding in log["findings"]:

            story.append(
                Paragraph(
                    f"• {finding['description']}",
                    styles["Normal"]
                )
            )

        story.append(Spacer(1, 15))

        # ML Analysis
        ml = log["ml_analysis"]

        story.append(
            Paragraph(
                "<b>Machine Learning Result</b>",
                styles["Heading2"]
            )
        )

        story.append(
            Paragraph(
                f"Prediction : {ml['prediction']}",
                styles["Normal"]
            )
        )

        story.append(
            Paragraph(
                f"Confidence : {ml['confidence']}",
                styles["Normal"]
            )
        )

        story.append(Spacer(1, 15))

        # AI Summary
        corr = investigation["correlation"]

        story.append(
            Paragraph(
                "<b>AI Investigation Summary</b>",
                styles["Heading2"]
            )
        )

        for line in corr["summary"]:

            story.append(
                Paragraph(
                    f"• {line}",
                    styles["Normal"]
                )
            )

        story.append(Spacer(1, 15))

        # Timeline
        story.append(
            Paragraph(
                "<b>Attack Timeline</b>",
                styles["Heading2"]
            )
        )

        for event in corr["timeline"]:

            story.append(
                Paragraph(
                    f"{event['timestamp']} : {event['event']} ({event['user']})",
                    styles["Normal"]
                )
            )

        story.append(Spacer(1, 20))

        # Recommendations
        story.append(
            Paragraph(
                "<b>Recommendations</b>",
                styles["Heading2"]
            )
        )

        recommendations = [
            "Block suspicious IP address.",
            "Reset administrator credentials.",
            "Enable Multi-Factor Authentication.",
            "Restore deleted logs.",
            "Audit confidential file access."
        ]

        for recommendation in recommendations:

            story.append(
                Paragraph(
                    f"• {recommendation}",
                    styles["Normal"]
                )
            )

        doc.build(story)

        return report_path