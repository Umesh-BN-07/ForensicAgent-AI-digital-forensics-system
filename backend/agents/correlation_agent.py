from datetime import datetime


class CorrelationAgent:

    def correlate(
        self,
        log_analysis,
        nlp_analysis=None
    ):

        timeline = []

        # Build timeline from parsed log events
        for event in log_analysis["events"]:

            timeline.append({
                "timestamp": event["timestamp"],
                "event": event["event"],
                "user": event["user"],
                "details": event["raw"]
            })

        # Sort chronologically
        timeline.sort(
            key=lambda x: datetime.fromisoformat(x["timestamp"])
        )

        conclusions = []

        findings = log_analysis["findings"]

        if any(
            f["type"] == "BRUTE_FORCE"
            for f in findings
        ):
            conclusions.append(
                "Brute-force attack detected."
            )

        if any(
            f["type"] == "LOGIN_AFTER_MULTIPLE_FAILURES"
            for f in findings
        ):
            conclusions.append(
                "Account compromise is likely."
            )

        if any(
            f["type"] == "SENSITIVE_FILE_ACCESS"
            for f in findings
        ):
            conclusions.append(
                "Sensitive data access detected."
            )

        if any(
            f["type"] == "LOG_DELETION"
            for f in findings
        ):
            conclusions.append(
                "Evidence tampering suspected."
            )

        # Include NLP findings if available
        if nlp_analysis:
            if nlp_analysis["risk"] in ["HIGH", "CRITICAL"]:
                conclusions.append(
                    "Suspicious communication detected by NLP analysis."
                )

        return {
            "timeline": timeline,
            "summary": conclusions,
            "overall_risk": log_analysis["risk_level"],
            "overall_score": log_analysis["threat_score"]
        }