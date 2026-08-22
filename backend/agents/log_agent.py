from ml.anomaly_detector import AnomalyDetector
import re
from collections import Counter
from datetime import datetime


class LogAnalysisAgent:

    def __init__(self):
        self.events = []
        self.detector = AnomalyDetector()

    # -------------------------------------------------
    # Parse a single log line
    # -------------------------------------------------
    def parse_line(self, line):

        pattern = (
            r"(?P<date>\d{4}-\d{2}-\d{2}) "
            r"(?P<time>\d{2}:\d{2}:\d{2}) "
            r"(?P<event>[A-Z_]+)"
            r"(?P<details>.*)"
        )

        match = re.match(pattern, line.strip())

        if not match:
            return None

        timestamp_string = (
            match.group("date")
            + " "
            + match.group("time")
        )

        timestamp = datetime.strptime(
            timestamp_string,
            "%Y-%m-%d %H:%M:%S"
        )

        details = match.group("details")

        # Extract user
        user_match = re.search(
            r"user=([^\s]+)",
            details
        )

        user = (
            user_match.group(1)
            if user_match
            else None
        )

        # Extract IP
        ip_match = re.search(
            r"ip=([^\s]+)",
            details
        )

        ip = (
            ip_match.group(1)
            if ip_match
            else None
        )

        # Extract file
        file_match = re.search(
            r"file=([^\s]+)",
            details
        )

        file_path = (
            file_match.group(1)
            if file_match
            else None
        )

        return {
            "timestamp": timestamp.isoformat(),
            "event": match.group("event"),
            "user": user,
            "ip": ip,
            "file": file_path,
            "raw": line.strip()
        }

    # -------------------------------------------------
    # Parse complete log file
    # -------------------------------------------------
    def parse_log_file(self, file_path):

        self.events = []

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            for line in file:

                event = self.parse_line(line)

                if event:
                    self.events.append(event)

        return self.events

    # -------------------------------------------------
    # Detect failed login attacks
    # -------------------------------------------------
    def detect_failed_logins(self):

        failed_ips = []

        for event in self.events:

            if event["event"] == "LOGIN_FAILED":

                if event["ip"]:
                    failed_ips.append(event["ip"])

        counts = Counter(failed_ips)

        findings = []

        for ip, count in counts.items():

            if count >= 5:

                findings.append({
                    "type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "ip": ip,
                    "failed_attempts": count,
                    "description":
                        f"Possible brute-force attack from {ip}"
                })

            elif count >= 3:

                findings.append({
                    "type": "MULTIPLE_FAILED_LOGINS",
                    "severity": "MEDIUM",
                    "ip": ip,
                    "failed_attempts": count,
                    "description":
                        f"Multiple failed login attempts from {ip}"
                })

        return findings

    # -------------------------------------------------
    # Detect suspicious file access
    # -------------------------------------------------
    def detect_sensitive_file_access(self):

        findings = []

        suspicious_keywords = [
            "confidential",
            "password",
            "credential",
            "secret",
            "database",
            "backup"
        ]

        for event in self.events:

            if event["event"] in [
                "FILE_ACCESS",
                "FILE_DOWNLOAD"
            ]:

                file_path = event["file"]

                if file_path:

                    path_lower = file_path.lower()

                    if any(
                        keyword in path_lower
                        for keyword in suspicious_keywords
                    ):

                        findings.append({
                            "type": "SENSITIVE_FILE_ACCESS",
                            "severity": "HIGH",
                            "user": event["user"],
                            "file": file_path,
                            "timestamp": event["timestamp"],
                            "description":
                                f"Sensitive file accessed: {file_path}"
                        })

        return findings

    # -------------------------------------------------
    # Detect log deletion
    # -------------------------------------------------
    def detect_log_deletion(self):

        findings = []

        for event in self.events:

            if event["event"] == "LOG_DELETE":

                findings.append({
                    "type": "LOG_DELETION",
                    "severity": "CRITICAL",
                    "user": event["user"],
                    "timestamp": event["timestamp"],
                    "description":
                        "Log deletion activity detected"
                })

        return findings

    # -------------------------------------------------
    # Detect suspicious successful login
    # -------------------------------------------------
    def detect_login_after_failures(self):

        findings = []

        failed_counts = Counter()

        for event in self.events:

            ip = event["ip"]

            if event["event"] == "LOGIN_FAILED":

                if ip:
                    failed_counts[ip] += 1

            elif event["event"] == "LOGIN_SUCCESS":

                if (
                    ip
                    and failed_counts[ip] >= 3
                ):

                    findings.append({
                        "type":
                            "LOGIN_AFTER_MULTIPLE_FAILURES",

                        "severity":
                            "CRITICAL",

                        "ip":
                            ip,

                        "user":
                            event["user"],

                        "previous_failures":
                            failed_counts[ip],

                        "timestamp":
                            event["timestamp"],

                        "description":
                            "Successful login detected after "
                            "multiple failed attempts"
                    })

        return findings

    # -------------------------------------------------
    # Threat score
    # -------------------------------------------------
    def calculate_threat_score(self, findings):

        weights = {
            "LOW": 5,
            "MEDIUM": 15,
            "HIGH": 25,
            "CRITICAL": 35
        }

        score = 0

        for finding in findings:

            severity = finding.get(
                "severity",
                "LOW"
            )

            score += weights.get(
                severity,
                0
            )

        # Maximum 100
        return min(score, 100)

    # -------------------------------------------------
    # Risk classification
    # -------------------------------------------------
    def get_risk_level(self, score):

        if score >= 80:
            return "CRITICAL"

        elif score >= 60:
            return "HIGH"

        elif score >= 30:
            return "MEDIUM"

        return "LOW"

    # -------------------------------------------------
    # Complete investigation
    # -------------------------------------------------
    def investigate(self, file_path):

        events = self.parse_log_file(file_path)

        findings = []

        findings.extend(
            self.detect_failed_logins()
        )

        findings.extend(
            self.detect_login_after_failures()
        )

        findings.extend(
            self.detect_sensitive_file_access()
        )

        findings.extend(
            self.detect_log_deletion()
        )

        threat_score = self.calculate_threat_score(findings)

        risk_level = self.get_risk_level(threat_score)

        # ==============================
        # ML Feature Extraction
        # ==============================

        failed_logins = sum(
            1 for event in events
            if event["event"] == "LOGIN_FAILED"
        )

        file_access = sum(
            1 for event in events
            if event["event"] == "FILE_ACCESS"
        )

        file_download = sum(
            1 for event in events
            if event["event"] == "FILE_DOWNLOAD"
        )

        log_delete = sum(
            1 for event in events
            if event["event"] == "LOG_DELETE"
        )

        ml_result = self.detector.predict(
            failed_logins,
            file_access,
            file_download,
            log_delete
        )

        return {
            "total_events": len(events),
            "events": events,
            "findings": findings,
            "finding_count": len(findings),
            "threat_score": threat_score,
            "risk_level": risk_level,

            # Add this line
            "ml_analysis": ml_result
        }