import hashlib
import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agents.log_agent import LogAnalysisAgent
from agents.nlp_agent import NLPAgent
from agents.correlation_agent import CorrelationAgent
from agents.folder_report_agent import FolderReportAgent


TEXT_EXTENSIONS = {
    ".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm",
    ".eml", ".md", ".ini", ".conf", ".cfg", ".yaml", ".yml"
}
LOG_EXTENSIONS = {".log"}
NLP_EXTENSIONS = {
    ".txt", ".csv", ".json", ".xml", ".html", ".htm",
    ".eml", ".md", ".ini", ".conf", ".cfg", ".yaml", ".yml"
}

MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_NLP_CHARS = 100_000


class FolderInvestigationAgent:
    """Coordinates a complete folder-level forensic investigation.

    Every file is collected and hashed. Supported text/log files are analyzed,
    while unsupported/binary files are preserved as evidence metadata instead
    of being executed or ignored.
    """

    def __init__(self, upload_root="uploads", reports_root="reports"):
        self.upload_root = os.path.abspath(upload_root)
        self.reports_root = os.path.abspath(reports_root)
        os.makedirs(self.upload_root, exist_ok=True)
        os.makedirs(self.reports_root, exist_ok=True)

    @staticmethod
    def sha256(path):
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def safe_extract(zip_file, destination):
        """Extract a ZIP without allowing path traversal."""
        destination = os.path.abspath(destination)
        os.makedirs(destination, exist_ok=True)

        for member in zip_file.infolist():
            member_path = os.path.abspath(os.path.join(destination, member.filename))
            if os.path.commonpath([destination, member_path]) != destination:
                raise ValueError("Unsafe archive path detected")

        zip_file.extractall(destination)

    def _read_text(self, path):
        try:
            if os.path.getsize(path) > MAX_TEXT_BYTES:
                return None
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                return handle.read(MAX_NLP_CHARS)
        except (OSError, UnicodeError):
            return None

    def collect_files(self, case_dir):
        evidence = []
        for root, _, filenames in os.walk(case_dir):
            for filename in filenames:
                path = os.path.join(root, filename)
                relative = os.path.relpath(path, case_dir)
                extension = Path(filename).suffix.lower()

                try:
                    size = os.path.getsize(path)
                    digest = self.sha256(path)
                except OSError as exc:
                    evidence.append({
                        "relative_path": relative,
                        "filename": filename,
                        "extension": extension,
                        "status": "HASH_FAILED",
                        "error": str(exc)
                    })
                    continue

                if extension in LOG_EXTENSIONS:
                    category = "log"
                elif extension in NLP_EXTENSIONS:
                    category = "text"
                else:
                    category = "binary_or_unsupported"

                evidence.append({
                    "relative_path": relative,
                    "filename": filename,
                    "extension": extension,
                    "size": size,
                    "sha256": digest,
                    "category": category,
                    "status": "COLLECTED"
                })

        return evidence

    @staticmethod
    def _risk_from_score(score):
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        return "LOW"

    def analyze_case(self, case_dir, original_folder_name):
        evidence = self.collect_files(case_dir)

        all_events = []
        all_findings = []
        per_file = []
        nlp_results = []

        # Analyze every supported file. Each log gets its own agent instance
        # so one file never overwrites another file's parser state.
        for item in evidence:
            path = os.path.join(case_dir, item["relative_path"])
            extension = item.get("extension", "")

            if item.get("status") != "COLLECTED":
                continue

            if extension in LOG_EXTENSIONS:
                try:
                    result = LogAnalysisAgent().investigate(path)
                    all_events.extend(result.get("events", []))
                    all_findings.extend(result.get("findings", []))
                    per_file.append({
                        "file": item["relative_path"],
                        "type": "LOG",
                        "threat_score": result.get("threat_score", 0),
                        "risk_level": result.get("risk_level", "LOW"),
                        "finding_count": result.get("finding_count", 0)
                    })
                except Exception as exc:
                    per_file.append({
                        "file": item["relative_path"],
                        "type": "LOG",
                        "status": "ANALYSIS_FAILED",
                        "error": str(exc)
                    })

            elif extension in NLP_EXTENSIONS:
                text = self._read_text(path)
                if text:
                    try:
                        nlp_result = NLPAgent().analyze_text(text)
                        nlp_result["file"] = item["relative_path"]
                        nlp_results.append(nlp_result)
                    except Exception as exc:
                        nlp_results.append({
                            "file": item["relative_path"],
                            "risk": "UNKNOWN",
                            "score": 0,
                            "keywords": [],
                            "error": str(exc)
                        })

        # Build one combined log-analysis object for the correlation agent.
        combined_log = {
            "total_events": len(all_events),
            "events": sorted(
                all_events,
                key=lambda event: event.get("timestamp", "")
            ),
            "findings": all_findings,
            "finding_count": len(all_findings),
            "threat_score": min(
                100,
                sum(self._finding_weight(f) for f in all_findings)
            ),
            "risk_level": "LOW",
            "ml_analysis": self._combined_ml_result(per_file)
        }
        combined_log["risk_level"] = self._risk_from_score(
            combined_log["threat_score"]
        )

        correlation = CorrelationAgent().correlate(combined_log)

        # Add NLP conclusions to the correlation result.
        highest_nlp = max(
            nlp_results,
            key=lambda result: result.get("score", 0),
            default=None
        )
        if highest_nlp and highest_nlp.get("score", 0) >= 50:
            correlation["summary"].append(
                "High-risk suspicious communication/content detected by NLP analysis."
            )

        nlp_score = max(
            [r.get("score", 0) for r in nlp_results] or [0]
        )
        overall_score = max(combined_log["threat_score"], nlp_score)
        overall_risk = self._risk_from_score(overall_score)
        correlation["overall_score"] = overall_score
        correlation["overall_risk"] = overall_risk
        correlation["nlp_analysis"] = nlp_results

        investigation = {
            "case_id": os.path.basename(case_dir),
            "folder_name": original_folder_name,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "evidence": evidence,
            "statistics": {
                "total_files": len(evidence),
                "logs_analyzed": sum(1 for x in per_file if x.get("type") == "LOG"),
                "text_files_analyzed": len(nlp_results),
                "unsupported_files": sum(
                    1 for x in evidence if x.get("category") == "binary_or_unsupported"
                ),
                "total_events": len(all_events),
                "total_findings": len(all_findings)
            },
            "files_analysis": per_file,
            "log_analysis": combined_log,
            "nlp_analysis": nlp_results,
            "correlation": correlation
        }

        report_path = FolderReportAgent().generate(
            original_folder_name,
            investigation
        )
        investigation["report"] = report_path
        return investigation

    @staticmethod
    def _finding_weight(finding):
        return {
            "LOW": 5,
            "MEDIUM": 15,
            "HIGH": 25,
            "CRITICAL": 35
        }.get(finding.get("severity", "LOW"), 0)

    @staticmethod
    def _combined_ml_result(per_file):
        suspicious = any(
            item.get("threat_score", 0) >= 60
            for item in per_file
            if item.get("type") == "LOG"
        )
        return {
            "prediction": "ANOMALY" if suspicious else "NORMAL",
            "confidence": "rule-correlated"
        }
