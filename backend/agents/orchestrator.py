from agents.log_agent import LogAnalysisAgent
from agents.correlation_agent import CorrelationAgent
from agents.report_agent import ReportAgent


class InvestigationOrchestrator:

    def __init__(self):
        self.log_agent = LogAnalysisAgent()
        self.correlation_agent = CorrelationAgent()
        self.report_agent = ReportAgent()

    def investigate_log(self, filepath):

        log_result = self.log_agent.investigate(filepath)

        correlation = self.correlation_agent.correlate(
            log_result
        )

        investigation = {
            "log_analysis": log_result,
            "correlation": correlation
        }

        report = self.report_agent.generate_report(
            filepath,
            investigation
        )

        investigation["report"] = report

        return investigation