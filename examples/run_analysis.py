"""
Run the SOC analysis engine against real Wazuh alerts.
"""

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from soc_tool.api.alerts import AlertService
from soc_tool.detections.account_creation import AccountCreationDetector
from soc_tool.detections.brute_force import BruteForceDetector
from soc_tool.detections.engine import AnalysisEngine
from soc_tool.detections.group_membership import GroupMembershipDetector
from soc_tool.detections.suspicious_powershell import (
    SuspiciousPowerShellDetector,
)
from soc_tool.models.report import Report
from soc_tool.reports.generator import ReportGenerator


def main() -> None:
    service = AlertService()

    alerts = service.get_by_event_ids(
        event_ids=[
            "4625",
            "4104",
            "4720",
            "4728",
        ],
        limit=5000,
    )

    engine = AnalysisEngine(
        detectors=[
            BruteForceDetector(),
            SuspiciousPowerShellDetector(),
            AccountCreationDetector(),
            GroupMembershipDetector(),
        ]
    )

    findings = engine.analyze(alerts)

    detection_counts = Counter(
        finding.title
        for finding in findings
    )

    print(f"Alerts retrieved: {len(alerts)}")
    print()
    print("=== ANALYSIS RESULTS ===")

    if not findings:
        print("No findings detected.")
        return

    for detection, count in detection_counts.items():
        print()
        print(detection)
        print(f"Findings: {count}")

    print()
    print(f"Total findings: {len(findings)}")

    report = Report(
        title="SOC Analysis Report",
        generated_at=datetime.now(timezone.utc).isoformat(),
        findings=findings,
    )

    output_path = Path("soc_analysis_report.html")

    generator = ReportGenerator()
    generator.generate_html(report, output_path)

    print()
    print(f"HTML report generated: {output_path}")


if __name__ == "__main__":
    main()