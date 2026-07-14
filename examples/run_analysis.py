"""
Run the SOC analysis engine against real Wazuh alerts.
"""

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from soc_tool.api.alerts import AlertService
from soc_tool.detections.account_creation import AccountCreationDetector
from soc_tool.detections.brute_force import BruteForceDetector
from soc_tool.detections.engine import AnalysisEngine
from soc_tool.detections.group_membership import GroupMembershipDetector
from soc_tool.detections.linux_failed_sudo import (
    LinuxFailedSudoDetector,
)
from soc_tool.detections.linux_privileged_group import (
    LinuxPrivilegedGroupDetector,
)
from soc_tool.detections.linux_ssh_brute_force import (
    LinuxSSHBruteForceDetector,
)
from soc_tool.detections.linux_user_creation import (
    LinuxUserCreationDetector,
)
from soc_tool.detections.persistence import FindingStore
from soc_tool.detections.suspicious_powershell import (
    SuspiciousPowerShellDetector,
)
from soc_tool.models.report import Report
from soc_tool.reports.generator import ReportGenerator


def main() -> None:
    service = AlertService()

    windows_alerts = service.get_by_event_ids(
        event_ids=[
            "4625",
            "4104",
            "4720",
            "4728",
        ],
        limit=5000,
    )

    linux_alerts = service.get_by_rule_ids(
        rule_ids=[
            "2502",
            "5404",
            "5902",
            "80792",
        ],
        limit=5000,
    )

    alerts = windows_alerts + linux_alerts

    engine = AnalysisEngine(
        detectors=[
            BruteForceDetector(),
            SuspiciousPowerShellDetector(),
            AccountCreationDetector(),
            GroupMembershipDetector(),
            LinuxSSHBruteForceDetector(),
            LinuxFailedSudoDetector(),
            LinuxUserCreationDetector(),
            LinuxPrivilegedGroupDetector(),
        ]
    )

    findings = engine.analyze(alerts)

    store = FindingStore(
        Path("soc_findings.db")
    )

    store.sync(findings)

    open_findings = store.get_open_findings(findings)

    detection_counts = Counter(
        finding.title
        for finding in open_findings
    )

    print(f"Alerts retrieved: {len(alerts)}")
    print(f"Findings detected: {len(findings)}")
    print(f"Open findings: {len(open_findings)}")
    print()
    print("=== ANALYSIS RESULTS ===")

    if not open_findings:
        print("No open findings detected.")

    for detection, count in detection_counts.items():
        print()
        print(detection)
        print(f"Findings: {count}")

    print()
    print(f"Total open findings: {len(open_findings)}")

    costa_rica = timezone(
        timedelta(hours=-6),
        name="Costa Rica",
    )

    report = Report(
        title="SOC Analysis Report",
        generated_at=datetime.now(costa_rica).isoformat(),
        findings=open_findings,
    )

    output_path = Path("soc_analysis_report.html")

    generator = ReportGenerator()
    generator.generate_html(report, output_path)

    print()
    print(f"HTML report generated: {output_path}")


if __name__ == "__main__":
    main()


