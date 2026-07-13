"""
Run suspicious PowerShell detection against real Wazuh alerts.
"""

from soc_tool.api.alerts import AlertService
from soc_tool.detections.suspicious_powershell import (
    SuspiciousPowerShellDetector,
)


def main() -> None:
    service = AlertService()

    alerts = service.get_by_event_id(
        event_id="4104",
        limit=100,
    )

    detector = SuspiciousPowerShellDetector()

    findings = detector.detect(alerts)

    print(f"4104 alerts retrieved: {len(alerts)}")
    print(f"Findings detected: {len(findings)}")

    for finding in findings:
        print()
        print("Suspicious PowerShell")
        print(f"Agent: {finding['agent_name']}")
        print(f"Matched patterns: {finding['matched_patterns']}")
        print(f"Timestamp: {finding['timestamp']}")
        print(f"Script: {finding['script_block_text']}")


if __name__ == "__main__":
    main()