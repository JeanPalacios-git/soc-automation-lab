"""
Run account creation detection against real Wazuh alerts.
"""

from soc_tool.api.alerts import AlertService
from soc_tool.detections.account_creation import AccountCreationDetector


def main() -> None:
    service = AlertService()

    alerts = service.get_by_event_id(
        event_id="4720",
        limit=100,
    )

    detector = AccountCreationDetector()

    findings = detector.detect(alerts)

    print(f"4720 alerts retrieved: {len(alerts)}")
    print(f"Findings detected: {len(findings)}")

    for finding in findings:
        print()
        print("User Account Created")
        print(f"Agent: {finding['agent_name']}")
        print(f"Created user: {finding['created_user']}")
        print(f"Created by: {finding['created_by']}")
        print(f"Domain: {finding['target_domain']}")
        print(f"Timestamp: {finding['timestamp']}")


if __name__ == "__main__":
    main()