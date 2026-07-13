"""
Run group membership detection against real Wazuh alerts.
"""

from soc_tool.api.alerts import AlertService
from soc_tool.detections.group_membership import GroupMembershipDetector


def main() -> None:
    service = AlertService()

    alerts = service.get_by_event_id(
        event_id="4728",
        limit=100,
    )

    detector = GroupMembershipDetector()

    findings = detector.detect(alerts)

    print(f"4728 alerts retrieved: {len(alerts)}")
    print(f"Findings detected: {len(findings)}")

    for finding in findings:
        print()
        print(finding["detection"])
        print(f"Agent: {finding['agent_name']}")
        print(f"Group: {finding['group_name']}")
        print(f"Member: {finding['member_name']}")
        print(f"Changed by: {finding['changed_by']}")
        print(f"Domain: {finding['target_domain']}")
        print(f"Timestamp: {finding['timestamp']}")


if __name__ == "__main__":
    main()


