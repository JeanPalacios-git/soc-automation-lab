"""
Run brute force detection against real Wazuh alerts.
"""

from soc_tool.api.alerts import AlertService
from soc_tool.detections.brute_force import BruteForceDetector


def main() -> None:
    service = AlertService()

    alerts = service.get_by_event_id(
        event_id="4625",
        limit=100,
    )

    detector = BruteForceDetector(
        threshold=5,
        window_minutes=5,
    )

    findings = detector.detect(alerts)

    print(f"4625 alerts retrieved: {len(alerts)}")
    print(f"Findings detected: {len(findings)}")

    for finding in findings:
        print()
        print("Possible Brute Force")
        print(f"Source IP: {finding['source_ip']}")
        print(f"Username: {finding['username']}")
        print(f"Failed attempts: {finding['failed_attempts']}")
        print(f"First seen: {finding['first_seen']}")
        print(f"Last seen: {finding['last_seen']}")


if __name__ == "__main__":
    main()